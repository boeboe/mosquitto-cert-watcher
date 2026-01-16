package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	version = "dev" // Set at compile time via -ldflags
)

const (
	defaultCertDir            = "/certs"
	defaultCACertFile         = "ca.crt"
	defaultClientCertFile     = "client.crt"
	defaultClientKeyFile      = "client.key"
	defaultMosquittoContainer = "eclipse-mosquitto"
	defaultUpstreamAddr       = ""
	defaultTLSSNI             = ""
	defaultTLSTimeout         = 5 * time.Second
	defaultCheckInterval      = 5 * time.Second
	defaultStabilityWindow    = 10 * time.Second
	defaultRestartCooldown    = 300 * time.Second
	defaultExpiryWarnDays     = 14
	defaultDockerSock         = "/var/run/docker.sock"
	defaultLogLevel           = "info"
	defaultMetricsPort        = "9090"
)

type Config struct {
	CertDir            string        `json:"cert_dir,omitempty"`
	CACertFile         string        `json:"ca_cert_file,omitempty"`
	ClientCertFile     string        `json:"client_cert_file,omitempty"`
	ClientKeyFile      string        `json:"client_key_file,omitempty"`
	MosquittoContainer string        `json:"mosquitto_container,omitempty"`
	UpstreamAddr       string        `json:"upstream_addr,omitempty"`
	TLSSNI             string        `json:"tls_sni,omitempty"`
	TLSTimeout         time.Duration `json:"-"`
	TLSTimeoutStr      string        `json:"tls_timeout,omitempty"`
	CheckInterval      time.Duration `json:"-"`
	CheckIntervalStr   string        `json:"check_interval,omitempty"`
	StabilityWindow    time.Duration `json:"-"`
	StabilityWindowStr string        `json:"stability_window,omitempty"`
	RestartCooldown    time.Duration `json:"-"`
	RestartCooldownStr string        `json:"restart_cooldown,omitempty"`
	ExpiryWarnDays     int           `json:"expiry_warn_days,omitempty"`
	DockerSock         string        `json:"docker_sock,omitempty"`
	EnableTLSProbe     bool          `json:"enable_tls_probe,omitempty"`
	EnableRestart      bool          `json:"enable_restart,omitempty"`
	LogLevel           string        `json:"log_level,omitempty"`
	EnableMetrics      bool          `json:"enable_metrics,omitempty"`
	MetricsPort        string        `json:"metrics_port,omitempty"`
}

type CertSet struct {
	CACertPath     string
	ClientCertPath string
	ClientKeyPath  string
	Hash           string
	LastModified   time.Time
	// Cached file contents to avoid re-reading
	CACertData     []byte
	ClientCertData []byte
}

type CertInfo struct {
	NotBefore     time.Time
	NotAfter      time.Time
	Subject       string
	Issuer        string
	IsExpired     bool
	DaysRemaining int
}

type Logger struct {
	Level string
}

type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Component string                 `json:"component"`
	Event     string                 `json:"event"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

func (l *Logger) log(level, component, event string, details map[string]interface{}) {
	if !l.shouldLog(level) {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level,
		Component: component,
		Event:     event,
		Details:   details,
	}

	data, _ := json.Marshal(entry)
	fmt.Println(string(data))
}

func (l *Logger) shouldLog(level string) bool {
	levels := map[string]int{
		"debug": 0,
		"info":  1,
		"warn":  2,
		"error": 3,
	}
	configLevel := levels[l.Level]
	msgLevel := levels[level]
	return msgLevel >= configLevel
}

func (l *Logger) Debug(component, event string, details map[string]interface{}) {
	l.log("debug", component, event, details)
}

func (l *Logger) Info(component, event string, details map[string]interface{}) {
	l.log("info", component, event, details)
}

func (l *Logger) Warn(component, event string, details map[string]interface{}) {
	l.log("warn", component, event, details)
}

func (l *Logger) Error(component, event string, details map[string]interface{}) {
	l.log("error", component, event, details)
}

type Metrics struct {
	CertDaysRemaining prometheus.Gauge
	TLSProbeSuccess   prometheus.Counter
	TLSProbeFailure   prometheus.Counter
	MosquittoRestarts prometheus.Counter
	RestartSuppressed prometheus.Counter
}

type Watcher struct {
	config       *Config
	logger       *Logger
	dockerClient *client.Client
	certSet      *CertSet
	lastRestart  time.Time
	lastHash     string
	dirty        bool // Set by fsnotify to accelerate next check
	metrics      *Metrics
}

func newMetrics() *Metrics {
	return &Metrics{
		CertDaysRemaining: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cert_days_remaining",
			Help: "Number of days until certificate expires",
		}),
		TLSProbeSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tls_probe_success_total",
			Help: "Total number of successful TLS handshake probes",
		}),
		TLSProbeFailure: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tls_probe_failure_total",
			Help: "Total number of failed TLS handshake probes",
		}),
		MosquittoRestarts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mosquitto_restarts_total",
			Help: "Total number of Mosquitto container restarts triggered",
		}),
		RestartSuppressed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "restart_suppressed_total",
			Help: "Total number of restarts suppressed due to cooldown or stability window",
		}),
	}
}

func (m *Metrics) register() {
	prometheus.MustRegister(
		m.CertDaysRemaining,
		m.TLSProbeSuccess,
		m.TLSProbeFailure,
		m.MosquittoRestarts,
		m.RestartSuppressed,
	)
}

func NewWatcher(config *Config) (*Watcher, error) {
	logger := &Logger{Level: config.LogLevel}

	// Initialize Docker client
	os.Setenv("DOCKER_HOST", "unix://"+config.DockerSock)
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	var metrics *Metrics
	if config.EnableMetrics {
		metrics = newMetrics()
		metrics.register()
	}

	return &Watcher{
		config:       config,
		logger:       logger,
		dockerClient: dockerClient,
		dirty:        false,
		metrics:      metrics,
	}, nil
}

func (w *Watcher) findCertFiles() (*CertSet, error) {
	caCertPath := filepath.Join(w.config.CertDir, w.config.CACertFile)
	clientCertPath := filepath.Join(w.config.CertDir, w.config.ClientCertFile)
	clientKeyPath := filepath.Join(w.config.CertDir, w.config.ClientKeyFile)

	// Check if files exist
	caExists := fileExists(caCertPath)
	clientCertExists := fileExists(clientCertPath)
	clientKeyExists := fileExists(clientKeyPath)

	if !caExists || !clientCertExists || !clientKeyExists {
		var missing []string
		if !caExists {
			missing = append(missing, caCertPath)
		}
		if !clientCertExists {
			missing = append(missing, clientCertPath)
		}
		if !clientKeyExists {
			missing = append(missing, clientKeyPath)
		}
		return nil, fmt.Errorf("certificate files missing: %v", missing)
	}

	// Check if files are non-empty
	if !fileNonEmpty(caCertPath) || !fileNonEmpty(clientCertPath) || !fileNonEmpty(clientKeyPath) {
		return nil, fmt.Errorf("certificate files are empty")
	}

	// Read certificate files once (we don't read the key for security)
	caCertData, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert from %s: %w", caCertPath, err)
	}

	clientCertData, err := os.ReadFile(clientCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read client cert from %s: %w", clientCertPath, err)
	}

	// Calculate hash of cert files (excluding key content for security)
	hash, err := w.calculateCertHash(caCertData, clientCertData, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate cert hash: %w", err)
	}

	// Get last modified time
	info, err := os.Stat(clientCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat cert file: %w", err)
	}

	return &CertSet{
		CACertPath:     caCertPath,
		ClientCertPath: clientCertPath,
		ClientKeyPath:  clientKeyPath,
		Hash:           hash,
		LastModified:   info.ModTime(),
		CACertData:     caCertData,
		ClientCertData: clientCertData,
	}, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func fileNonEmpty(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Size() > 0
}

func (w *Watcher) calculateCertHash(caData, certData []byte, keyPath string) (string, error) {
	// For key, only use size and mtime (don't read content for security)
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		return "", err
	}

	// Create hash from cert content + key metadata
	// Use SHA-256 for collision resistance
	sum := sha256.Sum256(append(caData, certData...))
	hash := hex.EncodeToString(sum[:])
	hash += fmt.Sprintf("_%d_%d", keyInfo.Size(), keyInfo.ModTime().Unix())

	return hash, nil
}

func (w *Watcher) parseCertificate(certData []byte) (*CertInfo, error) {

	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, errors.New("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	now := time.Now()
	isExpired := now.After(cert.NotAfter)
	daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)

	return &CertInfo{
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		IsExpired:     isExpired,
		DaysRemaining: daysRemaining,
	}, nil
}

func (w *Watcher) performTLSProbe(certSet *CertSet) error {
	if !w.config.EnableTLSProbe || w.config.UpstreamAddr == "" {
		return nil
	}

	// Load CA certificate (use cached data)
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(certSet.CACertData) {
		return fmt.Errorf("failed to parse CA certificate from %s", certSet.CACertPath)
	}

	// Load client certificate
	cert, err := tls.LoadX509KeyPair(certSet.ClientCertPath, certSet.ClientKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load client cert/key (cert: %s, key: %s): %w", certSet.ClientCertPath, certSet.ClientKeyPath, err)
	}

	// Configure TLS
	serverName := w.config.TLSSNI
	if serverName == "" {
		// Extract hostname from upstream address
		serverName = w.config.UpstreamAddr
		for i := 0; i < len(serverName); i++ {
			if serverName[i] == ':' {
				serverName = serverName[:i]
				break
			}
		}
	}

	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}

	// Perform handshake
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: w.config.TLSTimeout}, "tcp", w.config.UpstreamAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer conn.Close()

	// Verify connection state
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("no peer certificates received")
	}

	return nil
}

func (w *Watcher) restartMosquitto() error {
	if !w.config.EnableRestart {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use fixed stop timeout (SIGTERM grace period), not RestartCooldown
	// RestartCooldown is a policy concept enforced elsewhere
	timeout := 15
	err := w.dockerClient.ContainerRestart(ctx, w.config.MosquittoContainer, container.StopOptions{Timeout: &timeout})
	if err != nil {
		return fmt.Errorf("failed to restart container: %w", err)
	}

	return nil
}

func (w *Watcher) checkFileStability(certSet *CertSet) bool {
	files := []string{certSet.CACertPath, certSet.ClientCertPath, certSet.ClientKeyPath}
	now := time.Now()

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			return false
		}

		modTime := info.ModTime()
		// Check if file has been stable for the required window
		// (i.e., not modified within the stability window)
		if now.Sub(modTime) < w.config.StabilityWindow {
			return false
		}
	}

	return true
}

func (w *Watcher) startMetricsServer() {
	addr := ":" + w.config.MetricsPort
	http.Handle("/metrics", promhttp.Handler())

	w.logger.Info("metrics", "server_started", map[string]interface{}{
		"address": addr,
		"path":    "/metrics",
	})

	if err := http.ListenAndServe(addr, nil); err != nil {
		w.logger.Error("metrics", "server_failed", map[string]interface{}{
			"error": err.Error(),
		})
	}
}

func (w *Watcher) Run() error {
	w.logger.Info("watcher", "started", map[string]interface{}{
		"version":             version,
		"cert_dir":            w.config.CertDir,
		"mosquitto_container": w.config.MosquittoContainer,
		"upstream_addr":       w.config.UpstreamAddr,
		"check_interval":      w.config.CheckInterval.String(),
	})

	// Start metrics HTTP server if enabled
	if w.config.EnableMetrics {
		go w.startMetricsServer()
	}

	// Initial check
	w.checkAndProcess()

	// Set up file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	defer watcher.Close()

	err = watcher.Add(w.config.CertDir)
	if err != nil {
		w.logger.Warn("watcher", "watch_failed", map[string]interface{}{
			"error": err.Error(),
		})
		// Continue with polling if watch fails
	}

	// Main loop
	ticker := time.NewTicker(w.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				w.logger.Debug("watcher", "file_changed", map[string]interface{}{
					"file": event.Name,
				})
				// Mark as dirty to accelerate next check (don't trigger immediately)
				w.dirty = true
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			w.logger.Error("watcher", "watch_error", map[string]interface{}{
				"error": err.Error(),
			})

		case <-ticker.C:
			// Check if dirty flag is set or it's a regular tick
			if w.dirty {
				w.dirty = false
			}
			w.checkAndProcess()
		}
	}
}

func (w *Watcher) checkAndProcess() {
	// Find and validate cert files
	certSet, err := w.findCertFiles()
	if err != nil {
		w.logger.Warn("cert", "cert_missing", map[string]interface{}{
			"error": err.Error(),
		})
		w.certSet = nil
		return
	}

	// Parse certificate (use cached data)
	certInfo, err := w.parseCertificate(certSet.ClientCertData)
	if err != nil {
		w.logger.Error("cert", "cert_parse_failed", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	w.logger.Info("cert", "cert_parsed", map[string]interface{}{
		"subject":        certInfo.Subject,
		"issuer":         certInfo.Issuer,
		"not_before":     certInfo.NotBefore.Format(time.RFC3339),
		"not_after":      certInfo.NotAfter.Format(time.RFC3339),
		"days_remaining": certInfo.DaysRemaining,
	})

	// Update cert days remaining metric
	if w.metrics != nil {
		w.metrics.CertDaysRemaining.Set(float64(certInfo.DaysRemaining))
	}

	// Check expiry
	if certInfo.IsExpired {
		w.logger.Error("cert", "cert_expired", map[string]interface{}{
			"not_after": certInfo.NotAfter.Format(time.RFC3339),
		})
		// Set days remaining to 0 or negative for expired certs
		if w.metrics != nil {
			w.metrics.CertDaysRemaining.Set(0)
		}
		return
	}

	if certInfo.DaysRemaining <= w.config.ExpiryWarnDays {
		w.logger.Warn("cert", "cert_expiring", map[string]interface{}{
			"days_remaining": certInfo.DaysRemaining,
			"not_after":      certInfo.NotAfter.Format(time.RFC3339),
		})
	}

	// Perform TLS probe
	if w.config.EnableTLSProbe {
		err = w.performTLSProbe(certSet)
		if err != nil {
			w.logger.Error("tls", "tls_probe_failure", map[string]interface{}{
				"error": err.Error(),
			})
			if w.metrics != nil {
				w.metrics.TLSProbeFailure.Inc()
			}
		} else {
			w.logger.Info("tls", "tls_probe_success", map[string]interface{}{
				"upstream": w.config.UpstreamAddr,
			})
			if w.metrics != nil {
				w.metrics.TLSProbeSuccess.Inc()
			}
		}
	}

	// Check if restart is needed
	hashChanged := w.lastHash != certSet.Hash
	firstTime := w.lastHash == ""

	if hashChanged || firstTime {
		// Check stability window
		if !w.checkFileStability(certSet) {
			w.logger.Debug("restart", "restart_deferred", map[string]interface{}{
				"reason": "stability_window",
			})
			if w.metrics != nil {
				w.metrics.RestartSuppressed.Inc()
			}
			w.certSet = certSet
			return
		}

		// Check cooldown
		if time.Since(w.lastRestart) < w.config.RestartCooldown {
			w.logger.Info("restart", "restart_suppressed_cooldown", map[string]interface{}{
				"cooldown_remaining": w.config.RestartCooldown - time.Since(w.lastRestart),
			})
			if w.metrics != nil {
				w.metrics.RestartSuppressed.Inc()
			}
			w.certSet = certSet
			return
		}

		// All conditions met, trigger restart
		w.logger.Info("restart", "mosquitto_restart_triggered", map[string]interface{}{
			"container": w.config.MosquittoContainer,
			"cert_hash": certSet.Hash,
		})

		err = w.restartMosquitto()
		if err != nil {
			w.logger.Error("restart", "restart_failed", map[string]interface{}{
				"error": err.Error(),
			})
			return
		}

		// Record successful restart
		if w.metrics != nil {
			w.metrics.MosquittoRestarts.Inc()
		}

		w.lastRestart = time.Now()
		w.lastHash = certSet.Hash
		w.certSet = certSet

		w.logger.Info("restart", "restart_completed", map[string]interface{}{
			"container": w.config.MosquittoContainer,
		})
	}

	w.certSet = certSet
}

func loadConfigFromFile(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Parse duration strings
	if config.TLSTimeoutStr != "" {
		config.TLSTimeout = parseDuration(config.TLSTimeoutStr, defaultTLSTimeout)
	}
	if config.CheckIntervalStr != "" {
		config.CheckInterval = parseDuration(config.CheckIntervalStr, defaultCheckInterval)
	}
	if config.StabilityWindowStr != "" {
		config.StabilityWindow = parseDuration(config.StabilityWindowStr, defaultStabilityWindow)
	}
	if config.RestartCooldownStr != "" {
		config.RestartCooldown = parseDuration(config.RestartCooldownStr, defaultRestartCooldown)
	}

	return &config, nil
}

func loadConfig() *Config {
	var config *Config

	// Parse command line flags
	configFile := flag.String("config", "", "Path to JSON configuration file (optional)")
	flag.Parse()

	// Load from config file if provided
	if *configFile != "" {
		var err error
		config, err = loadConfigFromFile(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to load config file: %v\n", err)
			config = &Config{}
		}
	} else {
		config = &Config{}
	}

	// Set defaults for missing values
	if config.CertDir == "" {
		config.CertDir = defaultCertDir
	}
	if config.CACertFile == "" {
		config.CACertFile = defaultCACertFile
	}
	if config.ClientCertFile == "" {
		config.ClientCertFile = defaultClientCertFile
	}
	if config.ClientKeyFile == "" {
		config.ClientKeyFile = defaultClientKeyFile
	}
	if config.MosquittoContainer == "" {
		config.MosquittoContainer = defaultMosquittoContainer
	}
	if config.UpstreamAddr == "" {
		config.UpstreamAddr = defaultUpstreamAddr
	}
	if config.TLSSNI == "" {
		config.TLSSNI = defaultTLSSNI
	}
	if config.TLSTimeout == 0 {
		config.TLSTimeout = defaultTLSTimeout
	}
	if config.CheckInterval == 0 {
		config.CheckInterval = defaultCheckInterval
	}
	if config.StabilityWindow == 0 {
		config.StabilityWindow = defaultStabilityWindow
	}
	if config.RestartCooldown == 0 {
		config.RestartCooldown = defaultRestartCooldown
	}
	if config.ExpiryWarnDays == 0 {
		config.ExpiryWarnDays = defaultExpiryWarnDays
	}
	if config.DockerSock == "" {
		config.DockerSock = defaultDockerSock
	}
	if config.LogLevel == "" {
		config.LogLevel = defaultLogLevel
	}
	if config.MetricsPort == "" {
		config.MetricsPort = defaultMetricsPort
	}

	// ENV variables always override config file values
	config.CertDir = getEnv("CERT_DIR", config.CertDir)
	config.CACertFile = getEnv("CA_CERT_FILE", config.CACertFile)
	config.ClientCertFile = getEnv("CLIENT_CERT_FILE", config.ClientCertFile)
	config.ClientKeyFile = getEnv("CLIENT_KEY_FILE", config.ClientKeyFile)
	config.MosquittoContainer = getEnv("MOSQUITTO_CONTAINER", config.MosquittoContainer)
	config.UpstreamAddr = getEnv("UPSTREAM_ADDR", config.UpstreamAddr)
	config.TLSSNI = getEnv("TLS_SNI", config.TLSSNI)
	config.DockerSock = getEnv("DOCKER_SOCK", config.DockerSock)
	config.LogLevel = getEnv("LOG_LEVEL", config.LogLevel)
	config.EnableTLSProbe = getEnvBool("ENABLE_TLS_PROBE", config.EnableTLSProbe)
	config.EnableRestart = getEnvBool("ENABLE_RESTART", config.EnableRestart)
	config.EnableMetrics = getEnvBool("ENABLE_METRICS", config.EnableMetrics)
	config.MetricsPort = getEnv("METRICS_PORT", config.MetricsPort)

	// Parse duration overrides from ENV
	if envVal := os.Getenv("TLS_TIMEOUT"); envVal != "" {
		config.TLSTimeout = parseDuration(envVal, config.TLSTimeout)
	}
	if envVal := os.Getenv("CHECK_INTERVAL"); envVal != "" {
		config.CheckInterval = parseDuration(envVal, config.CheckInterval)
	}
	if envVal := os.Getenv("STABILITY_WINDOW"); envVal != "" {
		config.StabilityWindow = parseDuration(envVal, config.StabilityWindow)
	}
	if envVal := os.Getenv("RESTART_COOLDOWN"); envVal != "" {
		config.RestartCooldown = parseDuration(envVal, config.RestartCooldown)
	}
	if envVal := os.Getenv("EXPIRY_WARN_DAYS"); envVal != "" {
		config.ExpiryWarnDays = parseInt(envVal, config.ExpiryWarnDays)
	}

	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1"
	}
	return defaultValue
}

func parseDuration(s string, defaultValue time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultValue
	}
	return d
}

func parseInt(s string, defaultValue int) int {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return defaultValue
	}
	return n
}

func main() {
	config := loadConfig()

	watcher, err := NewWatcher(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create watcher: %v\n", err)
		os.Exit(1)
	}

	if err := watcher.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Watcher error: %v\n", err)
		os.Exit(1)
	}
}
