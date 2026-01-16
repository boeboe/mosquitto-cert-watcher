.PHONY: build build-linux-amd64 build-linux-arm64 build-linux-armv7 \
	archive-amd64 archive-arm64 archive-armv7 archive-all \
	docker push clean test deps version

# Read version from version.txt
VERSION := $(shell cat version.txt 2>/dev/null || echo "dev")
REGISTRY ?= pratexonexus.pratexo.com
IMAGE_NAME := mosquitto-cert-watcher
IMAGE_TAG := $(VERSION)
IMAGE := $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
IMAGE_LATEST := $(REGISTRY)/$(IMAGE_NAME):latest

# Build flags
LDFLAGS := -w -s -X main.version=$(VERSION)
BUILD_FLAGS := CGO_ENABLED=0

# Directories
BIN_DIR := bin
DIST_DIR := dist

# Build for current platform
build:
	@mkdir -p $(BIN_DIR)
	$(BUILD_FLAGS) go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/mosquitto-cert-watcher main.go

# Build for Linux AMD64
build-linux-amd64:
	@mkdir -p $(BIN_DIR)
	$(BUILD_FLAGS) GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/mosquitto-cert-watcher-linux-amd64 main.go

# Build for Linux ARM64
build-linux-arm64:
	@mkdir -p $(BIN_DIR)
	$(BUILD_FLAGS) GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/mosquitto-cert-watcher-linux-arm64 main.go

# Build for Linux ARMv7
build-linux-armv7:
	@mkdir -p $(BIN_DIR)
	$(BUILD_FLAGS) GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/mosquitto-cert-watcher-linux-armv7 main.go

# Build all architectures
build-all: build-linux-amd64 build-linux-arm64 build-linux-armv7

# Archive for AMD64
archive-amd64: build-linux-amd64
	@mkdir -p $(DIST_DIR)
	@mkdir -p $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-amd64
	@cp $(BIN_DIR)/mosquitto-cert-watcher-linux-amd64 $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-amd64/mosquitto-cert-watcher
	@chmod +x $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-amd64/mosquitto-cert-watcher
	@cd $(DIST_DIR) && tar -czf mosquitto-cert-watcher-$(VERSION).linux-amd64.tar.gz mosquitto-cert-watcher-$(VERSION).linux-amd64
	@rm -rf $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-amd64
	@echo "Created $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-amd64.tar.gz"

# Archive for ARM64
archive-arm64: build-linux-arm64
	@mkdir -p $(DIST_DIR)
	@mkdir -p $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-arm64
	@cp $(BIN_DIR)/mosquitto-cert-watcher-linux-arm64 $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-arm64/mosquitto-cert-watcher
	@chmod +x $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-arm64/mosquitto-cert-watcher
	@cd $(DIST_DIR) && tar -czf mosquitto-cert-watcher-$(VERSION).linux-arm64.tar.gz mosquitto-cert-watcher-$(VERSION).linux-arm64
	@rm -rf $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-arm64
	@echo "Created $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-arm64.tar.gz"

# Archive for ARMv7
archive-armv7: build-linux-armv7
	@mkdir -p $(DIST_DIR)
	@mkdir -p $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-armv7
	@cp $(BIN_DIR)/mosquitto-cert-watcher-linux-armv7 $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-armv7/mosquitto-cert-watcher
	@chmod +x $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-armv7/mosquitto-cert-watcher
	@cd $(DIST_DIR) && tar -czf mosquitto-cert-watcher-$(VERSION).linux-armv7.tar.gz mosquitto-cert-watcher-$(VERSION).linux-armv7
	@rm -rf $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-armv7
	@echo "Created $(DIST_DIR)/mosquitto-cert-watcher-$(VERSION).linux-armv7.tar.gz"

# Archive all architectures
archive-all: archive-amd64 archive-arm64 archive-armv7
	@echo "Created all archives in $(DIST_DIR)/"

# Build Docker image for current platform
docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) -t $(IMAGE_LATEST) .

# Setup buildx builder (create if it doesn't exist)
setup-buildx:
	@echo "Setting up buildx for multi-arch builds..."
	@if docker buildx ls 2>/dev/null | grep -q multiarch; then \
		echo "Buildx builder 'multiarch' found, checking if it's valid..."; \
		if ! docker buildx inspect multiarch >/dev/null 2>&1; then \
			echo "Builder 'multiarch' is invalid, removing and recreating..."; \
			docker buildx rm multiarch 2>/dev/null || true; \
			docker buildx create --name multiarch --driver docker-container --use || true; \
			docker buildx inspect --bootstrap || true; \
		else \
			echo "Using existing builder 'multiarch'"; \
			docker buildx use multiarch || docker buildx use default; \
		fi; \
	else \
		echo "Creating buildx builder 'multiarch'..."; \
		docker buildx create --name multiarch --driver docker-container --use || true; \
		docker buildx inspect --bootstrap || true; \
	fi

# Build and push multi-arch manifest
push: setup-buildx
	@echo "Building and pushing multi-arch manifest for $(IMAGE) and $(IMAGE_LATEST)..."
	@echo "Platforms: linux/amd64,linux/arm64,linux/arm/v7"
	docker buildx build \
		--platform linux/amd64,linux/arm64,linux/arm/v7 \
		--build-arg VERSION=$(VERSION) \
		--tag $(IMAGE) \
		--tag $(IMAGE_LATEST) \
		--push \
		.
	@echo "Pushed multi-arch manifest: $(IMAGE) and $(IMAGE_LATEST)"

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)

# Run tests
test:
	go test -v ./...

# Download dependencies
deps:
	go mod download
	go mod tidy

# Show version
version:
	@echo "Version: $(VERSION)"
	@echo "Image: $(IMAGE)"
