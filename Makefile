# Makefile for Passkey Origin Validator TypeScript Library

# Variables
NODE_VERSION ?= 18
NPM_REGISTRY ?= https://registry.npmjs.org/
PRIVATE_REGISTRY ?= 
DEBUG ?= false

# Default target
.PHONY: all
all: deps build test

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	@if [ -n "$(PRIVATE_REGISTRY)" ]; then \
		echo "Using private registry: $(PRIVATE_REGISTRY)"; \
		npm config set registry $(PRIVATE_REGISTRY); \
	else \
		echo "Using default registry: $(NPM_REGISTRY)"; \
		npm config set registry $(NPM_REGISTRY); \
	fi
	npm install

# Clean build artifacts and dependencies
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf dist/
	rm -rf node_modules/
	rm -rf coverage/
	rm -f package-lock.json

# Build the library
.PHONY: build
build:
	@echo "Building TypeScript library..."
	npm run build

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	npm test

# Run tests in watch mode
.PHONY: test-watch
test-watch:
	@echo "Running tests in watch mode..."
	npm run test:watch

# Run development mode (watch build)
.PHONY: dev
dev:
	@echo "Starting development mode..."
	npm run dev

# Run with debug logging
.PHONY: run
run:
	@echo "Running validation example..."
	@if [ "$(DEBUG)" = "true" ]; then \
		echo "Debug mode enabled"; \
	fi
	@if [ -n "$(DOMAIN)" ] && [ -n "$(ORIGIN)" ]; then \
		node -e "const { validatePasskeyOrigin } = require('./dist/index.js'); validatePasskeyOrigin('$(DOMAIN)', '$(ORIGIN)').then(r => console.log(JSON.stringify(r, null, 2))).catch(e => console.error('Error:', e.message))"; \
	else \
		echo "Usage: make run DOMAIN=example.com ORIGIN=https://app.example.com"; \
		echo "Example: make run DOMAIN=webauthn.io ORIGIN=https://webauthn.io"; \
	fi

# Lint the code
.PHONY: lint
lint:
	@echo "Linting code..."
	@if command -v eslint >/dev/null 2>&1; then \
		npx eslint src/**/*.ts; \
	else \
		echo "ESLint not installed, skipping lint check"; \
	fi

# Format the code
.PHONY: format
format:
	@echo "Formatting code..."
	@if command -v prettier >/dev/null 2>&1; then \
		npx prettier --write src/**/*.ts; \
	else \
		echo "Prettier not installed, skipping format"; \
	fi

# Prepare for publishing
.PHONY: prepublish
prepublish: clean deps build test
	@echo "Preparing for publish..."
	npm run prepublishOnly

# Publish to npm registry
.PHONY: publish
publish: prepublish
	@echo "Publishing to npm..."
	@if [ -n "$(PRIVATE_REGISTRY)" ]; then \
		echo "Publishing to private registry: $(PRIVATE_REGISTRY)"; \
		npm publish --registry $(PRIVATE_REGISTRY); \
	else \
		echo "Publishing to public registry"; \
		npm publish; \
	fi

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all          - Install deps, build, and test"
	@echo "  deps         - Install dependencies"
	@echo "  clean        - Clean build artifacts and dependencies"
	@echo "  build        - Build the TypeScript library"
	@echo "  test         - Run tests"
	@echo "  test-watch   - Run tests in watch mode"
	@echo "  dev          - Start development mode (watch build)"
	@echo "  run          - Run validation example (requires DOMAIN and ORIGIN)"
	@echo "  lint         - Lint the code (if ESLint is available)"
	@echo "  format       - Format the code (if Prettier is available)"
	@echo "  prepublish   - Prepare for publishing (clean, deps, build, test)"
	@echo "  publish      - Publish to npm registry"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  NODE_VERSION     - Node.js version to use (default: 18)"
	@echo "  NPM_REGISTRY     - NPM registry URL (default: https://registry.npmjs.org/)"
	@echo "  PRIVATE_REGISTRY - Private registry URL (overrides NPM_REGISTRY)"
	@echo "  DEBUG            - Enable debug logging (default: false)"
	@echo "  DOMAIN           - Domain for validation example"
	@echo "  ORIGIN           - Origin for validation example"
	@echo ""
	@echo "Examples:"
	@echo "  make run DOMAIN=webauthn.io ORIGIN=https://webauthn.io"
	@echo "  make publish PRIVATE_REGISTRY=https://npm.company.com/"
	@echo "  make test DEBUG=true"