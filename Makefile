# Makefile for RougeDHCPSnooper

.PHONY: help install test clean lint run setup dev-install

# Default target
help:
	@echo "Available targets:"
	@echo "  install     - Install the package and dependencies"
	@echo "  dev-install - Install in development mode"
	@echo "  test        - Run unit tests"
	@echo "  lint        - Run code linting"
	@echo "  clean       - Remove build artifacts"
	@echo "  run         - Run the DHCP snooper"
	@echo "  setup       - Initial project setup"
	@echo "  help        - Show this help message"

# Install package and dependencies
install:
	@echo "Installing RougeDHCPSnooper..."
	pip3 install -r requirements.txt
	pip3 install .

# Development installation
dev-install:
	@echo "Installing in development mode..."
	pip3 install -r requirements.txt
	pip3 install -e .

# Run tests
test:
	@echo "Running unit tests..."
	python3 -m unittest test_dhcp_snooper.py -v

# Run linting (if tools are available)
lint:
	@echo "Running code linting..."
	@if command -v flake8 >/dev/null 2>&1; then \
		flake8 dhcp_snooper.py test_dhcp_snooper.py; \
	else \
		echo "flake8 not found, skipping linting"; \
	fi

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf __pycache__/
	rm -rf .pytest_cache/
	rm -f *.pyc
	rm -f *.log
	rm -f dhcp_scan_results.json

# Run the DHCP snooper
run:
	@echo "Running DHCP snooper (requires sudo)..."
	@if [ "$(shell id -u)" -ne 0 ]; then \
		echo "This requires root privileges. Please run: sudo make run"; \
		exit 1; \
	fi
	python3 dhcp_snooper.py

# Initial project setup
setup:
	@echo "Setting up project..."
	chmod +x dhcp_snooper.py
	@if [ ! -f dhcp_whitelist.txt ]; then \
		echo "Creating sample whitelist file..."; \
		echo "# Sample authorized DHCP servers" > dhcp_whitelist.txt; \
		echo "192.168.1.1" >> dhcp_whitelist.txt; \
		echo "10.0.0.1" >> dhcp_whitelist.txt; \
	fi
	@echo "Project setup complete!"

# Development environment setup
dev-setup: setup dev-install
	@echo "Development environment ready!"