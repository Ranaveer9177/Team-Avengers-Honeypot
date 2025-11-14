# Makefile for Multi-Service Honeypot System
# Note: For Windows, use WSL or Git Bash to run make commands

.PHONY: help install test lint format clean run run-dashboard run-honeypot dev-setup coverage docs

# Default target
.DEFAULT_GOAL := help

# Python command
PYTHON := python3
PIP := pip3

help:  ## Show this help message
	@echo "Multi-Service Honeypot System - Available Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

install:  ## Install all dependencies
	$(PIP) install -r requirements.txt

install-dev:  ## Install development dependencies
	$(PIP) install -r requirements.txt
	$(PIP) install pytest pytest-cov flake8 black mypy

dev-setup:  ## Setup development environment
	$(PYTHON) -m venv .venv
	@echo "Virtual environment created. Activate with:"
	@echo "  Linux/Mac: source .venv/bin/activate"
	@echo "  Windows:   .venv\\Scripts\\activate"
	@echo "Then run: make install-dev"

test:  ## Run all tests
	pytest tests/ -v

test-coverage:  ## Run tests with coverage report
	pytest tests/ --cov=. --cov-report=html --cov-report=term-missing

test-unit:  ## Run unit tests only
	pytest tests/ -v -m unit

test-integration:  ## Run integration tests only
	pytest tests/ -v -m integration

lint:  ## Run code linting (flake8)
	flake8 *.py tests/ --max-line-length=120

format:  ## Format code with black
	black *.py tests/ --line-length=120

type-check:  ## Run type checking with mypy
	mypy *.py --ignore-missing-imports

quality:  ## Run all quality checks (lint, format check, type check)
	@echo "Running flake8..."
	@$(MAKE) lint
	@echo "\nChecking code format..."
	@black --check *.py tests/ --line-length=120
	@echo "\nRunning type checks..."
	@$(MAKE) type-check

clean:  ## Clean up generated files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete
	find . -type f -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache htmlcov .coverage
	rm -rf build dist *.egg-info
	@echo "Cleaned up generated files"

clean-logs:  ## Clean log files and captures
	rm -rf logs/*.log logs/*.json pcaps/*.pcap
	@echo "Cleaned log files"

clean-all: clean clean-logs  ## Clean everything including logs

setup-dirs:  ## Create necessary directories
	mkdir -p logs config ssh_keys certs pcaps templates tests
	@echo "Created necessary directories"

run-honeypot:  ## Run honeypot server only
	$(PYTHON) unified_honeypot.py

run-dashboard:  ## Run dashboard only
	$(PYTHON) app.py

run:  ## Run both honeypot and dashboard (requires separate terminals)
	@echo "Start honeypot in one terminal: make run-honeypot"
	@echo "Start dashboard in another: make run-dashboard"

# Docker targets (if implementing Docker support)
docker-build:  ## Build Docker image
	docker build -t honeypot-system .

docker-run:  ## Run in Docker container
	docker run -p 2222:2222 -p 5001:5001 -p 8080:8080 -p 8443:8443 honeypot-system

# Documentation
docs:  ## Generate documentation
	@echo "Documentation files:"
	@echo "  README.md - Main documentation"
	@echo "  API.md - API documentation"
	@echo "  CONTRIBUTING.md - Contributing guidelines"
	@echo "  CHANGELOG.md - Version history"

# Maintenance
check-deps:  ## Check for outdated dependencies
	$(PIP) list --outdated

update-deps:  ## Update all dependencies
	$(PIP) install --upgrade -r requirements.txt

security-check:  ## Run security checks on dependencies
	$(PIP) install safety
	safety check

# Development
watch-tests:  ## Run tests in watch mode (requires pytest-watch)
	$(PIP) install pytest-watch
	ptw

profile:  ## Profile the honeypot performance
	$(PYTHON) -m cProfile -o profile.stats unified_honeypot.py

# Installation verification
verify:  ## Verify installation
	@echo "Checking Python version..."
	@$(PYTHON) --version
	@echo "\nChecking installed packages..."
	@$(PIP) list | grep -E "(paramiko|flask|requests|markupsafe)" || echo "Missing dependencies - run 'make install'"
	@echo "\nChecking directory structure..."
	@ls -la | grep -E "(logs|config|ssh_keys|certs|templates|tests)" || echo "Missing directories - run 'make setup-dirs'"
	@echo "\nVerification complete"

# Quick start
quickstart:  ## Quick start - setup everything
	@echo "Setting up Multi-Service Honeypot System..."
	@$(MAKE) setup-dirs
	@$(MAKE) install
	@echo "\nSetup complete! You can now:"
	@echo "  1. Run honeypot: make run-honeypot"
	@echo "  2. Run dashboard: make run-dashboard"
	@echo "  Or use start.sh (Linux) / start.ps1 (Windows)"
