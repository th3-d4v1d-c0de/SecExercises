.PHONY: help run test all clean run-ex1 test-ex1 run-ex2 test-ex2 clean-ex1 clean-ex2

help:
	@echo "Available commands:"
	@echo "  make test      - Run all unit tests across all exercises"
	@echo "  make run       - Run all exercise solution scripts"
	@echo "  make test-ex1  - Run unit tests for Exercise 1 (Cloud IAM)"
	@echo "  make run-ex1   - Run solution script for Exercise 1"
	@echo "  make test-ex2  - Run unit tests for Exercise 2 (CIDR Filtering)"
	@echo "  make run-ex2   - Run solution script for Exercise 2"
	@echo "  make all       - Run all tests and solutions"
	@echo "  make clean     - Remove compiled Python bytecode and caches"

run: run-ex1 run-ex2

run-ex1:
	$(MAKE) -C detect_suspicious_cloud_iam_activity run

run-ex2:
	$(MAKE) -C cidr_network_allowlist_filtering run

test: test-ex1 test-ex2

test-ex1:
	$(MAKE) -C detect_suspicious_cloud_iam_activity test

test-ex2:
	$(MAKE) -C cidr_network_allowlist_filtering test

clean-ex1:
	$(MAKE) -C detect_suspicious_cloud_iam_activity clean

clean-ex2:
	$(MAKE) -C cidr_network_allowlist_filtering clean

clean: clean-ex1 clean-ex2
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

all: test run
