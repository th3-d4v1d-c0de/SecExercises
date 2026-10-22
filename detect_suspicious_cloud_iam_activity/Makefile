.PHONY: help run test all clean

PYTHON := python3

help:
	@echo "Available commands:"
	@echo "  make run    - Run the solution script on sample logs"
	@echo "  make test   - Run unit tests for the challenge"
	@echo "  make all    - Run both tests and the solution script"
	@echo "  make clean  - Remove compiled Python bytecode and caches"

run:
	$(PYTHON) solution.py

test:
	$(PYTHON) -m unittest test_solution.py

all: test run

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
