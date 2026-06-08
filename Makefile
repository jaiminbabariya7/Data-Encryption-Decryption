.PHONY: install install-dev lint test clean
install:
	pip install -r requirements.txt
install-dev: install
	pip install black isort flake8
lint:
	flake8 src/ tests/ --max-line-length=100
	black --check --line-length 100 src/ tests/
format:
	black --line-length 100 src/ tests/
test:
	pytest tests/ -v --cov=src --cov-report=term-missing
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true