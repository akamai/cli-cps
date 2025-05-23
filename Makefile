PYTHON = python3.10

.PHONY: help
help:
	@echo "  install     install all dev and production dependencies (virtualenv is created as venv)"
	@echo "  clean       remove unwanted stuff"
	@echo "  lint        check style with flake8"
	@echo "  test        run tests"
	@echo "  coverage    run tests with code coverage"

.PHONY: install
install:
	$(PYTHON) -m venv venv; . venv/bin/activate; python -m pip install -r dev-requirements.txt

.PHONY: clean
clean:
	rm -fr test
	rm -fr venv

.PHONY: lint
lint:
	pylint: ; @for py in *.py; do echo "Linting $$py"; pylint -rn $$py; done

.PHONY: test
test: #lint
	. venv/bin/activate; pytest -s --junitxml=test/tests.xml

.PHONY: test-docker
test-docker:
	sh ci/test_with_docker.sh

.PHONY: coverage
coverage:
	. venv/bin/activate; pytest --cov-report xml:test/coverage/cobertura-coverage.xml --cov=bin tests/

.PHONY: all
all: clean install test coverage
