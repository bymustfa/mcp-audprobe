.PHONY: install test demo
install:
	python3 -m venv .venv && .venv/bin/pip install -e ".[test]"
test:
	.venv/bin/python -m pytest -q
demo:
	./demo/run_demo.sh
