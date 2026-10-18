.DEFAULT_GOAL := test

PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: test run benchmark compile

test:
	@FALKORDB_HOST=127.0.0.1 FALKORDB_PORT=6399 FALKORDB_USERNAME= FALKORDB_PASSWORD= FALKORDB_SSL=false FALKORTRACE_STRICT_DB=0 $(PYTHON) -m pytest -q

run:
	@$(PYTHON) -m uvicorn backend.main:app --host 0.0.0.0 --port $${PORT:-8000}

benchmark:
	@FALKORDB_HOST=127.0.0.1 FALKORDB_PORT=6399 FALKORDB_USERNAME= FALKORDB_PASSWORD= FALKORDB_SSL=false FALKORTRACE_STRICT_DB=0 $(PYTHON) -c "from backend.agent import run_head_to_head_benchmark; import json; print(json.dumps(run_head_to_head_benchmark(), indent=2))"

compile:
	@$(PYTHON) -m compileall -q backend api tests
