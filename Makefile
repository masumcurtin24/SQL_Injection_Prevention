.PHONY: fmt lint test test-golden db-up db-current db-heads smoke baseline baseline-frontend critical-subset benchmark benchmark-update-baseline deps deps-dev deps-lock deps-sync-lock yara-stage yara-promote-dry yara-promote yara-promote-canary roadmap-sql-adversarial roadmap-sql-context roadmap-sql-features roadmap-sql-rules roadmap-sql-all

PY ?= python

fmt:
	@echo "fmt: (no-op)"; \
	$(PY) -m compileall -q backend/server backend/core backend/security backend/services backend/utils backend/tests

lint:
	@echo "lint: (syntax check)"; \
	$(PY) -m compileall -q backend/server backend/core backend/security backend/services backend/utils backend/tests

test:
	$(PY) -m pytest -q

test-golden:
	@echo "No golden tests configured."

db-up:
	$(PY) -m alembic -c backend/alembic.ini upgrade head

db-current:
	$(PY) -m alembic -c backend/alembic.ini current

db-heads:
	$(PY) -m alembic -c backend/alembic.ini heads

smoke:
	$(PY) scripts/verify_runtime_baseline.py

baseline:
	$(PY) scripts/verify_runtime_baseline.py

baseline-frontend:
	$(PY) scripts/verify_runtime_baseline.py --include-frontend

critical-subset:
	$(PY) scripts/run_backend_critical_subset.py

benchmark:
	$(PY) backend/scripts/build_evaluation_corpus.py --domain all --strict
	$(PY) backend/scripts/run_benchmark_harness.py --domain all --disable-transformer --strict-gate

benchmark-update-baseline:
	$(PY) backend/scripts/build_evaluation_corpus.py --domain all --strict
	$(PY) backend/scripts/run_benchmark_harness.py --domain all --disable-transformer --update-baseline

deps:
	$(PY) -m pip install -r backend/requirements.txt

deps-dev:
	$(PY) -m pip install -r backend/requirements-dev.txt

deps-lock:
	$(PY) -m pip freeze > backend/requirements-lock.txt

deps-sync-lock:
	$(PY) -m pip install -r backend/requirements-lock.txt

yara-stage:
	$(PY) backend/scripts/update_yara_staging.py

yara-promote-dry:
	$(PY) backend/scripts/promote_yara_staging.py

yara-promote:
	$(PY) backend/scripts/promote_yara_staging.py --execute

yara-promote-canary:
	$(PY) backend/scripts/promote_yara_staging.py --execute --canary-count 3

roadmap-sql-adversarial:
	$(PY) backend/scripts/run_sql_adversarial_regression.py --strict-gate

roadmap-sql-context:
	$(PY) backend/scripts/export_sql_context_dataset.py --limit 10000

roadmap-sql-features:
	$(PY) backend/scripts/train_sql_feature_selection_baseline.py --include-context

roadmap-sql-rules:
	$(PY) backend/scripts/generate_sql_rule_suggestions.py

roadmap-sql-all:
	$(MAKE) roadmap-sql-adversarial
	$(MAKE) roadmap-sql-context
	$(MAKE) roadmap-sql-features
	$(MAKE) roadmap-sql-rules
