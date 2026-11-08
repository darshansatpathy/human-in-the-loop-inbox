.PHONY: install check db serve bench

db:
	docker run -d --name hitl-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:17
	@echo 'export HITL_TEST_ADMIN_URL=postgresql://postgres:postgres@localhost:5432/postgres'

install:
	pip install -e ".[dev]"

check:
	ruff check .
	ruff format --check .
	mypy
	hitl check-policy --file policy.yaml
	pytest --cov --cov-report=term-missing

serve:
	hitl serve

bench:
	python bench/load.py --flows 400 --concurrency 16 --out docs/performance.md
