PYTHON ?= python3
LABCTL = $(PYTHON) -m tools.labctl

.PHONY: up down setup validate cleanup test

# Preflight (loopback-only, free ports) then docker compose up -d
up:
	$(LABCTL) up

down:
	docker compose down

# Load pipeline, index template, dashboards and monitors into OpenSearch
setup:
	$(LABCTL) setup

validate:
	$(LABCTL) validate $(if $(SEED),--seed $(SEED),)

cleanup:
	$(LABCTL) cleanup

test:
	$(PYTHON) -m pytest
