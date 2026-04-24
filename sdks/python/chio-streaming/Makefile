# chio-streaming developer targets.
#
# Unit tests run against in-memory broker doubles and need no infra.
# Integration tests run against a live broker stack and are gated by
# CHIO_INTEGRATION=1 (see tests/integration/conftest.py).

# Resolve the repo root so the compose file path works regardless of
# where `make` was invoked from.
REPO_ROOT := $(shell git rev-parse --show-toplevel)
COMPOSE   := docker compose -f $(REPO_ROOT)/infra/streaming-compose.yml

.PHONY: help test test-integration infra-up infra-down infra-logs

help:
	@echo "Targets:"
	@echo "  test              Unit tests (no broker required)"
	@echo "  test-integration  Bring up brokers, run live tests, tear down"
	@echo "  infra-up          Start the integration broker stack"
	@echo "  infra-down        Stop the integration broker stack and drop volumes"
	@echo "  infra-logs        Tail broker logs"

test:
	uv run pytest -v

infra-up:
	$(COMPOSE) up -d --wait

infra-down:
	$(COMPOSE) down -v

infra-logs:
	$(COMPOSE) logs -f

# Brings up brokers, runs the live-broker suite, and tears down even on
# failure (the trap fires before `make` exits non-zero).
test-integration:
	$(COMPOSE) up -d --wait
	@trap '$(COMPOSE) down -v' EXIT; \
	  CHIO_INTEGRATION=1 \
	  CHIO_TEST_REDIS_URL=redis://localhost:16379/0 \
	  CHIO_TEST_NATS_URL=nats://localhost:14222 \
	  uv run pytest tests/integration -v
