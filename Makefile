SHELL := /bin/bash
COMPOSE ?= docker compose
.DEFAULT_GOAL := help

# Default log tailing targets when SERVICES is not provided
DEFAULT_LOG_SERVICES := ids-proxy demo-app
# Default attack arguments when none are passed in (overridable via ATTACK_SIM_ARGS)
ATTACK_SIM_ARGS ?= --all --pace 1.0
DEFAULT_ATTACK_ARGS := $(ATTACK_SIM_ARGS)
ATTACK_ENDPOINT ?= http://localhost:9000/run
ATTACK_PACE ?= 1.0
ATTACK_TARGET ?=
ATTACK_SCENARIOS ?=
WAIT_TIMEOUT ?= 60
WAIT_INTERVAL ?= 2

define banner
	@printf '\n==> %s\n' '$(1)'
endef

define wait_for
	@echo "Waiting for $(2) at $(1)"; \
	end=$$(( $$(date +%s) + $(WAIT_TIMEOUT) )); \
	while true; do \
		if curl -fsS --max-time 2 "$(1)" >/dev/null 2>&1; then \
			echo "$(2) is ready"; \
			break; \
		fi; \
		if [ $$(date +%s) -ge $$end ]; then \
			echo "Timed out waiting for $(2) at $(1)"; \
			exit 1; \
		fi; \
		sleep $(WAIT_INTERVAL); \
	done
endef

.PHONY: help
help:
	@echo "Simple IDS helper targets:"
	@echo "  make up            - build images (if needed) and start the full stack"
	@echo "  make down          - stop services and remove volumes"
	@echo "  make restart       - restart the stack (down + up)"
	@echo "  make build         - rebuild images without starting containers"
	@echo "  make logs          - tail container logs (override with SERVICES=...)"
	@echo "  make ps            - show container status"
	@echo "  make attack        - run attack simulator (ARGS='--sql' etc.)"
	@echo "  make events        - dump current IDS events via curl"
	@echo "  make top           - show top talkers from the proxy"
	@echo "  make context IP=...  - fetch context for a specific IP"
	@echo "  make shell-<svc>   - launch an interactive shell in a service container"
	@echo "  make clean         - prune containers, volumes, logs"

.PHONY: up
up:
	$(call banner,Building and starting services)
	@$(COMPOSE) up -d --build

.PHONY: down
down:
	$(call banner,Stopping services and removing volumes)
	@$(COMPOSE) down -v

.PHONY: restart
restart:
	$(call banner,Restarting stack)
	@$(COMPOSE) down -v
	@$(COMPOSE) up -d --build

.PHONY: build
build:
	$(call banner,Building images)
	@$(COMPOSE) build

.PHONY: logs
logs:
	$(call banner,Tailing logs)
	@services="$(if $(strip $(SERVICES)),$(strip $(SERVICES)),$(DEFAULT_LOG_SERVICES))"; \
	$(COMPOSE) logs -f $$services

.PHONY: ps
ps:
	$(call banner,Container status)
	@$(COMPOSE) ps

.PHONY: attack
attack:
	@if [ -n "$(strip $(ARGS))" ]; then \
		echo "Running attack simulator via CLI: $(ARGS)"; \
		ATTACK_SIM_MODE=cli $(COMPOSE) run --rm attack-sim $(ARGS); \
	else \
			echo "Triggering attack simulator API"; \
			payload=$$(python3 -c $$'import json, os\nscenarios=[s for s in os.environ.get("ATTACK_SCENARIOS", "").split() if s]\npace_raw=os.environ.get("ATTACK_PACE", "1.0")\ntry:\n    pace=float(pace_raw)\nexcept ValueError:\n    pace=1.0\ntarget=os.environ.get("ATTACK_TARGET", "").strip()\nif scenarios:\n    data={"scenarios":scenarios, "pace":pace}\nelse:\n    data={"all":True, "pace":pace}\nif target:\n    data["target"]=target\nprint(json.dumps(data))'); \
			curl -fsS -X POST -H 'Content-Type: application/json' -d "$$payload" $(ATTACK_ENDPOINT) 2>/tmp/attack.err | (command -v jq >/dev/null 2>&1 && jq . || cat); \
			if [ $$? -ne 0 ]; then \
				cat /tmp/attack.err; \
			fi; \
			rm -f /tmp/attack.err; \
	fi

.PHONY: all
all:
	$(call banner,Starting full demo stack)
	@$(COMPOSE) up -d --build
	$(call wait_for,http://localhost:8000/health,ids-proxy)
	$(call wait_for,http://localhost:5001/,demo-app)
	$(call wait_for,http://localhost:3000/,dashboard)
	$(call wait_for,http://localhost:9000/health,attack-sim)
	$(call banner,Running attack simulator)
	@ATTACK_SCENARIOS= $(MAKE) --no-print-directory attack
	$(call banner,Fetching latest IDS events)
	@$(MAKE) --no-print-directory events

.PHONY: events
events:
	$(call banner,Fetching events from ids-proxy)
	@{ curl -sS http://localhost:8000/events || true; } | (command -v jq >/dev/null 2>&1 && jq . || cat)

.PHONY: top
top:
	$(call banner,Top talkers)
	@{ curl -sS http://localhost:8000/top || true; } | (command -v jq >/dev/null 2>&1 && jq . || cat)

.PHONY: context
context:
	@if [ -z "$(IP)" ]; then \
		echo "Usage: make context IP=1.2.3.4"; \
		exit 1; \
	fi
	$(call banner,Context for $(IP))
	@{ curl -sS http://localhost:8000/context/$(IP) || true; } | (command -v jq >/dev/null 2>&1 && jq . || cat)

.PHONY: shell-%
shell-%:
	$(call banner,Opening shell in service $*)
	@$(COMPOSE) run --rm $* bash

.PHONY: clean
clean:
	$(call banner,Cleaning docker resources and logs)
	@$(COMPOSE) down -v --remove-orphans || true
	@vol_prefix=$$(basename "$(CURDIR)" | tr '[:upper:]' '[:lower:]'); \
	if docker volume ls -q --filter name="$$vol_prefix\_ids_data" | grep -q "$$vol_prefix\_ids_data"; then \
		docker volume rm "$$vol_prefix\_ids_data" >/dev/null 2>&1 || true; \
	fi
	@docker image prune -f >/dev/null 2>&1 || true
	@rm -rf demo-app/logs ids-proxy/logs || true
	@find . -name '__pycache__' -type d -prune -exec rm -rf {} +
