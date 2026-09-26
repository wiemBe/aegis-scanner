# Aegis AI Security Lab — reproducible OFFLINE / CONTAINER developer workflow.
#
# SAFETY (read before adding a target):
#   * No target in this file loads `.env.gateway`, reads a provider secret, or runs a live
#     `--execute-live` campaign. Live entry points stay inert: they require explicit arming flags
#     AND exact budgets and are run by the operator by hand, never from `make`.
#   * Targets are grouped OFFLINE (no Docker, no network, no provider), CONTAINER (local synthetic
#     Docker range only, no public egress) and UTILITY. There is deliberately no LIVE group.
#
# Canonical Python: 3.12 (pyproject requires-python >=3.12; mypy runs as python_version 3.12). A
# newer local interpreter (e.g. 3.14) works for running the suite, but 3.12 is the supported target.

PYTHON ?= $(shell command -v python3.12 2>/dev/null || command -v python3)
VENV ?= .venv
VBIN := $(VENV)/bin
PYTEST := $(VBIN)/python -m pytest -p no:cacheprovider
RANGE_IMAGE_TAG := aegis-range-phase29:2.9.0
RANGE_DOCKERFILE := deploy/range/Dockerfile.phase-2-9
MODE ?= healthy
SAMPLES ?= 12
CONTAINER_ENGINE ?= podman

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help.
	@grep -hE '^[a-zA-Z0-9_.-]+:.*## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*## "}{printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'

# --- environment --------------------------------------------------------------------------------- #

.PHONY: venv
venv: ## Create the virtualenv with the canonical Python and install the project + dev deps.
	@echo ">> using interpreter: $(PYTHON)"
	$(PYTHON) -m venv $(VENV)
	$(VBIN)/python -m pip install --quiet --upgrade pip
	$(VBIN)/python -m pip install -e ".[dev]"

# --- OFFLINE: lint / type / test (no Docker, no network, no provider) ---------------------------- #

.PHONY: lint
lint: ## Ruff across the repository.
	$(VBIN)/ruff check .

.PHONY: typecheck
typecheck: ## Mypy under the canonical Python version (python_version=3.12 from pyproject).
	$(VBIN)/mypy

.PHONY: test
test: ## Full offline test suite once.
	$(PYTEST) -q

.PHONY: test-focused
test-focused: ## Run a focused subset: make test-focused TESTS="tests/test_phase_2_9.py".
	$(PYTEST) -q $(TESTS)

.PHONY: test-artifact-empty
test-artifact-empty: ## Prove the suite passes in an artifact-empty checkout (no private artifacts/).
	@tmp=$$(mktemp -d) \
	  && git archive HEAD | tar -x -C "$$tmp" \
	  && echo ">> running suite in artifact-empty export: $$tmp" \
	  && ( cd "$$tmp" && "$(CURDIR)/$(VBIN)/python" -m pytest -q -p no:cacheprovider ) ; \
	  rc=$$? ; rm -rf "$$tmp" ; exit $$rc

.PHONY: check
check: lint typecheck test ## The offline CI-equivalent: lint + typecheck + full suite (no secrets).

.PHONY: production-preflight
production-preflight: ## Prove the immutable private-provider Compose topology (no pull/start/call).
	$(VBIN)/python -m aegis.deploy.private_provider_preflight

.PHONY: aegis-ai-prod-preflight
aegis-ai-prod-preflight: ## Prove standalone Fedora/RHEL prod; CONTAINER_ENGINE=podman|docker.
	$(VBIN)/python -m aegis.deploy.aegis_ai_prod_preflight --engine "$(CONTAINER_ENGINE)"

.PHONY: staging-gate
staging-gate: ## Observe localhost readiness; MODE=healthy|not-ready SAMPLES=12 (read-only).
	$(VBIN)/python -m aegis.deploy.staging_gate --mode "$(MODE)" --samples "$(SAMPLES)"

# --- CONTAINER: local synthetic Docker range only (no public egress) ----------------------------- #

.PHONY: docker-check
docker-check: ## Report whether a usable Docker daemon is available.
	@if docker info >/dev/null 2>&1 ; then echo "docker: AVAILABLE" ; \
	  else echo "docker: UNAVAILABLE (container acceptance will SKIP)" ; fi

.PHONY: vendor-range-wheels
vendor-range-wheels: ## Vendor linux wheels for the egress-free range image build (local, gitignored).
	@arch=$$(docker version --format '{{.Server.Arch}}' 2>/dev/null || echo arm64) ; \
	  case "$$arch" in arm64|aarch64) plat=manylinux2014_aarch64 ;; amd64|x86_64) plat=manylinux2014_x86_64 ;; \
	    *) echo "unsupported docker arch: $$arch" ; exit 1 ;; esac ; \
	  echo ">> vendoring wheels for $$plat (py3.12) into deploy/range/wheels" ; \
	  $(VBIN)/python -m pip download --only-binary=:all: --platform "$$plat" \
	    --python-version 3.12 --implementation cp --abi cp312 -d deploy/range/wheels \
	    fastapi==0.116.1 uvicorn==0.35.0 pydantic==2.13.5

.PHONY: range-image
range-image: ## Build the pinned, egress-free synthetic range image (needs vendored wheels).
	docker build -t $(RANGE_IMAGE_TAG) -f $(RANGE_DOCKERFILE) .

.PHONY: container-acceptance
container-acceptance: ## Run containerized synthetic acceptance tests (skips if Docker is unavailable).
	$(PYTEST) -q tests/test_phase_2_9.py tests/test_phase_2_8_container_acceptance.py

.PHONY: cleanup-check
cleanup-check: ## Fail if any aegis-labelled container or network was left behind.
	@c=$$(docker ps -a --filter "label=aegis" --format '{{.Names}}' 2>/dev/null) ; \
	  n=$$(docker network ls --filter "label=aegis" --format '{{.Name}}' 2>/dev/null) ; \
	  r=$$(docker ps -a --format '{{.Image}} {{.Names}}' 2>/dev/null | grep -i aegis-range || true) ; \
	  if [ -n "$$c$$n$$r" ]; then echo "LEFTOVERS FOUND:" ; echo "$$c $$n $$r" ; exit 1 ; \
	  else echo "cleanup: no aegis container/network leftovers" ; fi
