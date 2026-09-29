#!/usr/bin/env bash
# One-command, model-aware launcher for the complete long-running Aegis development stack.
#
# Examples:
#   ./start.sh                         # DeepSeek (default)
#   ./start.sh --model qwen3:8b       # explicit local override
#   ./start.sh up --model qwen/qwen3.8-27b  # OPENROUTER_API_KEY comes from .env.gateway
#   ./start.sh status
#   ./start.sh logs
#   ./start.sh down

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="$ROOT_DIR/.aegis-stack.env"
# Match Docker Compose's normal per-directory project name by default so this launcher reuses an
# already-created stack and its fixed-subnet networks instead of trying to create overlapping
# duplicates. Operators can still choose a name explicitly with COMPOSE_PROJECT_NAME.
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-${ROOT_DIR##*/}}"

COMMAND="up"
MODEL=""
BUILD=1
WAIT=1
# Keep the long-running footprint small. The console's AI test creates no Docker resources.
CORE_ONLY=1
TOOLBOX_MODE="auto"
DEBUG_LOGGING="${AEGIS_DEBUG_LOGGING:-1}"
LOG_TAIL="${AEGIS_LOG_TAIL:-1000}"
LOG_FILE=""
CURRENT_STEP="bootstrap"
STARTED_AT="$SECONDS"

usage() {
  cat <<'EOF'
Usage:
  ./start.sh [up] [--model MODEL] [options]
  ./start.sh MODEL [options]
  ./start.sh down|status|logs|doctor|models [--model MODEL]

Models:
  deepseek-v4-pro             DeepSeek-compatible gateway (default)
  qwen3:4b                    Ollama / LOCAL_LLM
  qwen3:8b                    Ollama / LOCAL_LLM
  foundation-sec:8b-q4       Ollama / LOCAL_LLM
  ollama:<model>              Any explicitly selected Ollama model
  deepseek-chat               DeepSeek-compatible gateway
  deepseek-reasoner           DeepSeek-compatible gateway
  deepseek:<model>            Any explicitly selected DeepSeek model
  qwen/qwen3.8-27b            OpenRouter (the repository's exact pinned model)
  openrouter                  Alias for qwen/qwen3.8-27b

Options:
  -m, --model MODEL           Select the LLM model/provider profile
      --no-build              Do not build images before starting
      --no-wait               Return after containers are created
      --core-only             Start base + model + dashboard only (default)
      --full-lab              Also start synthetic range, Nuclei and ZAP services
      --no-toolbox            Exclude the disposable assessment toolbox
      --with-toolbox          Require the toolbox (all provider profiles)
      --debug                 Extensive timestamped launcher/runtime diagnostics (default)
      --quiet                 Disable launcher DEBUG lines; service request logs remain enabled
  -h, --help                  Show this help

The default stack includes the dashboard and selected model gateway. Use --full-lab only when the
long-running vulnerable range and scanner services are actually needed. The console's Test AI
button uses an ephemeral in-memory synthetic fixture and allocates no Docker network.
Runtime secrets are generated in memory and are never printed or written to the state file.
Debug logs are persisted below artifacts/runtime-logs with credential values redacted by design.
EOF
}

die() {
  log ERROR "$CURRENT_STEP" "$*"
  exit 1
}

note() {
  log INFO "$CURRENT_STEP" "$*"
}

log() {
  local level="$1" step_name="$2"
  shift 2
  local line
  line="$(printf '%s [%s] [%s] %s' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$level" "$step_name" "$*")"
  printf '%s\n' "$line"
  if [ -n "$LOG_FILE" ]; then
    printf '%s\n' "$line" >> "$LOG_FILE"
  fi
}

debug() {
  [ "$DEBUG_LOGGING" = "1" ] || return 0
  log DEBUG "$CURRENT_STEP" "$*"
}

step() {
  CURRENT_STEP="$1"
  shift
  debug "$*"
}

init_logging() {
  [ "$DEBUG_LOGGING" = "1" ] || return 0
  local log_dir="$ROOT_DIR/artifacts/runtime-logs"
  mkdir -p "$log_dir"
  LOG_FILE="$log_dir/start-$(date -u +'%Y%m%dT%H%M%SZ')-$$.log"
  : > "$LOG_FILE"
  debug "Persistent launcher log initialized: $LOG_FILE"
}

on_error() {
  local line="$1" status="$2"
  log ERROR "$CURRENT_STEP" "Step failed at line $line (exit=$status); secret values were not logged"
}

on_exit() {
  local status="$1"
  local elapsed=$((SECONDS - STARTED_AT))
  if [ "$status" -eq 0 ]; then
    debug "Command completed successfully in ${elapsed}s"
  else
    log ERROR "$CURRENT_STEP" "Command exited with status $status after ${elapsed}s"
  fi
}

trap 'on_error "$LINENO" "$?"' ERR
trap 'on_exit "$?"' EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

load_state() {
  # MODEL is intentionally not restored: every invocation defaults to DeepSeek unless the
  # operator explicitly supplies --model. The state file remains useful forensic context only.
  return 0
}

save_state() {
  umask 077
  {
    printf 'MODEL=%s\n' "$MODEL"
    printf 'PROVIDER=%s\n' "$PROVIDER"
  } > "$STATE_FILE"
}

show_models() {
  cat <<'EOF'
Model/provider routes:
  deepseek-v4-pro           -> docker-compose.deepseek.yml (default)
  qwen3:4b                  -> docker-compose.ollama.yml
  qwen3:8b                  -> docker-compose.ollama.yml
  foundation-sec:8b-q4     -> docker-compose.ollama.yml
  ollama:<model>            -> docker-compose.ollama.yml
  deepseek-chat             -> docker-compose.deepseek.yml
  deepseek-reasoner         -> docker-compose.deepseek.yml
  deepseek:<model>          -> docker-compose.deepseek.yml
  qwen/qwen3.8-27b         -> docker-compose.openrouter.yml
  openrouter                -> qwen/qwen3.8-27b
EOF
}

parse_arguments() {
  if [ "$#" -gt 0 ]; then
    case "$1" in
      up|down|status|logs|doctor|models)
        COMMAND="$1"
        shift
        ;;
      -*) ;;
      *)
        MODEL="$1"
        shift
        ;;
    esac
  fi

  while [ "$#" -gt 0 ]; do
    case "$1" in
      -m|--model)
        [ "$#" -ge 2 ] || die "$1 requires a model name"
        MODEL="$2"
        shift 2
        ;;
      --no-build)
        BUILD=0
        shift
        ;;
      --no-wait)
        WAIT=0
        shift
        ;;
      --core-only)
        CORE_ONLY=1
        shift
        ;;
      --full-lab)
        CORE_ONLY=0
        shift
        ;;
      --no-toolbox|--no-beast)
        TOOLBOX_MODE="off"
        shift
        ;;
      --with-toolbox|--with-beast)
        TOOLBOX_MODE="on"
        CORE_ONLY=0
        shift
        ;;
      --debug)
        DEBUG_LOGGING=1
        shift
        ;;
      --quiet)
        DEBUG_LOGGING=0
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1 (use --help)"
        ;;
    esac
  done
}

select_provider() {
  [ -n "$MODEL" ] || MODEL="deepseek-v4-pro"

  case "$MODEL" in
    openrouter)
      MODEL="qwen/qwen3.8-27b"
      PROVIDER="openrouter"
      PROVIDER_FILE="docker-compose.openrouter.yml"
      ;;
    qwen/qwen3.8-27b)
      PROVIDER="openrouter"
      PROVIDER_FILE="docker-compose.openrouter.yml"
      ;;
    qwen3:4b|qwen3:8b|foundation-sec:8b-q4)
      PROVIDER="ollama"
      PROVIDER_FILE="docker-compose.ollama.yml"
      ;;
    ollama:*)
      MODEL="${MODEL#ollama:}"
      [ -n "$MODEL" ] || die "ollama:<model> requires a model name"
      PROVIDER="ollama"
      PROVIDER_FILE="docker-compose.ollama.yml"
      ;;
    deepseek-v4-pro|deepseek-chat|deepseek-reasoner)
      PROVIDER="deepseek"
      PROVIDER_FILE="docker-compose.deepseek.yml"
      ;;
    deepseek:*)
      MODEL="${MODEL#deepseek:}"
      [ -n "$MODEL" ] || die "deepseek:<model> requires a model name"
      PROVIDER="deepseek"
      PROVIDER_FILE="docker-compose.deepseek.yml"
      ;;
    *)
      die "Unsupported model '$MODEL'. Run './start.sh models' to see model routes."
      ;;
  esac

  export AI_MODEL="$MODEL"
  # The gateway may switch at runtime only inside this exact startup allowlist. Provider family,
  # endpoint, credential placement and network topology remain fixed until the launcher restarts.
  case "$PROVIDER" in
    ollama)
      export AI_ALLOWED_MODELS="qwen3:4b,qwen3:8b,foundation-sec:8b-q4,$MODEL"
      ;;
    deepseek)
      export AI_ALLOWED_MODELS="deepseek-v4-pro,deepseek-chat,deepseek-reasoner"
      ;;
    openrouter)
      # Must equal OPENROUTER_APPROVED_MODELS in src/aegis/settings.py exactly: the provider and
      # the fail-closed readiness check reject any other set. Full GLM 5.3 family included.
      export AI_ALLOWED_MODELS="qwen/qwen3.8-27b,deepseek/deepseek-v4-flash,z-ai/glm-5.3,z-ai/glm-5.3-flash,z-ai/glm-5.3-flashx,z-ai/glm-5.3-prime"
      ;;
  esac

}

generate_runtime_secrets() {
  step runtime-secrets "Generating or reusing isolated runtime credentials"
  require_command openssl
  : "${BEAST_SUPERVISOR_TOKEN:=$(openssl rand -hex 32)}"
  : "${BEAST_BOUNDARY_TOKEN:=$(openssl rand -hex 32)}"
  : "${AEGIS_ZAP_GUARD_CONTROL_SECRET:=$(openssl rand -hex 32)}"
  : "${AEGIS_ZAP_ACTIVE_LEASE_SECRET:=$(openssl rand -hex 32)}"
  : "${AEGIS_ZAP_ACTIVE_ADMISSION_CLIENT:=$(openssl rand -hex 32)}"
  : "${AEGIS_ZAP_ACTIVE_RUNNER_CLIENT:=$(openssl rand -hex 32)}"
  : "${AEGIS_ZAP_ACTIVE_OPERATOR_BOOTSTRAP_SECRET:=$(openssl rand -hex 32)}"

  export BEAST_SUPERVISOR_TOKEN BEAST_BOUNDARY_TOKEN
  export AEGIS_ZAP_GUARD_CONTROL_SECRET AEGIS_ZAP_ACTIVE_LEASE_SECRET
  export AEGIS_ZAP_ACTIVE_ADMISSION_CLIENT AEGIS_ZAP_ACTIVE_RUNNER_CLIENT
  export AEGIS_ZAP_ACTIVE_OPERATOR_BOOTSTRAP_SECRET
  debug "Runtime credential set is complete (values suppressed)"
}

validate_provider_inputs() {
  step provider-validation "Validating provider prerequisites without reading credentials into logs"
  case "$PROVIDER" in
    ollama)
      return 0
      ;;
    deepseek)
      [ -f "$ROOT_DIR/.env.gateway" ] || die ".env.gateway is required for DeepSeek (AI_AUTH_TOKEN=<key>)"
      awk -F= '/^[[:space:]]*AI_AUTH_TOKEN=/{sub(/^[^=]*=/, ""); if (length($0) > 0) found=1} END{exit !found}' \
        "$ROOT_DIR/.env.gateway" || die ".env.gateway must contain a non-empty AI_AUTH_TOKEN"
      debug "DeepSeek gateway credential file is present and non-empty (value suppressed)"
      ;;
    openrouter)
      [ -f "$ROOT_DIR/.env.gateway" ] || die ".env.gateway is required for OpenRouter (OPENROUTER_API_KEY=<key>)"
      awk -F= '/^[[:space:]]*OPENROUTER_API_KEY=/{sub(/^[^=]*=/, ""); if (length($0) > 0) found=1} END{exit !found}' \
        "$ROOT_DIR/.env.gateway" || die ".env.gateway must contain a non-empty OPENROUTER_API_KEY"
      debug "OpenRouter gateway credential is present and non-empty (value suppressed)"
      ;;
  esac
}

build_compose_args() {
  step compose-plan "Building the ordered Compose overlay plan"
  COMPOSE_ARGS=(
    -p "$PROJECT_NAME"
    -f "$ROOT_DIR/docker-compose.yml"
    -f "$ROOT_DIR/$PROVIDER_FILE"
    -f "$ROOT_DIR/docker-compose.dashboard.yml"
  )

  INCLUDE_TOOLBOX=0
  if [ "$CORE_ONLY" -eq 0 ]; then
    COMPOSE_ARGS+=(
      -f "$ROOT_DIR/docker-compose.range.yml"
      -f "$ROOT_DIR/docker-compose.nuclei.yml"
      -f "$ROOT_DIR/docker-compose.zap.yml"
      -f "$ROOT_DIR/docker-compose.zap-active.yml"
    )

    if [ "$TOOLBOX_MODE" != "off" ]; then
      INCLUDE_TOOLBOX=1
      COMPOSE_ARGS+=(
        -f "$ROOT_DIR/docker-compose.beast.yml"
      )
    fi

    # Engine overlays bind Uvicorn to its fixed lab address instead of localhost. Keep the
    # matching healthcheck last so later overlays cannot restore the base 127.0.0.1 probe.
    COMPOSE_ARGS+=(
      -f "$ROOT_DIR/docker-compose.engine-healthcheck.yml"
    )
  elif [ "$TOOLBOX_MODE" = "on" ]; then
    die "--core-only and --with-toolbox cannot be used together"
  fi
  debug "Compose overlays: ${COMPOSE_ARGS[*]}"
}

compose() {
  debug "Compose action: $*"
  if [ -n "$LOG_FILE" ]; then
    docker compose "${COMPOSE_ARGS[@]}" "$@" 2>&1 | tee -a "$LOG_FILE"
  else
    docker compose "${COMPOSE_ARGS[@]}" "$@"
  fi
}

print_plan() {
  note "Project: $PROJECT_NAME"
  note "Provider: $PROVIDER"
  note "Model: $MODEL"
  if [ "$CORE_ONLY" -eq 1 ]; then
    note "Profile: core (application + model gateway + dashboard)"
  else
    note "Profile: full (range + Nuclei + passive/active ZAP$([ "$INCLUDE_TOOLBOX" -eq 1 ] && printf ' + toolbox'))"
  fi
  if [ "$INCLUDE_TOOLBOX" -eq 0 ] && [ "$CORE_ONLY" -eq 0 ]; then
    if [ "$TOOLBOX_MODE" = "off" ]; then
      note "Toolbox: disabled by operator"
    else
      note "Toolbox: skipped for unsupported provider '$PROVIDER'"
    fi
  fi
  note "Debug logging: $([ "$DEBUG_LOGGING" = "1" ] && printf enabled || printf reduced)"
  [ -z "$LOG_FILE" ] || note "Launcher log: $LOG_FILE"
}

run_up() {
  step startup-preflight "Running startup preflight"
  validate_provider_inputs
  generate_runtime_secrets
  build_compose_args
  print_plan

  step compose-validation "Validating merged Compose configuration"
  note "Validating merged Compose configuration"
  compose config --quiet
  debug "Merged Compose configuration accepted"

  # Never remove unrelated/previously healthy services during an up. A later network/build failure
  # must not turn a partial rollout into an outage. Operators can use the explicit `down` command
  # when they actually intend to remove the selected stack.
  local up_args=(up -d)
  [ "$BUILD" -eq 1 ] && up_args+=(--build)

  if [ "$WAIT" -eq 1 ] && docker compose up --help 2>/dev/null | grep -q -- '--wait'; then
    up_args+=(--wait --wait-timeout "${AEGIS_START_TIMEOUT_SECONDS:-420}")
  fi

  step service-start "Building and starting services"
  note "Starting services"
  if ! compose "${up_args[@]}"; then
    printf '\nStartup failed. Recent service state:\n' >&2
    compose ps >&2 || true
    printf '\nUse ./start.sh logs for details.\n' >&2
    exit 1
  fi

  save_state
  step service-status "Collecting final service state"
  printf '\n'
  compose ps
  printf '\nAegis is ready: http://127.0.0.1:8000/console/\n'
}

run_doctor() {
  step doctor "Running non-mutating deployment diagnostics"
  validate_provider_inputs
  generate_runtime_secrets
  build_compose_args
  print_plan
  step docker-daemon "Checking Docker daemon availability"
  note "Checking Docker daemon"
  docker info >/dev/null
  step compose-validation "Validating merged Compose configuration"
  note "Validating merged Compose configuration"
  compose config --quiet
  note "Preflight passed"
}

main() {
  cd "$ROOT_DIR"
  parse_arguments "$@"
  init_logging
  step argument-resolution "Arguments parsed; secrets and raw command line intentionally omitted"

  if [ "$COMMAND" = "models" ]; then
    show_models
    exit 0
  fi

  load_state
  debug "Persistent state inspected; saved MODEL does not override the DeepSeek default"
  select_provider
  export AEGIS_DEBUG_LOGGING="$DEBUG_LOGGING"
  debug "Selected provider=$PROVIDER model=$MODEL project=$PROJECT_NAME"
  require_command docker
  step docker-preflight "Checking Docker Compose availability"
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"

  case "$COMMAND" in
    up)
      run_up
      ;;
    down)
      generate_runtime_secrets
      build_compose_args
      step shutdown "Stopping the selected stack"
      print_plan
      compose down --remove-orphans
      ;;
    status)
      generate_runtime_secrets
      build_compose_args
      step status "Collecting service status"
      print_plan
      compose ps
      ;;
    logs)
      generate_runtime_secrets
      build_compose_args
      step service-logs "Following timestamped service logs"
      print_plan
      compose logs --timestamps --tail "$LOG_TAIL" -f
      ;;
    doctor)
      run_doctor
      ;;
    *)
      die "Unknown command: $COMMAND"
      ;;
  esac
}

main "$@"
