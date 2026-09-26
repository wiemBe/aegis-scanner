from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Provider selector -> dashboard/audit mode label. The control plane maps AI_PROVIDER to a mode
# label only; it holds no provider-specific request logic. LOCAL_LLM is a private Ollama runtime;
# INTERNAL_LLM is the company's private OpenAI-compatible endpoint. Public LLM egress is NOT the
# intended deployment model (the OpenAI Responses path is a deprecated, disabled compatibility
# profile). Ollama runs are never labelled LIVE_LLM.
PROVIDER_MODE_LABELS: dict[str, str] = {
    "demo": "DEMO_HEURISTIC",
    "ollama": "LOCAL_LLM",
    "internal_openai_compatible": "INTERNAL_LLM",
    "openai_responses": "PUBLIC_LLM_DEPRECATED",
    # DeepSeek is a public hosted API: the label is honest about the egress and the loss of the
    # digest-pinned, reproducible provenance that local Ollama runs carry.
    "deepseek": "PUBLIC_LLM_DEEPSEEK",
    "openrouter": "PUBLIC_LLM_OPENROUTER",
}

# The single OpenRouter model this project pins. Defined here (the lightweight settings module) so
# both the provider and the fail-closed readiness config check share one canonical identifier; the
# provider re-exports it for backward compatibility.
OPENROUTER_QWEN_MODEL = "qwen/qwen3.8-27b"

ProviderName = Literal[
    "demo",
    "ollama",
    "internal_openai_compatible",
    "openai_responses",
    "deepseek",
    "openrouter",
]
AuthMode = Literal["none", "bearer"]
# Structured-output negotiation for OpenAI-compatible backends. "json_schema" uses the provider's
# strict JSON-Schema response_format (OpenAI); "json_object" uses plain JSON mode and embeds the
# same strict schema in the prompt (e.g. DeepSeek, which does not support json_schema). In BOTH
# cases the full local Pydantic/JSON-Schema validation chain still runs and nothing is coerced.
JsonResponseMode = Literal["json_schema", "json_object"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Aegis AI Security Lab"

    # --- Provider selection (provider-agnostic control plane) -----------------------------------
    # demo                       -> offline DemoHeuristic planner, no gateway, no egress.
    # ollama                     -> local/private Ollama runtime (development + interchangeable).
    # internal_openai_compatible -> company private AI endpoint (production; disabled by default).
    # openai_responses           -> deprecated public OpenAI compatibility profile (disabled).
    ai_provider: ProviderName = "demo"
    # Model endpoint origin. Ollama dev default reaches the native host runtime through Docker's
    # host-gateway alias. Never hard-code this in business logic.
    ai_base_url: str = "http://host.docker.internal:11434"
    ai_model: str = "qwen3:4b"
    # Exact model allowlist. The provider refuses any model outside it; no silent substitution.
    # Switching qwen3:4b -> qwen3:8b -> foundation-sec:8b-q4 is configuration only, no source
    # change and no model-specific control-plane behaviour.
    ai_allowed_models: str = "qwen3:4b,qwen3:8b,foundation-sec:8b-q4"
    ai_context_length: int = Field(default=8192, ge=512, le=262144)
    ai_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    ai_seed: int = Field(default=42, ge=0)
    # Authentication for the internal endpoint. Local Ollama requires no auth (AI_AUTH_MODE=none).
    ai_auth_mode: AuthMode = "none"
    # Bearer credential for the internal endpoint. It is mounted ONLY into the llm-gateway service
    # (via .env.gateway) and is never given to the control plane, which refuses to start with it.
    ai_auth_token: SecretStr | None = None
    # Production deployments may mount the bearer token as a read-only file instead of exposing it
    # in the container environment. The path itself is not a secret. Exactly one of
    # AI_AUTH_TOKEN / AI_AUTH_TOKEN_FILE may be configured; the gateway reads at most 16 KiB and
    # never includes the path or value in an exception.
    ai_auth_token_file: str | None = None
    # Structured-output mode for internal_openai_compatible backends. Default json_schema keeps the
    # existing OpenAI strict-schema behaviour; json_object is for backends (e.g. DeepSeek) that only
    # support JSON mode — the strict schema is embedded in the prompt and locally re-validated.
    ai_response_format: JsonResponseMode = "json_schema"
    # Some OpenAI-compatible backends (e.g. DeepSeek) do not accept the OpenAI 'seed' field. When
    # False the field is omitted and metadata records seed=None, so no false determinism is claimed.
    ai_supports_seed: bool = True
    # Route the internal_openai_compatible provider through the constrained CONNECT egress proxy
    # (used for public backends like DeepSeek) instead of a direct internal-network connection.
    ai_use_egress_proxy: bool = False
    # DeepSeek hosted-API key (AI_PROVIDER=deepseek). Like ai_auth_token it is mounted ONLY into the
    # llm-gateway service, never the control plane or the beast sandbox, and is redacted everywhere.
    # Never commit it; export DEEPSEEK_API_KEY in the shell that runs compose.
    deepseek_api_key: SecretStr | None = None
    # OpenRouter hosted-API key (AI_PROVIDER=openrouter). Production mounts it as a read-only
    # file into llm-gateway only; inline environment configuration remains available for local
    # development. The control plane refuses either credential source.
    openrouter_api_key: SecretStr | None = None
    openrouter_api_key_file: str | None = None

    # Control plane -> llm-gateway RPC over the internal planner-rpc network (no secret in transit).
    llm_gateway_url: str = "http://llm-gateway:8080"

    # Optional declarative extension pack. The same read-only file is mounted into the control
    # plane and gateway. It may specialize bounded prompts/agent profiles and alias only existing
    # catalogued tools; it cannot load code, commands, URLs, credentials or new permissions.
    extension_manifest_path: str | None = None

    # Honest LOCAL_LLM acceptance status shown on the dashboard. Configuration only; it is a label
    # driven by the recorded acceptance verdict, never by live scan behaviour, and it must NEVER be
    # set to LOCAL_LLM_VALIDATED unless every acceptance threshold passed for the deployed model.
    # While evaluating Contract V2: LOCAL_LLM_CONTRACT_V2_TESTING. On failure: "NO-GO: <class>".
    # Phase 0.8 (deterministic execution queue): both approved models passed the narrow positive,
    # control and stability gates -> LOCAL_LLM_PHASE_0_8_GO. This is a phase-scoped acceptance
    # verdict for the synthetic lab, NOT a production-readiness or vulnerability-coverage claim.
    local_llm_validation_status: str = "LOCAL_LLM_PHASE_0_8_GO"

    # NOTE: Phase 0.5 Part D (bounded schema repair) is CONDITIONAL on Contract V2 still failing the
    # full loop due to JSON / Pydantic-structural / evidence-reference validation failures. The
    # no-repair Contract V2 benchmark produced ZERO such failures (see docs/phase-0.5.md), so that
    # precondition is not met and bounded repair was intentionally not implemented. No repair flag
    # is wired here to avoid implying an unimplemented capability.

    # --- Deprecated public-provider compatibility profile (AI_PROVIDER=openai_responses) --------
    # Public AI egress is NOT the intended deployment model. These fields are used only by the
    # disabled OpenAIResponsesProvider + Squid egress overlay, kept as an optional profile.
    provider_proxy_url: str = "http://egress-proxy:3128"
    provider_ca_bundle: str | None = None

    allowed_target_hosts: str = "lab-api"
    lab_base_url: str = "http://lab-api:8001"
    lab_openapi_url: str = "http://lab-api:8001/openapi.json"
    database_path: str = "/data/aegis.db"
    max_requests_per_scan: int = Field(default=8, ge=1, le=8)
    max_iterations: int = Field(default=6, ge=1, le=8)
    max_model_calls: int = Field(default=6, ge=1, le=8)
    max_candidates_per_generation: int = Field(default=3, ge=1, le=3)
    max_tokens_per_scan: int = Field(default=80000, ge=1, le=200000)
    max_completion_tokens: int = Field(default=2048, ge=128, le=8192)
    # Operator-configurable hard ceilings for a single multi-agent campaign/run. They bound the
    # cumulative model spend across every agent in one run, above and beyond the per-scan and
    # per-agent budgets. A public paid provider (DeepSeek/OpenRouter) makes an over-large or
    # mis-set global budget a real cost risk, so a campaign whose configured global budget exceeds
    # these ceilings fails closed at construction. Generous defaults leave the calibrated per-phase
    # budgets untouched while blocking runaway spend.
    max_tokens_per_campaign: int = Field(default=200_000, ge=1_000, le=1_000_000)
    max_model_calls_per_campaign: int = Field(default=40, ge=1, le=100)
    # Local model inference is slower than a hosted API, so the ceilings are generous. Every scan
    # is still bounded by these hard limits.
    scan_timeout_seconds: float = Field(default=90.0, gt=0, le=600)
    # Process shutdown first stops admission, then waits this long for controller-owned work.
    # Docker/Uvicorn allow additional time for cancellation persistence and lifespan teardown.
    shutdown_grace_seconds: float = Field(default=10.0, gt=0, le=120)
    request_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    model_timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    max_response_bytes: int = Field(default=131072, ge=1024, le=1048576)

    @field_validator("shutdown_grace_seconds", mode="before")
    @classmethod
    def validate_shutdown_grace(cls, value: object) -> object:
        """Reject booleans and non-numeric values instead of accepting Python's bool-as-int."""

        if isinstance(value, bool):
            raise ValueError("shutdown grace must be numeric")
        if isinstance(value, str):
            candidate = value.strip()
            if not candidate or candidate.lower() in {"true", "false"}:
                raise ValueError("shutdown grace must be numeric")
            try:
                return float(candidate)
            except ValueError:
                raise ValueError("shutdown grace must be numeric") from None
        return value

    # --- Phase 1.2 Nuclei integration (operator-enabled; OFF by default) -------------------------
    # Enabling only lets the controller talk to the isolated nuclei-runner over the internal
    # engine-rpc network. The runner must still attest READY (pinned binary, admitted signed
    # templates) before any job executes. No Nuclei/ProjectDiscovery credential exists anywhere.
    nuclei_enabled: bool = False
    nuclei_runner_url: str = "http://nuclei-runner:8090"
    nuclei_rpc_timeout_seconds: float = Field(default=60.0, gt=0, le=180)

    # --- Phase 1.3 ZAP passive OpenAPI integration (operator-enabled; OFF by default) ------------
    # Enabling only lets the controller talk to the isolated zap-runner over the internal
    # zap-rpc network. The runner must still attest READY (pinned ZAP image, jar, JVM and add-on
    # inventory; silent mode; attested scope guard) before any job executes. No ZAP API key,
    # credential or remote OpenAPI source exists anywhere.
    zap_enabled: bool = False
    zap_runner_url: str = "http://zap-runner:8092"
    zap_rpc_timeout_seconds: float = Field(default=150.0, gt=0, le=330)

    # --- Phase 1.5 controlled ZAP active reflected-XSS (SYNTHETIC_LAB only; OFF by default) ------
    # Enabling lets the controller talk to the isolated zap-active-runner. It does NOT authorize a
    # scan: every run additionally needs an operator activation ceremony and a single-use, signed
    # lease that the runner's root-owned admission component verifies for itself.
    zap_active_enabled: bool = False
    zap_active_runner_url: str = "http://zap-active-runner:8093"
    zap_active_rpc_timeout_seconds: float = Field(default=320.0, gt=0, le=660)
    # The HMAC key the controller signs leases with. It exists in exactly two places — here and the
    # root-owned runner admission component — and is never given to ZAP, the scope guard, the
    # Operator Console, an audit record, a report or an evidence artifact. Startup refuses a
    # missing, empty, short or placeholder value whenever ZAP Active is enabled.
    zap_active_lease_secret: SecretStr | None = None
    # Separate control-plane -> active-runner RPC credential. This keeps the runner's endpoints
    # unavailable to the untrusted ZAP child even though the child shares the runner namespace.
    zap_active_runner_client_secret: SecretStr | None = None
    # Separate from the lease key: authenticates a human into a short-lived, server-side session.
    zap_active_operator_bootstrap_secret: SecretStr | None = None

    def require_zap_active_operator_bootstrap_secret(self) -> str:
        value = self.zap_active_operator_bootstrap_secret
        if value is None or len(value.get_secret_value().encode()) < 32:
            raise RuntimeError("ZAP Active operator bootstrap secret unavailable")
        return value.get_secret_value()

    def require_internal_auth_token(self) -> str:
        """Resolve one bearer credential without leaking its value or source path.

        Environment credentials remain supported for existing development/acceptance overlays.
        The production overlay uses ``AI_AUTH_TOKEN_FILE`` so the credential is not present in
        ``docker inspect`` output or the rendered Compose environment.
        """

        inline = self.ai_auth_token
        token_file = self.ai_auth_token_file
        if inline is not None and token_file is not None:
            raise RuntimeError("configure exactly one internal provider credential source")
        if inline is not None:
            value = inline.get_secret_value().strip()
        elif token_file is not None:
            try:
                path = Path(token_file)
                if not path.is_absolute() or not path.is_file() or path.is_symlink():
                    raise OSError
                if path.stat().st_size > 16_384:
                    raise OSError
                value = path.read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError):
                raise RuntimeError("internal provider credential file is unavailable") from None
        else:
            raise RuntimeError("internal provider bearer credential is unavailable")
        if not value or "\x00" in value or len(value.encode("utf-8")) > 16_384:
            raise RuntimeError("internal provider bearer credential is invalid")
        return value

    def require_openrouter_api_key(self) -> str:
        """Resolve one OpenRouter credential without leaking its value or source path."""

        inline = self.openrouter_api_key
        key_file = self.openrouter_api_key_file
        if inline is not None and key_file is not None:
            raise RuntimeError("configure exactly one OpenRouter credential source")
        if inline is not None:
            value = inline.get_secret_value().strip()
        elif key_file is not None:
            try:
                path = Path(key_file)
                if not path.is_absolute() or not path.is_file() or path.is_symlink():
                    raise OSError
                if path.stat().st_size > 16_384:
                    raise OSError
                value = path.read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError):
                raise RuntimeError("OpenRouter credential file is unavailable") from None
        else:
            raise RuntimeError("OpenRouter bearer credential is unavailable")
        if not value or "\x00" in value or len(value.encode("utf-8")) > 16_384:
            raise RuntimeError("OpenRouter bearer credential is invalid")
        return value

    def require_zap_active_runner_client_secret(self) -> str:
        value = self.zap_active_runner_client_secret
        if value is None or len(value.get_secret_value().encode()) < 32:
            raise RuntimeError("ZAP Active runner client credential unavailable")
        return value.get_secret_value()

    # --- Phase 1.4 disposable AI adversary sandbox (OFF by default) -----------------------------
    # The controller sends command text as opaque JSON to the supervisor. This shared RPC token is
    # mounted only in those two controller components and is stripped from every shell environment.
    beast_enabled: bool = False
    beast_supervisor_url: str = "http://beast-rpc-relay:8094"
    beast_supervisor_token: SecretStr | None = None
    beast_lease_seconds: int = Field(default=600, ge=30, le=900)
    beast_required_model: str = "qwen3:8b"

    def require_zap_active_lease_secret(self) -> str:
        """Return the signing secret, or refuse to operate. Never logged and never returned to an
        API caller; the raised message deliberately names the variable, never a value."""

        from aegis_zap_active.lease import LeaseRejected, normalize_secret

        raw = self.zap_active_lease_secret
        try:
            return normalize_secret(raw.get_secret_value() if raw is not None else None).decode()
        except LeaseRejected:
            raise RuntimeError(
                "ZAP_ACTIVE_ENABLED requires a real ZAP_ACTIVE_LEASE_SECRET "
                "(>=32 bytes, not a placeholder); ZAP Active refuses to start without one"
            ) from None

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return frozenset(host.strip().lower() for host in self.allowed_target_hosts.split(","))

    @property
    def allowed_model_set(self) -> frozenset[str]:
        return frozenset(m.strip() for m in self.ai_allowed_models.split(",") if m.strip())

    @property
    def mode_label(self) -> str:
        return PROVIDER_MODE_LABELS.get(self.ai_provider, "DEMO_HEURISTIC")

    @property
    def credentials(self) -> dict[str, str]:
        # Synthetic credentials are resolved only inside the executor. They are never sent
        # to the planner, persisted, or rendered in evidence.
        return {
            "user_a": "lab-token-user-a",
            "user_b": "lab-token-user-b",
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
