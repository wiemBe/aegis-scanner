from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
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
}

ProviderName = Literal["demo", "ollama", "internal_openai_compatible", "openai_responses"]
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

    # Control plane -> llm-gateway RPC over the internal planner-rpc network (no secret in transit).
    llm_gateway_url: str = "http://llm-gateway:8080"

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
    # Local model inference is slower than a hosted API, so the ceilings are generous. Every scan
    # is still bounded by these hard limits.
    scan_timeout_seconds: float = Field(default=90.0, gt=0, le=600)
    request_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    model_timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    max_response_bytes: int = Field(default=131072, ge=1024, le=1048576)

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

    # --- Phase 1.4 disposable AI adversary sandbox (OFF by default) -----------------------------
    # The controller sends command text as opaque JSON to the supervisor. This shared RPC token is
    # mounted only in those two controller components and is stripped from every shell environment.
    beast_enabled: bool = False
    beast_supervisor_url: str = "http://beast-rpc-relay:8094"
    beast_supervisor_token: SecretStr | None = None
    beast_lease_seconds: int = Field(default=600, ge=30, le=900)
    beast_required_model: str = "qwen3:8b"

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
