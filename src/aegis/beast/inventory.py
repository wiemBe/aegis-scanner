from aegis.beast.contracts import BeastTarget, EnvironmentClass

_COMMON = {
    "name": "Disposable Synthetic Bank Adversary Target",
    "origin": "http://beast-target:8080",
    "environment": EnvironmentClass.SYNTHETIC_LAB,
    "owner": "Aegis Lab Engineering",
    "approval_reference": "PHASE-1.4-SYNTHETIC-LAB",
    "active_testing_authorized": True,
    "reset_available": True,
    "synthetic_data_only": True,
    # Phase 1.4 has no modeled synthetic mutation, so the immutable target contract is read-only.
    # The shell and raw HTTP syntax remain unrestricted; the target boundary owns method scope.
    "allowed_methods": ["GET", "HEAD", "OPTIONS"],
    "prohibited_operations": [
        "real payment or transfer",
        "external notification",
        "customer data access",
        "persistent deletion",
        "denial of service",
        "OAST or callback traffic",
    ],
    "reset_strategy": "Destroy run workspace and restore immutable in-memory synthetic fixture",
    "synthetic_credential_profiles": ["anonymous", "public_user_a", "public_user_b"],
    "expected_impact": "Bounded requests to an intentionally vulnerable disposable API fixture",
    "max_blast_radius": "One internal synthetic target service and run-local files only",
    "health": "GREEN",
}

BEAST_TARGETS: dict[str, BeastTarget] = {
    "beast-synthetic-vulnerable": BeastTarget.model_validate(
        {
            **_COMMON,
            "target_ref": "beast-synthetic-vulnerable",
            "base_path": "/lab/beast/vulnerable",
            "allowed_path_prefix": "/lab/beast/vulnerable",
        }
    ),
    "beast-synthetic-patched": BeastTarget.model_validate(
        {
            **_COMMON,
            "target_ref": "beast-synthetic-patched",
            "base_path": "/lab/beast/patched",
            "allowed_path_prefix": "/lab/beast/patched",
        }
    ),
    # Controller-owned negative-control records. They are deliberately never returned as launchable
    # targets, but let acceptance prove classification/reset rejection before any network action.
    "beast-control-production": BeastTarget.model_validate(
        {
            **_COMMON,
            "target_ref": "beast-control-production",
            "base_path": "/lab/beast/vulnerable",
            "allowed_path_prefix": "/lab/beast/vulnerable",
            "environment": EnvironmentClass.PRODUCTION,
            "active_testing_authorized": False,
            "synthetic_data_only": False,
        }
    ),
    "beast-control-no-reset": BeastTarget.model_validate(
        {
            **_COMMON,
            "target_ref": "beast-control-no-reset",
            "base_path": "/lab/beast/vulnerable",
            "allowed_path_prefix": "/lab/beast/vulnerable",
            "reset_available": False,
        }
    ),
}

LAUNCHABLE_BEAST_TARGETS = (
    "beast-synthetic-vulnerable",
    "beast-synthetic-patched",
)


def target(target_ref: str) -> BeastTarget:
    try:
        return BEAST_TARGETS[target_ref]
    except KeyError as exc:
        raise ValueError("TARGET_NOT_IN_CONTROLLER_INVENTORY") from exc
