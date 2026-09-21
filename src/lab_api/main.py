import asyncio
import html
from collections.abc import Iterator
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Response
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    StreamingResponse,
)

app = FastAPI(
    title="Synthetic Banking API",
    description="INTENTIONALLY VULNERABLE. Lab use only.",
    version="0.1.0",
)

USERS = {
    "lab-token-user-a": {"id": "user-a", "name": "Ada"},
    "lab-token-user-b": {"id": "user-b", "name": "Bora"},
}

ACCOUNTS: dict[str, dict[str, str | float]] = {
    "A-100": {"account_id": "A-100", "owner_id": "user-a", "balance": 1250.25},
    "B-200": {"account_id": "B-200", "owner_id": "user-b", "balance": 9875.50},
}


def current_user(authorization: str) -> dict[str, str]:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or token not in USERS:
        raise HTTPException(status_code=401, detail="Invalid synthetic token")
    return USERS[token]


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/me")
def me(authorization: Annotated[str, Header()]) -> dict[str, str]:
    return current_user(authorization)


@app.get("/api/v1/accounts/{account_id}")
def get_account(
    account_id: str,
    authorization: Annotated[str, Header()],
) -> dict[str, str | float]:
    current_user(authorization)
    account = ACCOUNTS.get(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")

    # Deliberate BOLA/IDOR: authentication is checked, object ownership is not.
    return {
        "account_id": str(account["account_id"]),
        "owner_id": str(account["owner_id"]),
        "balance": float(account["balance"]),
    }


@app.post("/api/v1/transfers")
def create_transfer(authorization: Annotated[str, Header()]) -> dict[str, str]:
    current_user(authorization)
    return {"status": "disabled_in_lab", "message": "State-changing operation is not executed"}


@app.get("/api/v1/patched/accounts/{account_id}")
def get_patched_account(
    account_id: str,
    authorization: Annotated[str, Header()],
) -> dict[str, str | float]:
    user = current_user(authorization)
    account = ACCOUNTS.get(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")
    if account["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return dict(account)


# --- Phase 1.2 synthetic Nuclei scenario: source-control metadata exposure ------------------------
# Two explicitly synthetic, read-only route families. They are excluded from the OpenAPI document so
# the planner's imported surface (and every AEGIS_NATIVE projection) stays byte-identical, and they
# share no state or switch with the BOLA routes above. The fixture holds no remote, URL or
# credential: it is a minimal, fake repository config that exists only to be detected.
SYNTHETIC_GIT_CONFIG = (
    "# SYNTHETIC AEGIS LAB FIXTURE - not a real repository\n"
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "\tfilemode = true\n"
    "\tbare = false\n"
)
_SCM_LAB = "scm-metadata-exposure"


@app.get("/lab/nuclei/vulnerable", include_in_schema=False)
def scm_lab_vulnerable() -> dict[str, str | bool]:
    return {"lab": _SCM_LAB, "variant": "vulnerable", "synthetic": True}


@app.get("/lab/nuclei/vulnerable/.git/config", include_in_schema=False)
def scm_lab_vulnerable_git_config() -> PlainTextResponse:
    # Deliberate misconfiguration: repository metadata is served from the web root.
    return PlainTextResponse(SYNTHETIC_GIT_CONFIG)


@app.get("/lab/nuclei/patched", include_in_schema=False)
def scm_lab_patched() -> dict[str, str | bool]:
    return {"lab": _SCM_LAB, "variant": "patched", "synthetic": True}


@app.get("/lab/nuclei/patched/.git/config", include_in_schema=False)
def scm_lab_patched_git_config() -> JSONResponse:
    # Remediated: the metadata path is explicitly denied with a deterministic body.
    return JSONResponse(status_code=404, content={"detail": "Repository metadata is not served"})


# --- Phase 1.3 synthetic ZAP scenario: missing anti-MIME-sniffing header -------------------------
# Explicitly synthetic, read-only route families, excluded from the OpenAPI document (so the
# planner's imported surface and every AEGIS_NATIVE / Nuclei projection stay byte-identical). They
# carry no credential, no business data and share no state with any other route. Every route sets
# ``X-Content-Type-Options: nosniff`` EXCEPT the vulnerable catalog route; the patched catalog route
# differs from it only by setting that header.
ZAP_LAB = "zap-passive-header"
ZAP_CATALOG_ID = "synthetic-catalog-1"
_NOSNIFF = {"X-Content-Type-Options": "nosniff"}


def _zap_marker(variant: str, route: str, **extra: str) -> dict[str, str | bool]:
    return {"lab": ZAP_LAB, "variant": variant, "route": route, "synthetic": True, **extra}


def _zap_not_found() -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": "Not found"}, headers=_NOSNIFF)


@app.get("/lab/zap/vulnerable/status", include_in_schema=False)
def zap_vulnerable_status() -> JSONResponse:
    return JSONResponse(_zap_marker("vulnerable", "status"), headers=_NOSNIFF)


@app.get("/lab/zap/vulnerable/catalog/{catalog_id}", include_in_schema=False)
def zap_vulnerable_catalog(catalog_id: str) -> JSONResponse:
    if catalog_id != ZAP_CATALOG_ID:
        return _zap_not_found()
    # Deliberate misconfiguration: this one route omits the anti-MIME-sniffing header.
    return JSONResponse(_zap_marker("vulnerable", "catalog", catalog_id=catalog_id))


@app.get("/lab/zap/patched/status", include_in_schema=False)
def zap_patched_status() -> JSONResponse:
    return JSONResponse(_zap_marker("patched", "status"), headers=_NOSNIFF)


@app.get("/lab/zap/patched/catalog/{catalog_id}", include_in_schema=False)
def zap_patched_catalog(catalog_id: str) -> JSONResponse:
    if catalog_id != ZAP_CATALOG_ID:
        return _zap_not_found()
    # Remediated: the same response, with the header set on this route.
    return JSONResponse(_zap_marker("patched", "catalog", catalog_id=catalog_id), headers=_NOSNIFF)


# Negative-control fixtures. They exist only to prove that the ZAP scope guard and runner fail
# closed; no acceptance scenario can pass through them.
@app.get("/lab/zap/redirect/status", include_in_schema=False)
def zap_negative_redirect() -> RedirectResponse:
    return RedirectResponse("/lab/zap/redirect/elsewhere", status_code=302, headers=_NOSNIFF)


@app.get("/lab/zap/unstable/status", include_in_schema=False)
def zap_negative_unstable() -> StreamingResponse:
    def broken() -> Iterator[bytes]:
        yield b'{"lab": "zap-passive-header", '
        raise RuntimeError("synthetic connection drop")

    return StreamingResponse(broken(), media_type="application/json", headers=_NOSNIFF)


@app.get("/lab/zap/slow/status", include_in_schema=False)
async def zap_negative_slow() -> JSONResponse:
    await asyncio.sleep(12)
    return JSONResponse(_zap_marker("negative", "slow"), headers=_NOSNIFF)


# --- Phase 1.4 disposable adversary target -----------------------------------------------------
# These routes are synthetic, side-effect free and isolated under a dedicated prefix. The public
# landing page exposes only a documentation link; it does not name a vulnerability or sequence.
BEAST_GIT_CONFIG = (
    "# SYNTHETIC AEGIS LAB FIXTURE - no remote, credential, or source tree\n"
    "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
)


def _beast_variant(variant: str) -> str:
    if variant not in {"vulnerable", "patched"}:
        raise HTTPException(status_code=404, detail="Unknown disposable target")
    return variant


@app.get("/lab/beast/{variant}", include_in_schema=False)
def beast_landing(variant: str) -> dict[str, str | bool]:
    _beast_variant(variant)
    return {
        "service": "Disposable Synthetic Bank API",
        "synthetic": True,
        "documentation": f"/lab/beast/{variant}/openapi.json",
    }


@app.get("/lab/beast/{variant}/openapi.json", include_in_schema=False)
def beast_openapi(variant: str) -> JSONResponse:
    _beast_variant(variant)
    prefix = f"/lab/beast/{variant}"
    document = {
        "openapi": "3.1.0",
        "info": {"title": "Disposable Synthetic Bank", "version": "1.0"},
        "paths": {
            f"{prefix}/me": {"get": {"summary": "Current synthetic public account"}},
            f"{prefix}/accounts": {"get": {"summary": "Synthetic account directory"}},
            f"{prefix}/accounts/{{account_id}}": {"get": {"summary": "Read one synthetic account"}},
            f"{prefix}/search": {
                "get": {
                    "summary": "Search the synthetic catalog",
                    "parameters": [{"name": "q", "in": "query", "required": True}],
                }
            },
        },
    }
    return JSONResponse(document, headers=_NOSNIFF)


@app.get("/lab/beast/{variant}/me", include_in_schema=False)
def beast_me(variant: str, authorization: Annotated[str, Header()]) -> dict[str, str]:
    _beast_variant(variant)
    user = current_user(authorization)
    account_id = "A-100" if user["id"] == "user-a" else "B-200"
    return {**user, "account_id": account_id}


@app.get("/lab/beast/{variant}/accounts", include_in_schema=False)
def beast_accounts(variant: str, authorization: Annotated[str, Header()]) -> dict[str, object]:
    _beast_variant(variant)
    current_user(authorization)
    return {"account_ids": sorted(ACCOUNTS), "synthetic": True}


@app.get("/lab/beast/{variant}/accounts/{account_id}", include_in_schema=False)
def beast_account(
    variant: str,
    account_id: str,
    authorization: Annotated[str, Header()],
) -> JSONResponse:
    selected = _beast_variant(variant)
    user = current_user(authorization)
    account = ACCOUNTS.get(account_id)
    if account is None:
        return JSONResponse(status_code=404, content={"detail": "Account not found"})
    if selected == "patched" and account["owner_id"] != user["id"]:
        return JSONResponse(status_code=403, content={"detail": "Forbidden"})
    return JSONResponse(dict(account), headers=_NOSNIFF)


@app.get("/lab/beast/{variant}/search", include_in_schema=False)
def beast_search(variant: str, q: str = "") -> JSONResponse:
    selected = _beast_variant(variant)
    injection_like = any(token in q.lower() for token in ("' or ", '" or ', "union select"))
    result: dict[str, object] = {"query_length": len(q), "matches": [], "synthetic": True}
    if selected == "vulnerable" and injection_like:
        # Deterministic marker for an intentionally vulnerable, non-database synthetic fixture.
        result["diagnostic"] = "SYNTHETIC_SQL_INJECTION_CONFIRMED"
        result["matches"] = ["synthetic-record-a", "synthetic-record-b"]
    return JSONResponse(result, headers=_NOSNIFF)


@app.get("/lab/beast/{variant}/.git/config", include_in_schema=False)
def beast_git_config(variant: str) -> Response:
    if _beast_variant(variant) == "patched":
        return JSONResponse(status_code=404, content={"detail": "Not found"}, headers=_NOSNIFF)
    return PlainTextResponse(BEAST_GIT_CONFIG, headers=_NOSNIFF)


# --- Phase 1.5 synthetic ZAP active scenario: reflected cross-site scripting ---------------------
# One isolated, read-only, side-effect-free family under a dedicated prefix, excluded from the
# OpenAPI document (so every other imported/projected surface stays byte-identical). It holds no
# credential, no database, no filesystem access and no mutable state: the two variants differ ONLY
# in output encoding. The vulnerable route reflects the single bounded ``q`` query parameter into an
# executable HTML element context WITHOUT encoding; the patched route reflects the identical value
# with correct contextual HTML-entity encoding. Because there is no state, reset is a deterministic
# no-op. The single controlled ZAP reflected-XSS rule (40012) and the independent Aegis verifier
# both act on this one parameter alone.
ZAP_ACTIVE_LAB = "zap-active-reflected-xss"
ZAP_ACTIVE_Q_MAX = 256


def _zap_active_variant(variant: str) -> str:
    if variant not in {"vulnerable", "patched"}:
        raise HTTPException(status_code=404, detail="Unknown synthetic target")
    return variant


def _zap_active_page(variant: str, reflected: str) -> str:
    # Identical skeleton for both variants; only ``reflected`` differs (raw vs. encoded). The
    # synthetic marker lets the independent verifier confirm exact routing and variant.
    marker = f'data-lab="{ZAP_ACTIVE_LAB}" data-variant="{variant}" data-synthetic="true"'
    return (
        "<!doctype html><html><head><title>Synthetic catalog search</title></head>"
        f"<body><p {marker}>Synthetic catalog search.</p>"
        f'<div id="query-echo">You searched for: {reflected}</div>'
        "</body></html>"
    )


@app.get("/lab/zap-active/{variant}", include_in_schema=False)
def zap_active_landing(variant: str) -> dict[str, str | bool]:
    selected = _zap_active_variant(variant)
    return {
        "lab": ZAP_ACTIVE_LAB,
        "variant": selected,
        "synthetic": True,
        "search": f"/lab/zap-active/{selected}/search",
    }


@app.get("/lab/zap-active/{variant}/search", include_in_schema=False)
def zap_active_search(variant: str, q: str = "") -> HTMLResponse:
    selected = _zap_active_variant(variant)
    # Bounded, deterministic: the reflected value is clipped identically for both variants, so the
    # only behavioural difference is contextual output encoding.
    clipped = q[:ZAP_ACTIVE_Q_MAX]
    reflected = clipped if selected == "vulnerable" else html.escape(clipped, quote=True)
    return HTMLResponse(
        _zap_active_page(selected, reflected),
        headers={"Content-Type": "text/html; charset=utf-8", **_NOSNIFF},
    )


@app.get("/lab/zap-active/{variant}/reset", include_in_schema=False)
def zap_active_reset(variant: str) -> JSONResponse:
    selected = _zap_active_variant(variant)
    # The scenario is stateless, so reset is a deterministic confirmation, never a mutation.
    return JSONResponse(
        {
            "lab": ZAP_ACTIVE_LAB,
            "variant": selected,
            "reset": True,
            "stateful": False,
            "synthetic": True,
        },
        headers=_NOSNIFF,
    )
