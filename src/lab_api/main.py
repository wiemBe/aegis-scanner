from typing import Annotated

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse

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
