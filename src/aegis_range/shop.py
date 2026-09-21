"""Aegis Shop: deterministic catalog search and promotion preview service."""

from __future__ import annotations

import hashlib
import html
import sqlite3
from typing import Annotated

from fastapi import Cookie, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from aegis_range.documents import openapi_document
from aegis_range.runtime import Mode, ScenarioRuntime, management_router

SERVICE = "aegis-shop"
SQL_SCENARIO = "shop-catalog-query-v1"
XSS_SCENARIO = "shop-promotion-preview-v1"
STORED_SCENARIO = "shop-review-content-v1"
CSRF_SCENARIO = "shop-preference-request-v1"
UPLOAD_SCENARIO = "shop-attachment-policy-v1"
SHOP_SESSION = "synthetic-shop-session"  # noqa: S105 - inert range-only session marker
runtime = ScenarioRuntime(
    SERVICE, (SQL_SCENARIO, XSS_SCENARIO, STORED_SCENARIO, CSRF_SCENARIO, UPLOAD_SCENARIO)
)
app = FastAPI(title="Aegis Shop", version="1.0.0", openapi_url=None, docs_url=None, redoc_url=None)

PRODUCTS = (
    ("PRD-100", "Travel Notebook", "Stationery", 18.50),
    ("PRD-200", "Desk Lamp", "Office", 74.90),
    ("PRD-300", "Canvas Tote", "Accessories", 29.00),
)
REVIEWS: list[dict[str, str]] = []
PREFERENCES: dict[str, str] = {}
UPLOADS: dict[str, tuple[bytes, str, str]] = {}
CSRF_TOKEN = ""


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_id: str = Field(max_length=20)
    content: str = Field(max_length=1000)


class PreferenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    newsletter: bool


def _reset_state(generation: int) -> None:
    global CSRF_TOKEN
    REVIEWS.clear()
    PREFERENCES.clear()
    UPLOADS.clear()
    CSRF_TOKEN = hashlib.sha256(f"shop-csrf-{generation}:{SHOP_SESSION}".encode()).hexdigest()[:24]


runtime.add_reset_hook(_reset_state)


def _database() -> sqlite3.Connection:
    database = sqlite3.connect(":memory:")
    database.execute(
        "CREATE TABLE products (product_id TEXT, name TEXT, category TEXT, price REAL)"
    )
    database.executemany("INSERT INTO products VALUES (?, ?, ?, ?)", PRODUCTS)
    return database


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE, "seed": "2026.1"}


@app.get("/openapi.json", include_in_schema=False)
def openapi() -> dict[str, object]:
    return openapi_document(SERVICE)


@app.get("/api/products", operation_id="searchProducts")
def products(q: str = Query(default="", max_length=120)) -> dict[str, object]:
    with _database() as database:
        if runtime.mode(SQL_SCENARIO) is Mode.VULNERABLE:
            statement = (
                f"SELECT product_id, name, category, price FROM products WHERE name LIKE '%{q}%'"  # noqa: S608
            )
            try:
                rows = database.execute(statement).fetchall()
            except sqlite3.Error:
                rows = []
        else:
            rows = database.execute(
                "SELECT product_id, name, category, price FROM products WHERE name LIKE ?",
                (f"%{q}%",),
            ).fetchall()
    return {
        "products": [
            {"product_id": row[0], "name": row[1], "category": row[2], "price": row[3]}
            for row in rows
        ]
    }


@app.get("/api/categories", operation_id="listCategories")
def categories() -> dict[str, object]:
    return {"categories": sorted({row[2] for row in PRODUCTS})}


@app.get("/api/promotions/preview", response_class=HTMLResponse, operation_id="previewPromotion")
def promotion_preview(message: str = Query(max_length=240)) -> HTMLResponse:
    rendered = message if runtime.mode(XSS_SCENARIO) is Mode.VULNERABLE else html.escape(message)
    page = (
        "<!doctype html><html><head><title>Promotion Preview</title></head>"
        f'<body><main><h1>Promotion Preview</h1><p class="message">{rendered}</p>'
        "</main></body></html>"
    )
    return HTMLResponse(page, headers={"Content-Security-Policy": "default-src 'self'"})


@app.post("/api/reviews", operation_id="createProductReview")
def create_review(payload: ReviewRequest) -> dict[str, str]:
    review_id = f"REV-{len(REVIEWS) + 1:04d}"
    REVIEWS.append({"review_id": review_id, **payload.model_dump()})
    return {"review_id": review_id, "status": "received"}


def _review_page() -> HTMLResponse:
    rows = []
    for review in REVIEWS:
        content = review["content"]
        if runtime.mode(STORED_SCENARIO) is Mode.PATCHED:
            content = html.escape(content)
        rows.append(f'<article data-id="{review["review_id"]}"><p>{content}</p></article>')
    policy = (
        "default-src 'self'; script-src 'self'"
        if runtime.mode(STORED_SCENARIO) is Mode.PATCHED
        else "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src *; connect-src *"
    )
    return HTMLResponse(
        "<!doctype html><html><body><main>" + "".join(rows) + "</main></body></html>",
        headers={"Content-Security-Policy": policy},
    )


@app.get("/api/reviews", response_class=HTMLResponse, operation_id="listProductReviews")
def list_reviews() -> HTMLResponse:
    return _review_page()


@app.get("/internal/reviews/view", include_in_schema=False)
def privileged_review_view() -> HTMLResponse:
    return _review_page()


@app.get("/api/profile/form", operation_id="getPreferenceForm")
def preference_form() -> Response:
    response = Response(
        content=json_bytes(
            {"csrf_token": CSRF_TOKEN, "newsletter": PREFERENCES.get("newsletter", "false")}
        ),
        media_type="application/json",
    )
    vulnerable = runtime.mode(CSRF_SCENARIO) is Mode.VULNERABLE
    response.set_cookie(
        "shop_session",
        SHOP_SESSION,
        httponly=True,
        secure=vulnerable,
        samesite="none" if vulnerable else "strict",
    )
    return response


def json_bytes(value: object) -> bytes:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@app.post("/api/profile/preferences", operation_id="updatePreferences")
def update_preferences(
    payload: PreferenceRequest,
    shop_session: Annotated[str | None, Cookie()] = None,
    x_csrf_token: Annotated[str | None, Header()] = None,
    origin: Annotated[str | None, Header()] = None,
) -> dict[str, str]:
    if shop_session != SHOP_SESSION:
        raise HTTPException(status_code=401, detail="Session unavailable")
    if runtime.mode(CSRF_SCENARIO) is Mode.PATCHED and (
        x_csrf_token != CSRF_TOKEN or origin != "http://aegis-shop:8102"
    ):
        raise HTTPException(status_code=403, detail="Request could not be completed")
    PREFERENCES["newsletter"] = str(payload.newsletter).lower()
    return {"status": "saved"}


@app.post("/api/attachments", operation_id="createSupportAttachment")
async def create_attachment(
    request: Request,
    x_filename: Annotated[str, Header(max_length=120)],
    content_type: Annotated[str | None, Header()] = None,
) -> dict[str, str]:
    body = await request.body()
    media_type = content_type or "application/octet-stream"
    suffix = "." + x_filename.rsplit(".", 1)[-1].lower() if "." in x_filename else ""
    safe = (
        len(body) <= 65_536
        and media_type in {"text/plain", "image/png"}
        and suffix in {".txt", ".png"}
        and b"<script" not in body.lower()
    )
    if runtime.mode(UPLOAD_SCENARIO) is Mode.PATCHED and not safe:
        raise HTTPException(status_code=400, detail="Attachment could not be accepted")
    storage_name = (
        hashlib.sha256(body + str(runtime.generation).encode()).hexdigest()[:24] + suffix
        if runtime.mode(UPLOAD_SCENARIO) is Mode.PATCHED
        else x_filename
    )
    disposition = "attachment" if runtime.mode(UPLOAD_SCENARIO) is Mode.PATCHED else "inline"
    UPLOADS[storage_name] = (body[:65_536], media_type, disposition)
    return {"attachment_id": storage_name, "status": "received"}


@app.get("/api/attachments/{attachment_id}", operation_id="getSupportAttachment")
def get_attachment(attachment_id: str) -> Response:
    item = UPLOADS.get(attachment_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    body, media_type, disposition = item
    return Response(
        body,
        media_type=media_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="download"',
            "X-Content-Type-Options": "nosniff",
        },
    )


app.include_router(management_router(runtime))
