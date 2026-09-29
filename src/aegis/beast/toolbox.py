"""Controller-owned inventory of tools installed in the BEAST_ADVERSARY_SANDBOX_V1 image.

This is the single Python-side source of truth for *which* tools the disposable sandbox ships and
what they are for. It is surfaced to the model as advisory environment context only
(`BeastDecisionRequest.available_tools`); it is never a command allow-list, a suggested command, or
an authority. The model still authors the exact `command_text` itself and may use any installed
tool or shell syntax. What actually bounds the adversary is the immutable target boundary
(GET/HEAD/OPTIONS to one synthetic origin, under byte/rate/connection budgets) — not this note.

Phase 1.4-B added `akca`, `katana`, `httpx` and `gobuster` (see
`docs/phase-1.4-b-beast-toolbox.md`). Every
externally fetched binary here is pinned by version + SHA-256 in
`deploy/beast-sandbox/tools.lock.json` and installed by the pinned, checksum-verified stages of
`deploy/beast-sandbox/Dockerfile`. `tests/test_beast_toolbox.py` keeps the three in sync.

Deliberately omitted from this advisory list: raw-socket / exploitation tooling. `nmap` is present
in the base image but its scan modes are inert here — the sandbox drops all Linux capabilities (no
NET_RAW) and the only route out is the HTTP gateway, which forwards GET/HEAD/OPTIONS to a single
synthetic host. Listing such tools as "available" would misdescribe what the boundary permits.
"""

from __future__ import annotations

from aegis.beast.contracts import BeastToolDescriptor

# The gateway constraint that every entry below is subject to. Rendered once into the model brief so
# the advisory list cannot be read as "these tools may do anything".
SANDBOX_TOOLBOX_BOUNDARY_NOTE = (
    "All tools reach the target only through the sandbox gateway, which forwards GET/HEAD/OPTIONS "
    "to one synthetic origin under strict byte, rate and connection budgets. Raw-socket, brute, "
    "exploit, callback/OAST and state-changing behaviour cannot leave the sandbox."
)

# HTTP-capable tools that can actually do useful work through the GET/HEAD/OPTIONS gateway. Ordered
# from general to specific. `source` records provenance for audit/attestation.
SANDBOX_TOOLBOX: tuple[BeastToolDescriptor, ...] = (
    BeastToolDescriptor(
        name="curl",
        category="http-client",
        purpose="Issue individual bounded HTTP requests and inspect status, headers and body.",
        source="debian",
    ),
    BeastToolDescriptor(
        name="httpie",
        category="http-client",
        purpose="Human-readable HTTP client for quick request/response inspection.",
        source="debian",
    ),
    BeastToolDescriptor(
        name="httpx",
        category="http-prober",
        purpose="Probe observed paths for status, title, tech and content length.",
        source="github:projectdiscovery/httpx@v1.12.0",
    ),
    BeastToolDescriptor(
        name="katana",
        category="web-crawler",
        purpose="Crawl the authorized surface and enumerate in-scope links from responses.",
        source="github:projectdiscovery/katana@v1.7.0",
    ),
    BeastToolDescriptor(
        name="akca",
        category="dast-scanner",
        purpose=(
            "Contextual DAST crawler/scanner: HTTP + JS-aware crawling and adaptive passive/active "
            "checks over the authorized surface."
        ),
        source="github:akha-security/akca@v0.2.4",
    ),
    BeastToolDescriptor(
        name="ffuf",
        category="content-discovery",
        purpose="Fuzz for additional paths below the authorized base path via GET requests.",
        source="debian",
    ),
    BeastToolDescriptor(
        name="gobuster",
        category="content-discovery",
        purpose=(
            "Enumerate paths below the authorized base path with a controller-bounded wordlist."
        ),
        source="debian",
    ),
    BeastToolDescriptor(
        name="nuclei",
        category="template-scanner",
        purpose="Run request-based detection templates against the authorized surface.",
        source="github:projectdiscovery/nuclei@v3.11.1",
    ),
    BeastToolDescriptor(
        name="sqlmap",
        category="injection-probe",
        purpose="Non-destructive injection probing of an observed query parameter.",
        source="debian",
    ),
)


def sandbox_toolbox() -> list[BeastToolDescriptor]:
    """Return a fresh copy of the advisory sandbox toolbox for a decision request."""

    return [tool.model_copy() for tool in SANDBOX_TOOLBOX]
