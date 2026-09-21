# HISTORICAL DRAFT — ZAP active scanning prerequisites (superseded)

> **Historical prerequisite draft. Not the current phase plan.** This note was written during
> Phase 1.3 and speculatively labelled "Phase 1.4"; that number was later assigned to **Beast Mode**
> ([Phase 1.4](phase-1.4-beast-mode.md)). Controlled ZAP active scanning is **Phase 1.5**
> ([Phase 1.5](phase-1.5-zap-active-reflected-xss.md)), and it targets the **synthetic lab only** —
> not the "staging" environment this draft assumed. Several assumptions here are now stale (for
> example, the pinned base image *does* contain a release reflected-XSS active rule; it was pruned
> from the passive runner image, and the admitted rule's add-on transitively requires the `oast` and
> `database` add-ons, which Phase 1.5 includes only as neutralised forced dependencies). This file is
> retained unchanged below for provenance; follow Phase 1.5 for the actual, implemented plan.

Phase 1.3 ships **passive** ZAP analysis of controller-projected read-only operations against the
synthetic lab only. Active scanning is structurally impossible in 1.3: no active-rule add-on is in
the image, `activeScan*` jobs are refused by the plan validator, the only enabled ZAP capability is
`PASSIVE`, and `zap_active_scan_v0` is catalogued solely to be refused
(`ACTIVE_SCAN_FORBIDDEN`). None of the items below is implemented. Do not start Phase 1.4 until all
of them exist and are reviewed.

## Authorization and scope

1. A written, owner-signed authorization for a named **staging** environment (never production),
   with an explicit target inventory, time window, rate limits and a named human approver.
2. A staging-specific target inventory with its own origin allowlist in both the controller and the
   scope guard, plus a kill switch that disarms the guard and stops the runner immediately.
3. A data-classification review of the staging environment: synthetic or approved test data only,
   and a documented plan for any response content that could contain real data.

## Engine and supply chain

4. A new manifest version adding only reviewed active-rule add-ons (e.g. `ascanrules`) at pinned
   versions and digests, with an explicit, minimal per-rule allowlist and strength/threshold
   settings justified individually. Beta/alpha active rules stay excluded unless reviewed.
5. A separate, versioned profile (e.g. `ZAP_STAGING_ACTIVE_V1`); the Phase 1.3 passive profile must
   remain unchanged and independently selectable.
6. Explicit handling of state-changing behaviour: active rules send attack payloads. Either restrict
   to read-only methods with an evidence-based review of every admitted rule, or provide an
   isolated, resettable staging dataset and a documented rollback.

## Boundary and budgets

7. Guard support for the larger but still hard request budget of an active scan, per-rule request
   accounting, rate limiting and payload-size limits, with the same fail-closed polling and kill.
8. Timeouts, response-size and report-size bounds re-derived for active scanning, with fail-closed
   tests for each.

## Verification and human review

9. A deterministic Aegis verifier (or a documented human-review path that can only reach
   `REVIEW_REQUIRED`) for every admitted active rule; no active-scan alert may become `VERIFIED`
   without one.
10. A report parser extension that still refuses request/response bodies and attack prose, and a
    decision on whether the `attack` field may be recorded (currently any value fails closed).

## Evidence

11. A fresh, immutable acceptance matrix in the staging environment: positive/negative pairs per
    admitted rule, projection and scope negative controls, budget and kill-switch controls, and
    Nuclei, AEGIS_NATIVE and passive-ZAP regressions. Prior artifacts must stay byte-identical.
12. Updated threat model, isolation and privacy documentation, and an operator countersignature on
    the rule manifest (Phase 1.3's review is AI-assisted and not countersigned).

Enabling an active capability by flipping a catalog flag, adding a job to the plan or installing an
add-on at runtime is a scope and safety regression, not a configuration change.
