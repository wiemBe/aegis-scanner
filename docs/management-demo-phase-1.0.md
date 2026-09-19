# Phase 1.0 management demo guide

Open <http://127.0.0.1:8000/console/> and choose **Presentation mode**.

Use this description exactly:

> The local AI model analyzes a projected API surface and independently proposes an
> object-authorization attack hypothesis. A deterministic policy layer validates scope and safety,
> compiles approved read-only requests, and executes the test. A deterministic verifier confirms
> the result from fresh evidence. After remediation, the controller repeats the same access
> direction and verifies that the unauthorized request is denied.

Suggested flow:

1. Point out the permanent `SYNTHETIC LAB`, `LOCAL LLM`, `READ-ONLY`, and `AUTHORIZED TARGET` labels.
2. Explain that the model proposes one direction; it does not create the three-request protocol.
3. Show deterministic safety controls and zero external model egress.
4. Show `200 / 200 / 200`, the verifier-owned HIGH/CONFIRMED finding, and the linked
   controller-constructed `200 / 200 / 403` retest.
5. End on the visible limitations: synthetic lab, one read-only BOLA capability, no broad coverage,
   not production readiness, and not unrestricted autonomous pentesting.

Do not describe Nuclei, ZAP, or Burp DAST as connected. Do not call the audit store immutable.
