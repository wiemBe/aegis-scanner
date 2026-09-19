# Browser screenshot privacy and retention policy

Browser screenshot capture is **disabled** in Phase 1.0. No approved browser runner is connected,
and no fixture is presented as scan evidence. The console labels the future placeholder
`BROWSER_SCREENSHOT · FIXTURE · NOT SCAN EVIDENCE`.

The implemented storage boundary applies these controls before any future capture can be persisted:

- approved synthetic origins only: `lab-api`, `127.0.0.1`, or `localhost`;
- capture must already have sensitive DOM selectors redacted;
- redaction status must be `REDACTED`;
- PNG or WebP only, with declared MIME checked against file magic;
- maximum 2560×1600 and 5,000,000 bytes per artifact;
- SHA-256 digest checked on read;
- content-addressed, generated relative storage reference; arbitrary paths are impossible;
- default 24-hour retention and maximum 48-hour metadata window;
- 25,000,000-byte project quota;
- expiry deletion requires the exact resolved project root and validated metadata;
- browser bytes and screenshot metadata are excluded from planner/model input by default;
- no public or cross-origin screenshot download endpoint exists in Phase 1.0.

Any future enablement requires an approved runner, selector-redaction tests, explicit audit events,
and hardened attachment responses (`Content-Disposition: attachment`, fixed safe filename,
`X-Content-Type-Options: nosniff`). It must not expand target scope or introduce unrestricted browser
automation.
