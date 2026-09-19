# Repository provenance

This Git repository was initialized on 2026-09-19 from the **Phase 1.1 GO working snapshot** of the
Aegis AI Security Lab.

- **Original history unavailable.** The original repository metadata and earlier commit history were
  unavailable when this repository was created. They were not recovered and have not been
  reconstructed.
- **One import commit.** The initial commit (`chore(repo): establish Phase 1.1 lab baseline`) imports
  the working snapshot as a single commit. It has no ancestors. It must not be presented as proof
  that historical commits were recovered, and no earlier commit is referenced as its parent.
- **Earlier phases are documents, not ancestors.** The phase documents in `docs/` (Phase 0.2 through
  Phase 1.1) and `PROJECT_STATE.md` describe how the project evolved. They are records of that work,
  not Git ancestors of the baseline commit.
- **Local evidence stays local.** Generated runtime evidence under `artifacts/`, local configuration
  (`.env`, `.env.gateway`, backups), test certificates and keys (`deploy/certs/`), local databases and
  model weights are excluded by `.gitignore` and are not part of the repository.
- **Phase 1.2 is ordinary forward history.** Work after the import commit is recorded honestly on
  `feat/phase-1.2-nuclei`; it does not reconstruct any missing ancestor. The Phase 1.2 scope adds
  only one pinned, signed, anonymous read-only Nuclei capability for the synthetic lab. ZAP and Burp
  DAST remain disabled. Nothing in this repository claims production readiness.

- **Phase 1.3 is ordinary forward history.** Work after `phase-1.2-go` is recorded on
  `feat/phase-1.3-zap-passive`. It adds only one pinned, isolated, passive ZAP profile for the
  synthetic lab. Active scanning, production targets and Burp DAST remain disabled.

- **Phase 1.4 is ordinary forward history.** Work starts from clean `main` at annotated tag
  `phase-1.3-go` on `feat/phase-1.4-beast-mode`. The authoritative TRUE ADVERSARY SHELL correction
  permits arbitrary model-selected commands only inside the disposable sandbox. It does not widen
  the synthetic target, network, resource, audit, cleanup, emergency-stop or verifier boundaries.

The baseline commit is tagged `phase-1.1-go`.
