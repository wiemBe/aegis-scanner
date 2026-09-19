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
- **Scope is unchanged.** The Phase 1.1 GO verdict remains limited to the bounded synthetic lab and the
  single read-only BOLA capability executed through the engine interface. Nuclei, ZAP and Burp DAST
  are not operational. Nothing in this repository claims production readiness.

The baseline commit is tagged `phase-1.1-go`.
