# Nuclei template supply chain

The controller-owned manifest is `src/aegis_nuclei/manifest.json`. It pins the engine release and
binary hashes, the upstream template release/commit, license, exact admitted path and bytes,
signature identity, protocol/method/request budget, redirect behavior, severity, capability,
verification policy and review record. The admitted bytes are under
`deploy/nuclei-runner/templates/`; runtime update or download is forbidden.

## Admission sequence

At runner boot and again immediately before execution, Aegis requires:

1. the Nuclei binary digest for the current architecture matches the manifest;
2. every manifest entry is a regular non-symlink file below the fixed template root;
3. file and license hashes match, with no extra YAML files;
4. the structural allowlist accepts only HTTP GET/HEAD, pinned `{{BaseURL}}` paths and reviewed
   matcher/extractor syntax, with no raw request, body, payload, redirect, local file, environment,
   remote reference, OAST, workflow, code, JavaScript, headless, file or network feature;
5. pinned Nuclei `-validate` succeeds; and
6. a loopback sink probe with `-disable-unsigned-templates` proves all admitted templates execute
   as signed and none is skipped as unsigned.

Any uncertainty makes the runner NOT READY or rejects the whole execution. A signature comment is
not treated as cryptographic proof by itself; the pinned Nuclei binary's signature enforcement and
execution report provide that proof.

## Current manifest

| Field | Pin |
| --- | --- |
| Nuclei | `v3.11.1` / `a8c88feb4a1c8e961b7902534ce3af97e9d524a4` |
| Templates | `v10.4.8` / `e5f19e6144135e107962bb943231413796fd7fe7` |
| Template | `http/exposures/configs/git-config.yaml` (`git-config`) |
| Template SHA-256 | `bd8bdfa0b5ed5bf4d3712edb793adfd0987d9282e51c6f7d673bf14b9e4dd524` |
| Signature | `SIGNED_VERIFIED`, signer fingerprint `922c64590222798bb761d5b6d8e72950` |
| Manifest SHA-256 | `8c69c056d9d11990bf11cbc688252d30426654a7ccb16996d3559c84fa472845` |

The AI technical admission review remains visibly marked `operator_countersigned: false`. Runtime
cryptographic and integrity checks are complete, but future template additions require explicit
operator review and a new manifest/profile version.
