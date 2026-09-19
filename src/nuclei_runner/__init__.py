"""The isolated Aegis nuclei-runner service (Phase 1.2).

It runs in its own hardened container: non-root, read-only root filesystem, bounded tmpfs, no Linux
capabilities, no shell, no Docker socket, no host mount, no LLM credential, reachable only over the
internal engine-RPC network and able to reach only the synthetic target network. It executes the
single fixed ``NUCLEI_LAB_SAFE_HTTP_V1`` profile against inventory-resolved synthetic targets with
the pinned Nuclei binary and the pinned, admitted, signed template set — nothing else.
"""
