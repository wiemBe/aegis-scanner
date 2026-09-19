"""The isolated Aegis zap-runner service (Phase 1.3).

It runs in its own hardened container built from the pinned ZAP image: non-root, read-only root
filesystem, bounded tmpfs for all ZAP state, no Linux capabilities, no shell, no Docker socket,
no host mount, no credential, no published port. It is reachable only over the internal zap-rpc
network and its only outbound network contains nothing but the scope guard. It executes the single
fixed ``ZAP_LAB_PASSIVE_OPENAPI_V1`` profile against inventory-resolved synthetic targets with the
pinned ZAP release and the pinned add-on inventory — nothing else.
"""
