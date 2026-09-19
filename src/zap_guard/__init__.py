"""The isolated Aegis ZAP scope guard (Phase 1.3).

A standard-library-only forward proxy and counter that sits between the zap-runner and the
synthetic target. It is the network-layer scope boundary for ZAP: the runner container has no
route to the target except through this service. See :mod:`zap_guard.guard`.
"""
