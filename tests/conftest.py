"""Shared, environment-independent setup for the offline suite.

``aegis.settings.Settings`` reads a local ``.env`` so that a deployment can be configured without
code changes. The offline suite must not inherit whatever the developer happens to have configured
there (a different provider, model, base URL or auth mode), or its assertions about the documented
defaults become a property of one machine. Every test therefore runs against the declared defaults
plus its own explicit overrides; tests that need a specific profile (for example the DeepSeek
provider tests) already pass it explicitly.

Nothing about the runtime behaviour changes: the control plane still reads ``.env`` in production.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from aegis.settings import Settings


@pytest.fixture(autouse=True)
def hermetic_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Ignore the developer's local ``.env`` for the duration of every offline test."""

    monkeypatch.setitem(Settings.model_config, "env_file", None)
    yield
