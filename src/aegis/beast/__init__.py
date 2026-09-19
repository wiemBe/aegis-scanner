"""Phase 1.4 controlled active adversarial testing.

The package is deliberately separate from the scanner kernel.  Scanner jobs remain typed and
controller-compiled; BEAST commands are opaque data until they reach the disposable sandbox.
"""

from aegis.beast.contracts import BEAST_PROFILE_ID

__all__ = ["BEAST_PROFILE_ID"]
