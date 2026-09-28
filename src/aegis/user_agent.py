"""Controller-owned default HTTP User-Agent for probes against the synthetic lab.

A tool-identifying User-Agent (ffuf's default, or the previous ``Aegis-*`` strings) is trivially
matched by default WAF / deny rules, so the target answers 403 for a reason that has nothing to do
with the finding under test and masks its real behaviour. Probes therefore present a common,
unremarkable browser User-Agent so the synthetic target responds as it would to an ordinary client.

This is a single, fixed client header on requests to the operator's own authorized target. It is
*not* an evasion or anti-attribution control: there is no per-request cycling, no IP rotation and no
MAC spoofing, and — by the Phase 2.2 invariant — the model can never choose this value.
"""

# Current-stable Chrome on Windows. To present as Firefox instead, swap in the line below.
DEFAULT_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# Firefox alternative (uncomment to use instead of the Chrome string above):
# DEFAULT_BROWSER_USER_AGENT = (
#     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
# )
