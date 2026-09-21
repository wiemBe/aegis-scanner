"""Single-use ops task process; its parent destroys the workspace after every invocation."""

from __future__ import annotations

import json
import re
import subprocess
import sys

from jinja2 import Environment, StrictUndefined, select_autoescape


def main() -> None:
    raw = sys.stdin.buffer.read(4096)
    payload = json.loads(raw)
    if payload.get("kind") == "diagnostic":
        target = str(payload["target"])
        if payload.get("execution") == "shell":
            argv = ["/bin/sh", "-c", f"printf '%s' {target}"]
        else:
            if not re.fullmatch(r"[A-Za-z0-9.-]{1,100}", target):
                raise ValueError("invalid target")
            argv = ["/usr/bin/printf", "%s", target]
        completed = subprocess.run(  # noqa: S603 - deliberate bounded synthetic worker execution
            argv,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=2,
            check=False,
        )
        if len(completed.stdout) > 4096:
            raise ValueError("output limit")
        result = {"run_id": f"OPS-{payload['reference']}", "status": "complete"}
    elif payload.get("kind") == "template":
        content = str(payload["content"])
        if payload.get("evaluation") == "template":
            value = (
                Environment(undefined=StrictUndefined, autoescape=select_autoescape())
                .from_string(content)
                .render()
            )
        else:
            value = (
                Environment(autoescape=True).from_string("{{ content }}").render(content=content)
            )
        result = {"preview": value[:1000]}
    else:
        raise ValueError("invalid task")
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
