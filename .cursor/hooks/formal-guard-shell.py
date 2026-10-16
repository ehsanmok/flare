#!/usr/bin/env python3
"""Cursor `beforeShellExecution` hook: the agent may not re-lock Lean specs or
skip the formal pre-commit gate. Re-locking is a human sign-off.
"""

import json
import re
import sys

LOCK = re.compile(r"pixi\s+run\b[^|;&]*\sformal-spec-lock\b|spec_guard\.py\b[^|;&]*\s--lock\b")
SKIP = re.compile(r"(?:^|[;&|(]\s*|\bexport\s+)FORMAL_SKIP=1\b|git\s+commit\b[^|;&]*(?:--no-verify|\s-n\b)")


def main():
    try:
        cmd = json.load(sys.stdin).get("command", "")
    except ValueError:
        return {"permission": "allow"}
    if LOCK.search(cmd):
        return {
            "permission": "deny",
            "user_message": "Blocked: re-locking formal/spec.lock is reserved for humans.",
            "agent_message": (
                "Re-locking Lean specs (formal-spec-lock / spec_guard.py --lock) is a human "
                "sign-off. Show the user the spec or theorem-statement diff and ask them to run "
                "`pixi run -e formal formal-spec-lock` themselves."
            ),
        }
    if SKIP.search(cmd):
        return {
            "permission": "ask",
            "user_message": "This command skips the formal-drift pre-commit gate. Allow it?",
            "agent_message": (
                "Skipping the formal gate needs the user's approval. Prefer fixing what it "
                "reports (see the formal-sync skill)."
            ),
        }
    return {"permission": "allow"}


if __name__ == "__main__":
    print(json.dumps(main()))
