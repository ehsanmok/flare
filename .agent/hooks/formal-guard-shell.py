#!/usr/bin/env python3
"""Shell guard hook: the agent may not re-lock Lean specs or skip the formal
pre-commit gate. Re-locking is a human sign-off.

Speaks both hook dialects: Cursor `beforeShellExecution` (wired in
.cursor/hooks.json) and Claude Code `PreToolUse` on Bash (wired in
.claude/settings.json).
"""

import json
import re
import sys

LOCK = re.compile(r"pixi\s+run\b[^|;&]*\sformal-spec-lock\b|spec_guard\.py\b[^|;&]*\s--lock\b")
SKIP = re.compile(r"(?:^|[;&|(]\s*|\bexport\s+)FORMAL_SKIP=1\b|git\s+commit\b[^|;&]*(?:--no-verify|\s-n\b)")


def decide(cmd):
    """Returns (permission, user_message, agent_message), or None to allow."""
    if LOCK.search(cmd):
        return (
            "deny",
            "Blocked: re-locking formal/spec.lock is reserved for humans.",
            "Re-locking Lean specs (formal-spec-lock / spec_guard.py --lock) is a human "
            "sign-off. Show the user the spec or theorem-statement diff and ask them to run "
            "`pixi run -e formal formal-spec-lock` themselves.",
        )
    if SKIP.search(cmd):
        return (
            "ask",
            "This command skips the formal-drift pre-commit gate. Allow it?",
            "Skipping the formal gate needs the user's approval. Prefer fixing what it "
            "reports (see the formal-sync skill).",
        )
    return None


def main():
    try:
        event = json.load(sys.stdin)
    except ValueError:
        event = {}
    claude = event.get("hook_event_name") == "PreToolUse"
    if claude:
        cmd = (event.get("tool_input") or {}).get("command", "")
    else:
        cmd = event.get("command", "")
    verdict = decide(cmd)
    if claude:
        # Claude Code: say nothing on allow, so the normal permission flow applies.
        if verdict is None:
            return {}
        permission, user_msg, agent_msg = verdict
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": permission,
                "permissionDecisionReason": f"{user_msg} {agent_msg}",
            }
        }
    if verdict is None:
        return {"permission": "allow"}
    permission, user_msg, agent_msg = verdict
    return {"permission": permission, "user_message": user_msg, "agent_message": agent_msg}


if __name__ == "__main__":
    print(json.dumps(main()))
