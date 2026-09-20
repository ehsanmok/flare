#!/usr/bin/env python3
"""Keep the three example inventories in step.

There are three lists of examples in this repo and they had drifted
apart: the files under ``examples/``, the ``example-*`` tasks in
``pixi.toml``, and the ``examples`` aggregate that runs them in one go.
At the time this was written the aggregate ran 44 of 72 files, so a
third of the examples were not run by anything, and at least one
``example-*`` task named a file that did not exist.

An example nothing runs is an example that rots. This is the gate that
stops the three lists separating again:

1. every ``examples/**/*.mojo`` has exactly one ``example-*`` task;
2. every ``example-*`` task names a file that exists;
3. the ``examples`` aggregate depends on every ``example-*`` task.

Run: ``pixi run check-example-tasks`` (also wired into the CI lint job).
Exit 0 when the three agree, 1 otherwise with the differences listed.
"""

from __future__ import annotations

import os
import re
import sys

PIXI = "pixi.toml"
ROOT = "examples"

TASK = re.compile(r'^(example-[a-z0-9-]+)\s*=\s*(.+)$', re.M)
MOJO_PATH = re.compile(r'(examples/[A-Za-z0-9_/.-]+\.mojo)')
AGGREGATE = re.compile(r'^examples\s*=\s*(\{.*?\}|".*?")\s*$', re.M | re.S)


def main() -> int:
    text = open(PIXI).read()

    tasks: dict[str, str] = {}
    for name, body in TASK.findall(text):
        hit = MOJO_PATH.search(body)
        if hit:
            tasks[name] = hit.group(1)

    on_disk = set()
    for dirpath, _, filenames in os.walk(ROOT):
        for f in filenames:
            if f.endswith(".mojo"):
                on_disk.add(os.path.join(dirpath, f))

    agg = AGGREGATE.search(text)
    in_aggregate: set[str] = set()
    if agg:
        in_aggregate = set(re.findall(r'"(example-[a-z0-9-]+)"', agg.group(1)))

    problems: list[str] = []

    run_by_a_task = set(tasks.values())
    for path in sorted(on_disk - run_by_a_task):
        problems.append(f"  no example-* task runs {path}")

    for name, path in sorted(tasks.items()):
        if path not in on_disk:
            problems.append(f"  task {name} names {path}, which does not exist")

    if agg is None:
        problems.append("  no `examples` aggregate task found in pixi.toml")
    else:
        for name in sorted(set(tasks) - in_aggregate):
            problems.append(f"  the `examples` aggregate is missing {name}")
        for name in sorted(in_aggregate - set(tasks)):
            problems.append(f"  the `examples` aggregate names {name}, which is not a task")

    if problems:
        sys.stderr.write(
            "check-example-tasks: the example inventories disagree.\n"
            + "\n".join(problems)
            + "\n\nEvery examples/**/*.mojo needs an `example-<name>` task,\n"
              "and the `examples` aggregate needs `depends-on` for each one.\n"
        )
        return 1

    print(
        f"check-example-tasks: {len(on_disk)} example(s), "
        f"{len(tasks)} task(s), all in the aggregate."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
