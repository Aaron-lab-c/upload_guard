"""Keep README code blocks identical to the files under examples/ and run the quick start.

A block is bound to a file with a marker on the line before its opening fence:

    <!-- include: examples/flask_app/app.py -->
    ```python
    ...file content...
    ```

    python tools/readme_examples.py --check   # CI: exit 1 if any block differs
    python tools/readme_examples.py --write   # refresh README from the files
    python tools/readme_examples.py --run     # execute blocks marked <!-- run -->
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
BLOCK = re.compile(r"<!-- include: (?P<path>[^ ]+) -->\n```(?P<lang>[a-z]*)\n(?P<body>.*?)```", re.S)
RUN = re.compile(r"<!-- run -->\n```python\n(?P<body>.*?)```", re.S)


def _file_text(rel: str) -> str:
    text = (ROOT / rel).read_text(encoding="utf-8")
    return text if text.endswith("\n") else text + "\n"


def check(readme: str) -> List[str]:
    problems = []
    found = 0
    for m in BLOCK.finditer(readme):
        found += 1
        if m.group("body") != _file_text(m.group("path")):
            problems.append(m.group("path"))
    if not found:
        problems.append("<no include markers found>")
    return problems


def write(readme: str) -> str:
    return BLOCK.sub(lambda m: "<!-- include: %s -->\n```%s\n%s```" % (m.group("path"), m.group("lang"), _file_text(m.group("path"))), readme)


def run_blocks(readme: str) -> int:
    sys.path.insert(0, str(ROOT / "src"))
    n = 0
    for m in RUN.finditer(readme):
        exec(compile(m.group("body"), "README-run-%d" % n, "exec"), {"__name__": "__readme__"})  # noqa: S102
        n += 1
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--write", action="store_true")
    g.add_argument("--run", action="store_true")
    args = ap.parse_args(argv)
    text = README.read_text(encoding="utf-8")
    if args.write:
        with README.open("w", encoding="utf-8", newline="\n") as fh:  # Path.write_text(newline=) needs 3.10
            fh.write(write(text))
        return 0
    if args.run:
        print("ran %d block(s)" % run_blocks(text))
        return 0
    problems = check(text)
    for p in problems:
        print("README block out of date:", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
