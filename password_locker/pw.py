"""Windows-friendly shortcut for the secure credential retrieval command."""

from __future__ import annotations

import sys
from typing import Sequence, TextIO

from . import cli


def main(
    argv: Sequence[str] | None = None,
    *,
    dependencies: cli.CLIDependencies | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Delegate ``pw ACCOUNT`` to ``password-locker get ACCOUNT``."""
    arguments = sys.argv[1:] if argv is None else argv
    return cli.main(
        ["get", *arguments],
        dependencies=dependencies,
        stdout=stdout,
        stderr=stderr,
    )
