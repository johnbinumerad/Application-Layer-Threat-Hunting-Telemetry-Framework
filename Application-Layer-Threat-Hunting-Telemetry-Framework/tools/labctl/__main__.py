"""Dispatcher: ``python -m tools.labctl <command>``."""

from __future__ import annotations

import importlib
import sys

# Subcommands are implemented in later tasks; each module must expose main(argv).
COMMANDS = {
    "up": "tools.labctl.up",
    "setup": "tools.labctl.setup",
    "validate": "tools.labctl.validate",
    "cleanup": "tools.labctl.cleanup",
    "sigma-check": "tools.labctl.sigma_check",
    "verify-no-secrets": "tools.labctl.verify_no_secrets",
}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in COMMANDS:
        print(f"usage: labctl {{{'|'.join(COMMANDS)}}} [args]", file=sys.stderr)
        return 2
    try:
        module = importlib.import_module(COMMANDS[args[0]])
    except ModuleNotFoundError:
        print(f"labctl {args[0]}: not implemented yet", file=sys.stderr)
        return 2
    return int(module.main(args[1:]) or 0)


if __name__ == "__main__":
    sys.exit(main())
