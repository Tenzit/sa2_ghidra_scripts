import argparse
from argparse import Namespace
from typing import Any, Callable, Sequence, Optional


class GhidraArgumentParser(argparse.ArgumentParser):
    def __init__(self, *a, **kw) -> None:
        super().__init__(*a, *kw)
        self._soft = {}

    def add_argument(self, *flags, **kw) -> argparse.Action:
        on_missing: Optional[Callable[[], Any]] = kw.pop("on_missing", None)
        action: argparse.Action = super().add_argument(*flags, **kw)

        if action.required and not action.default:
            setattr(action, "default", argparse.SUPPRESS)
            setattr(action, "nargs", "?")
            self._soft[action.dest] = (on_missing, action)

        return action

    def parse_args(self, # type: ignore[override]
                   args: Optional[Sequence[str]] = None,
                   namespace: None = None) -> Namespace:
        ns = super().parse_args(args=args, namespace=namespace)

        for dest, (cb, action) in self._soft.items():
            if not hasattr(ns, dest):
                if cb is None:
                    self.error(f"Missing required argument: {dest}")
                val = cb()
                setattr(ns, dest, val)

        return ns

    # optional: don't kill the whole run with SystemExit; raise a Python exception instead
    def error(self, message):
        self.print_usage()
        raise RuntimeError(f"Argument error: {message}")