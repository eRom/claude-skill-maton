"""Rule registry with auto-discovery.

Calling ``get_all_rules()`` imports every rule module found in this package
(excluding ``__init__.py`` and ``base.py``), collects all concrete subclasses
of ``Rule``, instantiates them, and returns the list.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.rules.base import Rule

# Legacy placeholder kept for backward compatibility; the canonical entry-point
# is get_all_rules().
REGISTRY: list = []


def get_all_rules() -> list["Rule"]:
    """Discover and return all concrete Rule subclasses from this package.

    Walks every .py module in the ``scanner/rules/`` directory (skipping
    ``__init__.py`` and ``base.py``), imports it, and collects any class that:
      - is a subclass of Rule
      - is not Rule itself
      - is not abstract (i.e. has no unimplemented abstract methods)

    Each qualifying class is instantiated once and included in the returned list.
    """
    from scanner.rules.base import Rule as BaseRule  # local import avoids circularity

    rules_pkg_path = Path(__file__).parent

    discovered: list["Rule"] = []
    seen_classes: set[type] = set()

    for module_info in pkgutil.iter_modules([str(rules_pkg_path)]):
        if module_info.name in ("base",):
            continue

        module = importlib.import_module(f"scanner.rules.{module_info.name}")

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                obj is BaseRule
                or not issubclass(obj, BaseRule)
                or obj in seen_classes
                or inspect.isabstract(obj)
            ):
                continue
            seen_classes.add(obj)
            discovered.append(obj())

    return discovered
