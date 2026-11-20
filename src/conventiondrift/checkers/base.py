"""The checker interface (INTERFACES I-10, ADR-0003; DESIGN §12 A-1).

Internal in v1, shaped as a future plugin API. Checkers are pure: they see
only the parsed AST and a ``FileContext``. The Protocol itself is defined in
``components.py`` with the other I-11 Protocols (I-13 C6 item 8), so that
module never has to load a checker; it is re-exported here with the types it
uses, which live in ``model.py`` (I-13 Q1).
"""

from conventiondrift.components import Checker
from conventiondrift.model import CheckerId, FileContext, RuleMatch, Site

__all__ = ["Checker", "CheckerId", "FileContext", "RuleMatch", "Site"]
