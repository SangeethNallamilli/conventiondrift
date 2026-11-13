"""Pytest plugin entry for mutmut: -p mutation_yaml_guard."""

from check_mutation_yaml import check, pytest_sessionstart

__all__ = ["check", "pytest_sessionstart"]
