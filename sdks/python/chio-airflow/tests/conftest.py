"""Shared pytest configuration for the chio-airflow test suite.

Airflow boots a lot of machinery (database, configuration, scheduler
metadata) the first time any ``airflow.*`` module is imported.
Forcing unit-test mode keeps the database on sqlite-in-memory and
avoids scheduler bootstrap, which is critical for fast, hermetic
tests.
"""

from __future__ import annotations

import os

os.environ.setdefault("AIRFLOW__CORE__UNIT_TEST_MODE", "True")
os.environ.setdefault("AIRFLOW__CORE__LOAD_EXAMPLES", "False")
os.environ.setdefault("AIRFLOW__CORE__LAZY_LOAD_PLUGINS", "True")
