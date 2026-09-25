"""
SupplyGraph Conftest
Shared pytest fixtures for backend tests.
"""

import pytest
from typing import Generator


@pytest.fixture(scope="session")
def sample_pypi_packages() -> list[dict]:
    """Sample PyPI packages for testing."""
    return [
        {"name": "requests", "version": "2.31.0", "ecosystem": "pypi"},
        {"name": "flask", "version": "3.0.0", "ecosystem": "pypi"},
        {"name": "numpy", "version": "1.26.0", "ecosystem": "pypi"},
    ]


@pytest.fixture(scope="session")
def sample_npm_packages() -> list[dict]:
    """Sample npm packages for testing."""
    return [
        {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
        {"name": "express", "version": "4.18.0", "ecosystem": "npm"},
    ]


@pytest.fixture(scope="session")
def typosquat_pairs() -> list[tuple[str, str]]:
    """Known typosquatting pairs for testing."""
    return [
        ("reqeusts", "requests"),   # transposition
        ("numpyy", "numpy"),         # extra character
        ("fl4sk", "flask"),          # character substitution
        ("expres", "express"),       # missing character
    ]


@pytest.fixture(scope="session")
def suspicious_python_code() -> str:
    """Sample Python code with suspicious patterns for AST testing."""
    return '''
import subprocess
import base64
import os

# Suspicious: subprocess with shell=True
def run_command(cmd):
    subprocess.call(cmd, shell=True)

# Suspicious: base64 encoded string
ENCODED = base64.b64decode("aHR0cHM6Ly9zdXNwaWNpb3VzLWV4YW1wbGUuY29t").decode()

# Suspicious: eval usage
def dynamic_exec(code_str):
    eval(code_str)

# Suspicious: environment credential access
TOKEN = os.environ.get("AWS_SECRET_ACCESS_KEY")
'''


@pytest.fixture(scope="session")
def clean_python_code() -> str:
    """Sample Python code with no suspicious patterns."""
    return '''
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


def greet(name: str) -> str:
    """Return a greeting message."""
    return f"Hello, {name}!"


class Calculator:
    def multiply(self, a: float, b: float) -> float:
        return a * b
'''
