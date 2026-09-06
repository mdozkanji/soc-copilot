"""
Test-session configuration.

The DeprecationWarning filter below exists because pyproject.toml's
[tool.pytest.ini_options] filterwarnings entry did not reliably suppress
it -- tried both a message-regex form and a module-targeted form, neither
took effect, most likely because the warning fires at *import* time
(fastapi.testclient's `from starlette.testclient import TestClient`, first
triggered while pytest is still collecting test_api.py) rather than during
test execution, which is a different point in pytest's filter-application
lifecycle than the ini option reliably covers. Registering the filter here,
in conftest.py, which pytest imports before collecting any test file,
fixed it -- confirmed by actually re-running the suite after each attempt,
not assumed.

This is Starlette's own signaled migration to a future package it calls
httpx2 -- not yet a real, released, adoptable dependency, and not
something in this project's code to fix, unlike the chromadb warning
resolved properly in Week 5 (which was our own test double's contract to
get right). Revisit if/when httpx2 actually exists as a stable, documented
package worth adopting.

Root cause of why this took several attempts to actually suppress: every
DeprecationWarning-category filter tried was correctly failing to match,
because starlette.exceptions.StarletteDeprecationWarning actually
subclasses UserWarning, not DeprecationWarning -- confirmed directly by
inspecting warning.category.__mro__ at runtime rather than assuming.
"""


def pytest_configure(config):
    config.addinivalue_line("filterwarnings", "ignore:.*httpx2.*:UserWarning")
