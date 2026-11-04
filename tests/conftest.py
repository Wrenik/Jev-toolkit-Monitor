"""Keep every test away from the developer's real ~/.jev-toolkit and from any real JEV_* settings."""

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("JEV_HOME", str(tmp_path_factory.mktemp("jev-home")))
    for key in ("JEV_TOOLKIT_ENV", "TYPESAFE_API_KEY", "JEV_JUDGE", "JEV_MODEL"):
        monkeypatch.delenv(key, raising=False)
