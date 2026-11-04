# Contributing

Thanks for looking. This is a small learning project, so the bar is "clear and honest", not "enterprise".

1. `python -m venv .venv`, install with `.venv/Scripts/python -m pip install -e ../Jev-toolkit-usage` and then `-e ".[dev]"` (use `.venv/bin/python` on Linux/macOS).
2. Run the tests: `python -m pytest`. They are offline and need no API key (`JEV_JUDGE=fake` is set in CI). Tests marked `live` call the real Jev API and are skipped by default.
3. New behaviour comes with a test. A bug fix comes with a regression test that fails without the fix.
4. Keep documentation claims measured: say what was tested, on how many cases, and what the limits are.
5. Never use the Jev SDK directly (it lives in Jev-toolkit-usage, `jev_core`); this tool talks to the `Judge` interface so the judge can be replaced by a local or European model.

Good first contributions: a bypass or false positive with an inert example (add it to a new held-out set, never tune rules on a set you report on), a clearer explanation in `--explain`.
