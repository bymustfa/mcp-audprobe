## What and why

<!-- Short description of the change and motivation. Link issues: Fixes #123 -->

## Checklist

- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `pytest -q` passes (tests added/updated for behaviour changes)
- [ ] `./demo/run_demo.sh` still shows vulnerable=FAIL, hardened=PASS
- [ ] README.md **and** README.tr.md updated if CLI/JSON/checks changed
- [ ] Nothing probes servers other than ones started locally (127.0.0.1) in tests/demos
- [ ] No AI signature / `Co-Authored-By` / "generated with" lines in commits or this description
