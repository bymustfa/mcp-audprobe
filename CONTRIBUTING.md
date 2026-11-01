# Contributing to mcp-audprobe

Thanks for helping! This is a small, focused tool; bug reports, new checks and docs fixes are all welcome.
(Türkçe katkılar ve issue'lar da kabul edilir.)

## Ground rules

- **Safety first.** mcp-audprobe must only ever send requests to servers you own or are explicitly authorized to
  test. Tests, demos and examples must only talk to servers started locally on `127.0.0.1`. PRs that add probing of
  third-party servers will be declined.
- **No AI signatures.** Do not add AI-tool signatures, `Co-Authored-By` trailers or "generated with ..." notes to
  commit messages or PR descriptions (see [AGENTS.md](AGENTS.md)).
- Be kind: see the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

```bash
git clone https://github.com/bymustfa/mcp-audprobe.git
cd mcp-audprobe
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
```

## Before opening a PR

```bash
ruff check .            # lint
ruff format --check .   # formatting (run `ruff format .` to fix)
pytest -q               # unit + end-to-end tests
./demo/run_demo.sh      # vulnerable=FAIL, hardened=PASS must still hold
```

CI runs the same steps (`lint`, `test`, `demo`, `action-selftest`) and they must pass.

## Pull requests

1. Fork and branch from `main` (`main` is protected: changes land via PR with one approving review).
2. Keep PRs small and focused; add or update tests for behaviour changes (verdict logic lives in
   `src/mcp_audprobe/checks.py`).
3. If you change the CLI, JSON output or checks, update both `README.md` and `README.tr.md`. The JSON schema is
   versioned (`schema_version`); do not change existing fields without bumping it.
4. Use [Conventional Commits](https://www.conventionalcommits.org/) for the PR title (it becomes the squash-commit
   subject): `feat: ...`, `fix: ...`, `docs: ...`, `chore: ...`; add `!` for breaking changes. Releases and the
   changelog are generated from these by release-please.

## Reporting bugs and ideas

Use the issue templates. For **security problems in mcp-audprobe itself**, do not open a public issue: see
[SECURITY.md](SECURITY.md).

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).

## Releases (maintainers)

Releases are automated with [release-please](https://github.com/googleapis/release-please): merging
Conventional-Commit PRs to `main` keeps an open "chore(main): release X.Y.Z" PR up to date; merging it creates the
tag, the GitHub Release and `CHANGELOG.md`, then publishes to PyPI via Trusted Publishing (OIDC, environment
`pypi`) and moves the floating `v1` tag used by `uses: bymustfa/mcp-audprobe@v1`. Release PRs created with the
default `GITHUB_TOKEN` do not trigger CI, so required checks do not report on them: merge them as an admin.
`release-as` was only used to force the first release (1.0.0) and has been removed; versions now follow the commit types.
