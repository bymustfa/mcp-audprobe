# AGENTS.md

Proje kuralı (Mustafa ÖZTÜRK): Hiçbir yapay zekâ aracı (Claude, Codex, Cursor, Copilot vb.) commit mesajlarına veya PR açıklamalarına imza, `Co-Authored-By` satırı ya da "generated with ..." / "Generated with Claude Code" benzeri bir not eklemez.

English equivalent: no AI tool may add a signature, a `Co-Authored-By` trailer, or a "generated with ..." note to commit messages or pull request descriptions.

## Safety

`mcp-audprobe` must only ever send requests to servers you own or are explicitly authorized to test. Never point it (or tests) at third-party servers.
