# Renders docs/demo.gif:  PATH=$PATH:/path/to/vhs-and-ttyd  vhs docs/demo.tape   (needs vhs, ttyd, ffmpeg)
Output docs/demo.gif
Set Shell "bash"
Set FontSize 13
Set Width 1060
Set Height 470
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms

Hide
Type "source docs/demo-setup.sh"
Enter
Sleep 5s
Type "clear"
Enter
Show

Type "# 1) vulnerable MCP server: verifies signature/iss/exp but not aud"
Enter
Type "mcp-audprobe probe http://127.0.0.1:18001/mcp --audience http://127.0.0.1:18001/mcp --key-file key.pem"
Sleep 400ms
Enter
Sleep 5s

Hide
Type "clear"
Enter
Show

Type "# 2) hardened server: MCP SDK validate_token_resource=True"
Enter
Type "mcp-audprobe probe http://127.0.0.1:18002/mcp --audience http://127.0.0.1:18002/mcp --key-file key.pem"
Sleep 400ms
Enter
Sleep 5s

Type "echo exit code: $?"
Enter
Sleep 2s

Hide
Type "stop_demo"
Enter
Sleep 500ms
