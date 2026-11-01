import pytest

from mcp_audprobe.safety import UnsafeTargetError, check_target


@pytest.mark.parametrize("u", ["http://127.0.0.1:8000/mcp", "http://localhost/mcp", "http://[::1]:9/mcp", "https://127.1.2.3/x"])
def test_loopback_ok(u):
    check_target(u)


@pytest.mark.parametrize("u", ["https://example.com/mcp", "http://10.0.0.5/mcp", "http://192.168.1.1/", "http://evil-localhost.com/", "ftp://127.0.0.1/"])
def test_non_loopback_refused(u):
    with pytest.raises(UnsafeTargetError):
        check_target(u)


def test_allow_remote():
    check_target("https://example.com/mcp", allow_remote=True)
