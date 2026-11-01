import pytest

from mcp_audprobe.tokens import KeyMaterial


@pytest.fixture(scope="session")
def km() -> KeyMaterial:
    return KeyMaterial.generate()
