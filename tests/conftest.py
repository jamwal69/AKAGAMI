"""
ReconForge Test Fixtures — Shared fixtures for all tests.
"""

import os
import tempfile
from unittest.mock import MagicMock, AsyncMock

import pytest

from reconforge.intel.models import MissionState, Task, OsintFinding
from reconforge.intel.store import IntelStore
from reconforge.memory.episodic import EpisodicMemory
from reconforge.memory.working import WorkingMemory


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    yield path
    os.unlink(path)


@pytest.fixture
def intel_store(temp_db):
    """Create a test IntelStore."""
    store = IntelStore(temp_db)
    yield store
    store.close()


@pytest.fixture
def episodic_memory(temp_db):
    """Create a test EpisodicMemory."""
    mem = EpisodicMemory(temp_db)
    yield mem
    mem.close()


@pytest.fixture
def working_memory():
    """Create a test WorkingMemory."""
    return WorkingMemory()


@pytest.fixture
def mission():
    """Create a test MissionState."""
    return MissionState(
        target="scanme.nmap.org",
        mission_name="Test Mission",
        scope=["scanme.nmap.org", "*.scanme.nmap.org"],
        out_of_scope=["mail.scanme.nmap.org"],
        active_scan_permitted=False,
        opsec_mode=False,
    )


@pytest.fixture
def sample_finding(mission):
    """Create a sample OsintFinding."""
    return OsintFinding(
        source_agent="osint_agent",
        source_tool="whois",
        confidence=0.9,
        mission_id=mission.mission_id,
        category="whois",
        value="scanme.nmap.org",
        context="Registered to Nmap.Org",
    )


@pytest.fixture
def sample_task():
    """Create a sample Task."""
    return Task(
        id="test_task_1",
        agent_type="osint",
        tool="whois",
        params={"target": "scanme.nmap.org"},
        priority=1,
        opsec_risk="passive",
    )


@pytest.fixture
def mock_anthropic():
    """Create a mock Anthropic client."""
    client = MagicMock()
    response = MagicMock()
    response.content = [MagicMock(text='[]')]
    client.messages.create.return_value = response
    return client
