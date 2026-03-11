"""Unit tests for the state machine."""
import pytest
from src.state.state_machine import StateMachine, JobStatus, InvalidTransitionError, DuplicateJobError
from src.state.store import StateStore
import tempfile, os

@pytest.fixture
def store(tmp_path):
    return StateStore(db_path=str(tmp_path / "test.db"))

@pytest.fixture
def sm(store):
    return StateMachine(store)

def test_create_job(sm):
    job = sm.create_job("/tmp/bundle.pem", "cert_vpn_prod", "abc123")
    assert job.status == JobStatus.DETECTED
    assert job.job_id is not None

def test_valid_transition(sm):
    job = sm.create_job("/tmp/bundle.pem", "cert_vpn_prod", "def456")
    job = sm.transition(job, JobStatus.INSPECTED, reason="test")
    assert job.status == JobStatus.INSPECTED
    assert len(job.history) == 1

def test_invalid_transition(sm):
    job = sm.create_job("/tmp/bundle.pem", "cert_vpn_prod", "ghi789")
    with pytest.raises(InvalidTransitionError):
        sm.transition(job, JobStatus.COMPLETED)  # Can't jump to COMPLETED from DETECTED

def test_duplicate_job_rejected(sm):
    sm.create_job("/tmp/bundle.pem", "cert_vpn_prod", "sha_same")
    with pytest.raises(DuplicateJobError):
        sm.create_job("/tmp/bundle2.pem", "cert_vpn_prod", "sha_same")

def test_full_happy_path(sm):
    job = sm.create_job("/tmp/b.pem", "certkey", "sha_happy")
    for status in [
        JobStatus.INSPECTED, JobStatus.DELTA_ANALYZED,
        JobStatus.UAT_DEPLOYED, JobStatus.UAT_VALIDATED,
        JobStatus.TCM_PENDING, JobStatus.TCM_APPROVED,
        JobStatus.PROD_WAVE_1, JobStatus.PROD_WAVE_2,
        JobStatus.PROD_WAVE_3, JobStatus.COMPLETED,
    ]:
        job = sm.transition(job, status)
    assert job.status == JobStatus.COMPLETED
    assert len(job.history) == 10
