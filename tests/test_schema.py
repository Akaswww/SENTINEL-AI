from datetime import datetime, timezone
import pytest
from pydantic import ValidationError
from backend.app.schemas import TelemetryInput

def test_valid_telemetry():
    value = TelemetryInput(hostname='test-mac', timestamp=datetime.now(timezone.utc), cpu_percent=12.5, memory_percent=40, process_count=100, bytes_sent=0, bytes_received=0)
    assert value.hostname == 'test-mac'

def test_invalid_cpu():
    with pytest.raises(ValidationError):
        TelemetryInput(hostname='test-mac', timestamp=datetime.now(timezone.utc), cpu_percent=150, memory_percent=40, process_count=100, bytes_sent=0, bytes_received=0)
