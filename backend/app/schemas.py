
from datetime import datetime

from pydantic import BaseModel, Field



class TelemetryInput(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    timestamp: datetime
    cpu_percent: float = Field(ge=0, le=100)
    memory_percent: float = Field(ge=0, le=100)
    process_count: int = Field(ge=0)
    bytes_sent: int = Field(ge=0)
    bytes_received: int = Field(ge=0)


class ProcessInput(BaseModel):
    pid: int = Field(ge=0)
    name: str = Field(min_length=1, max_length=255)
    status: str = Field(max_length=50)
    cpu_percent: float = Field(ge=0)
    memory_percent: float = Field(ge=0)
    executable: str | None = Field(
        default=None, max_length=2048
    )


class ProcessBatch(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    timestamp: datetime
    processes: list[ProcessInput] = Field(max_length=5000)


class NetworkAddress(BaseModel):
    ip: str = Field(min_length=1, max_length=100)
    port: int = Field(ge=0, le=65535)


class NetworkConnectionInput(BaseModel):
    pid: int | None = Field(default=None, ge=0)
    protocol: str = Field(pattern="^(TCP|UDP)$")
    status: str = Field(max_length=40)
    local_address: NetworkAddress | None = None
    remote_address: NetworkAddress | None = None


class NetworkBatch(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    timestamp: datetime
    connections: list[NetworkConnectionInput] = Field(
        max_length=10000
    )


class WebEventInput(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    timestamp: datetime
    method: str = Field(min_length=1, max_length=16)
    path: str = Field(min_length=1, max_length=2048)
    status_code: int = Field(ge=100, le=599)
    source: str = Field(default="local-test", max_length=100)
