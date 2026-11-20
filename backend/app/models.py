
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class Telemetry(Base):
    __tablename__ = "telemetry"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )

    hostname: Mapped[str] = mapped_column(
        String(255), index=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True)
    )

    cpu_percent: Mapped[float] = mapped_column(Float)
    memory_percent: Mapped[float] = mapped_column(Float)
    process_count: Mapped[int] = mapped_column(Integer)

    bytes_sent: Mapped[int] = mapped_column(BigInteger)
    bytes_received: Mapped[int] = mapped_column(BigInteger)


class ProcessSnapshot(Base):
    __tablename__ = "process_snapshots"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )

    hostname: Mapped[str] = mapped_column(
        String(255), index=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True)
    )

    pid: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(50))
    cpu_percent: Mapped[float] = mapped_column(Float)
    memory_percent: Mapped[float] = mapped_column(Float)
    executable: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )


class SecurityAlert(Base):
    source_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="unknown",
    )
    
    source_name: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    __tablename__ = "security_alerts"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )

    hostname: Mapped[str] = mapped_column(
        String(255), index=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True)
    )

    category: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(String(2048))
    pid: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    evidence: Mapped[str] = mapped_column(String(2048))
    status: Mapped[str] = mapped_column(
        String(20), default="open"
    )


class NetworkConnection(Base):
    __tablename__ = "network_connections"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )

    hostname: Mapped[str] = mapped_column(
        String(255), index=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )

    pid: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    protocol: Mapped[str] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(40))

    local_ip: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    local_port: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    remote_ip: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    remote_port: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )


class DefenseDecision(Base):
    __tablename__ = "defense_decisions"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )

    alert_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("security_alerts.id"),
        index=True,
    )

    action: Mapped[str] = mapped_column(String(100))

    decision: Mapped[str] = mapped_column(String(20))

    execution_mode: Mapped[str] = mapped_column(
        String(20), default="simulation"
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True)
    )
