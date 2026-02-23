"""Modelos relacionados a los Clientes (Dispositivos) y Métricas"""

from __future__ import annotations

from datetime import datetime, UTC
from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from utils.database import Base


class ApprovedClient(Base):
    __tablename__ = "approved_clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
    )


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    client_identifier: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False, index=True
    )
    client_secret_key: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
    )    

    # Relaciones
    metrics: Mapped[list[ServerMetric]] = relationship(back_populates="client")


class DeviceCode(Base):
    __tablename__ = "device_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_code: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    user_code: Mapped[str] = mapped_column(
        String(20), unique=True, nullable=False, index=True
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    client_id: Mapped[int | None] = mapped_column(
        ForeignKey("clients.id"), nullable=True
    )


class ServerMetric(Base):
    __tablename__ = "server_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id"), nullable=False)
    cpu_usage: Mapped[float] = mapped_column(Float, nullable=False)
    ram_usage: Mapped[float] = mapped_column(Float, nullable=False)
    disk_usage: Mapped[float] = mapped_column(Float, nullable=False)
    net_sent: Mapped[int] = mapped_column(BigInteger)
    net_recv: Mapped[int] = mapped_column(BigInteger)
    net_speed_sent: Mapped[float] = mapped_column(Float, nullable=True)
    net_speed_recv: Mapped[float] = mapped_column(Float, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
    )

    client: Mapped[Client] = relationship(back_populates="metrics")
