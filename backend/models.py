"""SQLAlchemy database models for vuln-scanner."""

from sqlalchemy import Column, Date, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Scan(Base):
    """Represents a completed scan job."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    target_path = Column(String, nullable=False)
    status = Column(String, default="completed")
    started_at = Column(DateTime)
    completed_at = Column(DateTime)


class Vulnerability(Base):
    """Represents a detected vulnerability."""

    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, nullable=False)
    category = Column(String, nullable=False)  # sqli, xss, secrets, outdated_deps
    severity_score = Column(Float, nullable=False)
    description = Column(Text, nullable=False)
    location = Column(String, nullable=False)
    remediation_suggestion = Column(Text, nullable=True)


class TrendRecord(Base):
    """Tracks per-day vulnerability counts from scan history."""

    __tablename__ = "trend_records"

    id = Column(Integer, primary_key=True)
    date = Column(Date, nullable=False, unique=True)
    sqli_count = Column(Integer, default=0)
    xss_count = Column(Integer, default=0)
    secrets_count = Column(Integer, default=0)
    outdated_deps_count = Column(Integer, default=0)
