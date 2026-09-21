"""
IOC (Indicators of Compromise), Domain, IP, and URL ORM models.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from app.database.base import Base


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    
    ioc_type = Column(String(24), nullable=False) # IP, DOMAIN, URL, HASH
    value = Column(String(512), nullable=False, index=True)
    
    reputation_score = Column(Integer, default=0, nullable=False) # 0 (clean) to 100 (confirmed threat)
    is_malicious = Column(Boolean, default=False, nullable=False)
    source_feed = Column(String(64), default="LOCAL_OBSERVATION", nullable=False)
    
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="iocs")


class IPAddress(Base):
    __tablename__ = "ip_addresses"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(64), unique=True, index=True, nullable=False)
    is_private = Column(Boolean, default=False, nullable=False)
    
    # Geolocation & Network Infrastructure (Observed)
    country_code = Column(String(8), nullable=True)
    country_name = Column(String(64), nullable=True)
    city = Column(String(64), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    asn = Column(String(32), nullable=True)
    asn_org = Column(String(128), nullable=True)
    isp = Column(String(128), nullable=True)
    abuse_score = Column(Integer, default=0, nullable=False)
    
    last_checked = Column(DateTime, default=datetime.utcnow, nullable=False)


class DomainName(Base):
    __tablename__ = "domain_names"

    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String(255), unique=True, index=True, nullable=False)
    registrar = Column(String(128), nullable=True)
    registered_at = Column(DateTime, nullable=True)
    is_lookalike = Column(Boolean, default=False, nullable=False)
    impersonated_target = Column(String(128), nullable=True)
    reputation_score = Column(Integer, default=0, nullable=False)
    
    last_checked = Column(DateTime, default=datetime.utcnow, nullable=False)


class SuspiciousURL(Base):
    __tablename__ = "suspicious_urls"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(1024), unique=True, index=True, nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    threat_category = Column(String(64), default="SUSPICIOUS_LINK", nullable=False)
    is_defanged = Column(Boolean, default=True, nullable=False)
    virustotal_positives = Column(Integer, default=0, nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
