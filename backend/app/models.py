from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, String, Text, JSON, Integer, Index
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base

def utcnow(): return datetime.now(timezone.utc)
class Dataset(Base):
    __tablename__="datasets"
    id:Mapped[str]=mapped_column(String(36),primary_key=True); name:Mapped[str]=mapped_column(String(255)); data_type:Mapped[str]=mapped_column(String(16)); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=utcnow); event_count:Mapped[int]=mapped_column(Integer,default=0); status:Mapped[str]=mapped_column(String(32),default="ready",index=True); error:Mapped[str|None]=mapped_column(Text,nullable=True)
class SecurityEvent(Base):
    __tablename__="security_events"
    id:Mapped[str]=mapped_column(String(36),primary_key=True); dataset_id:Mapped[str]=mapped_column(ForeignKey("datasets.id",ondelete="CASCADE"),index=True); event_key:Mapped[str]=mapped_column(String(255)); timestamp:Mapped[str]=mapped_column(String(40),index=True); event_type:Mapped[str]=mapped_column(String(100),default="unknown"); username:Mapped[str|None]=mapped_column(String(255),nullable=True,index=True); source_ip:Mapped[str|None]=mapped_column(String(64),nullable=True,index=True); host:Mapped[str|None]=mapped_column(String(255),nullable=True); outcome:Mapped[str|None]=mapped_column(String(64),nullable=True); fields:Mapped[dict]=mapped_column(JSON,default=dict)
Index("ix_event_dataset_source_time",SecurityEvent.dataset_id,SecurityEvent.source_ip,SecurityEvent.timestamp)
class DetectionFinding(Base):
    __tablename__="detection_findings"
    id:Mapped[str]=mapped_column(String(36),primary_key=True); dataset_id:Mapped[str]=mapped_column(ForeignKey("datasets.id",ondelete="CASCADE"),index=True); rule_id:Mapped[str]=mapped_column(String(80),index=True); title:Mapped[str]=mapped_column(String(255)); severity:Mapped[str]=mapped_column(String(16),index=True); description:Mapped[str]=mapped_column(Text); event_ids:Mapped[list]=mapped_column(JSON); detected_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=utcnow)
class Incident(Base):
    __tablename__="incidents"
    id:Mapped[str]=mapped_column(String(36),primary_key=True); dataset_id:Mapped[str]=mapped_column(ForeignKey("datasets.id",ondelete="CASCADE"),index=True); title:Mapped[str]=mapped_column(String(255)); severity:Mapped[str]=mapped_column(String(16),index=True); status:Mapped[str]=mapped_column(String(32),default="open",index=True); first_seen:Mapped[str]=mapped_column(String(40)); last_seen:Mapped[str]=mapped_column(String(40)); event_ids:Mapped[list]=mapped_column(JSON); finding_ids:Mapped[list]=mapped_column(JSON); indicators:Mapped[list]=mapped_column(JSON); summary:Mapped[str]=mapped_column(Text,default="")
class AnalysisJob(Base):
    __tablename__="analysis_jobs"
    id:Mapped[str]=mapped_column(String(36),primary_key=True); dataset_id:Mapped[str]=mapped_column(ForeignKey("datasets.id",ondelete="CASCADE"),index=True); status:Mapped[str]=mapped_column(String(32),default="queued",index=True); stage:Mapped[str]=mapped_column(String(80),default="queued"); error:Mapped[str|None]=mapped_column(Text,nullable=True); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=utcnow); started_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True); ended_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
class Indicator(Base):
    __tablename__="indicators"
    id:Mapped[str]=mapped_column(String(36),primary_key=True); dataset_id:Mapped[str]=mapped_column(ForeignKey("datasets.id",ondelete="CASCADE"),index=True); kind:Mapped[str]=mapped_column(String(16)); value:Mapped[str]=mapped_column(String(512)); validation_status:Mapped[str]=mapped_column(String(32)); source_event_ids:Mapped[list]=mapped_column(JSON)
class ThreatIntelResult(Base):
    __tablename__="threat_intel_results"
    id:Mapped[str]=mapped_column(String(36),primary_key=True); indicator_id:Mapped[str]=mapped_column(ForeignKey("indicators.id",ondelete="CASCADE"),index=True); provider:Mapped[str]=mapped_column(String(64)); status:Mapped[str]=mapped_column(String(32)); payload:Mapped[dict]=mapped_column(JSON); retrieved_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=utcnow)
class AgentExecution(Base):
    __tablename__="agent_executions"
    id:Mapped[int]=mapped_column(primary_key=True); job_id:Mapped[str]=mapped_column(ForeignKey("analysis_jobs.id",ondelete="CASCADE"),index=True); agent:Mapped[str]=mapped_column(String(80)); status:Mapped[str]=mapped_column(String(32)); summary:Mapped[str]=mapped_column(Text,default=""); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=utcnow)
class IncidentReport(Base):
    __tablename__="incident_reports"
    id:Mapped[str]=mapped_column(String(36),primary_key=True); incident_id:Mapped[str]=mapped_column(ForeignKey("incidents.id",ondelete="CASCADE"),index=True); content:Mapped[dict]=mapped_column(JSON); markdown:Mapped[str]=mapped_column(Text); validation_status:Mapped[str]=mapped_column(String(32)); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=utcnow)
class HumanReview(Base):
    __tablename__="human_reviews"
    id:Mapped[str]=mapped_column(String(36),primary_key=True); incident_id:Mapped[str]=mapped_column(ForeignKey("incidents.id",ondelete="CASCADE"),index=True); decision:Mapped[str]=mapped_column(String(32)); note:Mapped[str]=mapped_column(Text,default=""); reviewer:Mapped[str]=mapped_column(String(100),default="local-analyst"); reviewed_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=utcnow)
