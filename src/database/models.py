"""
数据库模型定义
用于记录渗透测试的每一步操作和日志
"""
from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON, ForeignKey, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum

from ..orchestrator.states import KillChainState, TaskStatus, AgentType

Base = declarative_base()


class PenetrationTestSession(Base):
    """渗透测试会话"""
    __tablename__ = "pentest_sessions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), unique=True, nullable=False, index=True)
    target_url = Column(String(2048), nullable=False)
    target_info = Column(JSON, nullable=True)
    
    # 会话状态
    status = Column(Enum(TaskStatus), default=TaskStatus.PENDING, nullable=False)
    current_stage = Column(Enum(KillChainState), default=KillChainState.INITIALIZED, nullable=False)
    safe_mode = Column(Boolean, default=True, nullable=False)
    
    # 时间戳
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    
    # 配置信息
    configuration = Column(JSON, nullable=True)
    
    # 关系
    stages = relationship("StageExecution", back_populates="session", cascade="all, delete-orphan")
    agent_logs = relationship("AgentLog", back_populates="session", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<PenetrationTestSession(id={self.id}, session_id='{self.session_id}', target='{self.target_url}')>"


class StageExecution(Base):
    """阶段执行记录"""
    __tablename__ = "stage_executions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("pentest_sessions.session_id"), nullable=False, index=True)
    
    # 阶段信息
    stage = Column(Enum(KillChainState), nullable=False)
    stage_name = Column(String(256), nullable=False)
    agent_type = Column(Enum(AgentType), nullable=False)
    
    # 执行状态
    status = Column(Enum(TaskStatus), default=TaskStatus.PENDING, nullable=False)
    
    # 输入输出
    input_data = Column(JSON, nullable=True)
    output_data = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    
    # 执行时间
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    execution_time_seconds = Column(Integer, nullable=True)
    
    # 工具使用
    tools_used = Column(JSON, nullable=True)  # 记录使用的工具列表
    commands_executed = Column(JSON, nullable=True)  # 记录执行的命令
    
    # 关系
    session = relationship("PenetrationTestSession", back_populates="stages")
    agent_logs = relationship("AgentLog", back_populates="stage", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<StageExecution(id={self.id}, stage='{self.stage}', status='{self.status}')>"


class AgentLog(Base):
    """Agent详细日志"""
    __tablename__ = "agent_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("pentest_sessions.session_id"), nullable=False, index=True)
    stage_id = Column(Integer, ForeignKey("stage_executions.id"), nullable=True, index=True)
    
    # Agent信息
    agent_name = Column(String(256), nullable=False)
    agent_type = Column(Enum(AgentType), nullable=False)
    
    # 日志级别和类型
    log_level = Column(String(20), nullable=False, default="INFO")  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    log_type = Column(String(50), nullable=False)  # EXECUTION, DECISION, TOOL_CALL, RESPONSE, ERROR
    
    # 日志内容
    message = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)  # 详细信息，如工具调用参数、响应数据等
    
    # 时间戳
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # 关系
    session = relationship("PenetrationTestSession", back_populates="agent_logs")
    stage = relationship("StageExecution", back_populates="agent_logs")
    
    def __repr__(self):
        return f"<AgentLog(id={self.id}, agent='{self.agent_name}', level='{self.log_level}')>"


class ToolExecution(Base):
    """工具执行记录"""
    __tablename__ = "tool_executions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("pentest_sessions.session_id"), nullable=False, index=True)
    stage_id = Column(Integer, ForeignKey("stage_executions.id"), nullable=True, index=True)
    
    # 工具信息
    tool_name = Column(String(256), nullable=False)
    tool_version = Column(String(50), nullable=True)
    command = Column(Text, nullable=False)
    parameters = Column(JSON, nullable=True)
    
    # 执行结果
    status = Column(Enum(TaskStatus), default=TaskStatus.PENDING, nullable=False)
    return_code = Column(Integer, nullable=True)
    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)
    execution_time_seconds = Column(Integer, nullable=True)
    
    # 时间戳
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    
    # 安全相关
    safe_mode = Column(Boolean, default=True, nullable=False)
    risk_level = Column(String(20), nullable=False, default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    
    def __repr__(self):
        return f"<ToolExecution(id={self.id}, tool='{self.tool_name}', status='{self.status}')>"


class HumanIntervention(Base):
    """人工干预记录"""
    __tablename__ = "human_interventions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("pentest_sessions.session_id"), nullable=False, index=True)
    stage_id = Column(Integer, ForeignKey("stage_executions.id"), nullable=True, index=True)
    
    # 干预信息
    trigger_reason = Column(String(512), nullable=False)  # 触发干预的原因
    intervention_type = Column(String(50), nullable=False)  # APPROVAL, MODIFICATION, HALT, GUIDANCE
    
    # 请求和响应
    request_data = Column(JSON, nullable=False)  # 请求人工干预的数据
    response_data = Column(JSON, nullable=True)  # 人工响应的数据
    approval_status = Column(String(20), nullable=True)  # APPROVED, REJECTED, MODIFIED
    
    # 时间戳
    requested_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    responded_at = Column(DateTime, nullable=True)
    
    # 操作员信息
    operator_id = Column(String(128), nullable=True)
    operator_notes = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<HumanIntervention(id={self.id}, type='{self.intervention_type}', status='{self.approval_status}')>"


class SelfCorrection(Base):
    """自我纠错记录"""
    __tablename__ = "self_corrections"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("pentest_sessions.session_id"), nullable=False, index=True)
    stage_id = Column(Integer, ForeignKey("stage_executions.id"), nullable=True, index=True)
    
    # 纠错信息
    correction_type = Column(String(50), nullable=False)  # RETRY, ALTERNATIVE, PARAMETER_ADJUSTMENT
    trigger_condition = Column(String(512), nullable=False)  # 触发纠错的条件
    
    # 原始和修正数据
    original_action = Column(JSON, nullable=False)
    corrected_action = Column(JSON, nullable=False)
    correction_reasoning = Column(Text, nullable=False)
    
    # 结果
    correction_result = Column(JSON, nullable=True)
    success = Column(Boolean, nullable=True)
    
    # 时间戳
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    applied_at = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f"<SelfCorrection(id={self.id}, type='{self.correction_type}', success='{self.success}')>"


class VulnerabilityDiscovery(Base):
    """漏洞发现记录"""
    __tablename__ = "vulnerability_discoveries"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("pentest_sessions.session_id"), nullable=False, index=True)
    stage_id = Column(Integer, ForeignKey("stage_executions.id"), nullable=True, index=True)
    
    # 漏洞信息
    vulnerability_type = Column(String(256), nullable=False)
    cve_id = Column(String(20), nullable=True)
    cvss_score = Column(String(10), nullable=True)
    severity = Column(String(20), nullable=False, default="UNKNOWN")  # LOW, MEDIUM, HIGH, CRITICAL
    
    # 发现详情
    discovery_method = Column(String(256), nullable=False)
    target_component = Column(String(512), nullable=False)
    vulnerability_details = Column(JSON, nullable=False)
    proof_of_concept = Column(Text, nullable=True)
    
    # 验证状态
    verified = Column(Boolean, default=False, nullable=False)
    exploitable = Column(Boolean, default=False, nullable=False)
    false_positive = Column(Boolean, default=False, nullable=False)
    
    # 时间戳
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    verified_at = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f"<VulnerabilityDiscovery(id={self.id}, type='{self.vulnerability_type}', severity='{self.severity}')>"
