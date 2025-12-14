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


class CredentialType(enum.Enum):
    """凭证类型"""
    PLAINTEXT = "plaintext"
    NTLM_HASH = "ntlm_hash"
    KERBEROS = "kerberos"
    SSH_KEY = "ssh_key"
    AWS = "aws"
    CERTIFICATE = "certificate"
    OTHER = "other"


class Credential(Base):
    """凭证记录（参考 harbinger 设计）"""
    __tablename__ = "credentials"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("pentest_sessions.session_id"), nullable=False, index=True)
    
    # 凭证基本信息
    credential_type = Column(Enum(CredentialType), default=CredentialType.PLAINTEXT, nullable=False)
    username = Column(String(256), nullable=True, index=True)
    domain = Column(String(256), nullable=True, index=True)
    
    # 密码/哈希信息
    password = Column(Text, nullable=True)  # 明文密码或加密存储
    ntlm_hash = Column(String(64), nullable=True)
    lm_hash = Column(String(64), nullable=True)
    aes256_key = Column(String(128), nullable=True)
    aes128_key = Column(String(64), nullable=True)
    
    # Kerberos信息
    kerberos_ticket = Column(Text, nullable=True)
    kerberos_realm = Column(String(256), nullable=True)
    
    # SSH密钥信息
    ssh_private_key = Column(Text, nullable=True)
    ssh_key_type = Column(String(50), nullable=True)
    
    # AWS凭证
    aws_access_key_id = Column(String(128), nullable=True)
    aws_secret_access_key = Column(String(256), nullable=True)
    
    # 来源信息
    source = Column(String(256), nullable=True)  # 凭证来源（如：lsass dump, config file等）
    source_host = Column(String(256), nullable=True)
    source_file = Column(String(512), nullable=True)
    
    # 验证信息
    verified = Column(Boolean, default=False, nullable=False)
    valid = Column(Boolean, nullable=True)  # 凭证是否有效
    
    # 权限级别
    privilege_level = Column(String(50), nullable=True)  # user, admin, domain_admin等
    
    # 标签
    labels = Column(JSON, nullable=True)  # 标签列表
    
    # 时间戳
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_verified_at = Column(DateTime, nullable=True)
    
    # 附加信息
    notes = Column(Text, nullable=True)
    extra_data = Column(JSON, nullable=True)  # 额外元数据
    
    def __repr__(self):
        return f"<Credential(id={self.id}, username='{self.username}', type='{self.credential_type}')>"
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（隐藏敏感信息）"""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "credential_type": self.credential_type.value if self.credential_type else None,
            "username": self.username,
            "domain": self.domain,
            "has_password": bool(self.password),
            "has_ntlm_hash": bool(self.ntlm_hash),
            "has_kerberos": bool(self.kerberos_ticket),
            "has_ssh_key": bool(self.ssh_private_key),
            "source": self.source,
            "source_host": self.source_host,
            "verified": self.verified,
            "valid": self.valid,
            "privilege_level": self.privilege_level,
            "labels": self.labels,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }


class Host(Base):
    """主机记录（参考 harbinger 设计）"""
    __tablename__ = "hosts"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("pentest_sessions.session_id"), nullable=False, index=True)
    
    # 主机标识
    ip_address = Column(String(45), nullable=False, index=True)  # 支持IPv6
    hostname = Column(String(256), nullable=True, index=True)
    mac_address = Column(String(17), nullable=True)
    mac_vendor = Column(String(256), nullable=True)
    
    # 域信息
    domain = Column(String(256), nullable=True, index=True)
    fqdn = Column(String(512), nullable=True)
    
    # 操作系统信息
    os_name = Column(String(256), nullable=True)
    os_version = Column(String(128), nullable=True)
    os_family = Column(String(50), nullable=True)  # windows, linux, macos, etc.
    
    # 主机状态
    status = Column(String(20), default="up", nullable=False)  # up, down, unknown
    
    # 角色信息
    is_domain_controller = Column(Boolean, default=False, nullable=False)
    is_dns_server = Column(Boolean, default=False, nullable=False)
    is_web_server = Column(Boolean, default=False, nullable=False)
    is_database_server = Column(Boolean, default=False, nullable=False)
    is_file_server = Column(Boolean, default=False, nullable=False)
    
    # 访问级别
    access_level = Column(String(50), nullable=True)  # none, user, admin, system
    compromised = Column(Boolean, default=False, nullable=False)
    
    # 标签
    labels = Column(JSON, nullable=True)
    
    # 时间戳
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen_at = Column(DateTime, nullable=True)
    
    # 附加信息
    notes = Column(Text, nullable=True)
    extra_data = Column(JSON, nullable=True)  # 额外元数据
    
    # 关系
    services = relationship("Service", back_populates="host", cascade="all, delete-orphan")
    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Host(id={self.id}, ip='{self.ip_address}', hostname='{self.hostname}')>"


class Port(Base):
    """端口记录"""
    __tablename__ = "ports"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    
    # 端口信息
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp", nullable=False)  # tcp, udp
    state = Column(String(20), default="open", nullable=False)  # open, closed, filtered
    
    # 服务信息（简化）
    service_name = Column(String(128), nullable=True)
    service_version = Column(String(256), nullable=True)
    
    # 时间戳
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # 关系
    host = relationship("Host", back_populates="ports")
    
    def __repr__(self):
        return f"<Port(id={self.id}, port={self.port_number}/{self.protocol}, state='{self.state}')>"


class Service(Base):
    """服务记录"""
    __tablename__ = "services"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    session_id = Column(String(36), ForeignKey("pentest_sessions.session_id"), nullable=False, index=True)
    
    # 服务信息
    service_name = Column(String(128), nullable=False, index=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(10), default="tcp", nullable=False)
    
    # 版本信息
    product = Column(String(256), nullable=True)
    version = Column(String(128), nullable=True)
    extra_info = Column(Text, nullable=True)
    
    # 服务状态
    state = Column(String(20), default="running", nullable=False)  # running, stopped, unknown
    
    # 认证信息
    requires_auth = Column(Boolean, nullable=True)
    auth_type = Column(String(50), nullable=True)  # basic, ntlm, kerberos, etc.
    
    # 潜在漏洞
    potential_vulnerabilities = Column(JSON, nullable=True)
    
    # 标签
    labels = Column(JSON, nullable=True)
    
    # 时间戳
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # 附加信息
    banner = Column(Text, nullable=True)
    fingerprint = Column(JSON, nullable=True)
    extra_data = Column(JSON, nullable=True)  # 额外元数据
    
    # 关系
    host = relationship("Host", back_populates="services")
    
    def __repr__(self):
        return f"<Service(id={self.id}, name='{self.service_name}', port={self.port})>"


class Domain(Base):
    """域信息记录"""
    __tablename__ = "domains"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("pentest_sessions.session_id"), nullable=False, index=True)
    
    # 域名信息
    short_name = Column(String(256), nullable=True, index=True)  # CONTOSO
    long_name = Column(String(512), nullable=True, index=True)   # contoso.local
    
    # 域控信息
    domain_controllers = Column(JSON, nullable=True)  # DC列表
    dns_servers = Column(JSON, nullable=True)         # DNS服务器列表
    
    # 信任关系
    trusts = Column(JSON, nullable=True)
    
    # 功能级别
    functional_level = Column(String(128), nullable=True)
    
    # 标签
    labels = Column(JSON, nullable=True)
    
    # 时间戳
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # 附加信息
    notes = Column(Text, nullable=True)
    extra_data = Column(JSON, nullable=True)  # 额外元数据
    
    def __repr__(self):
        return f"<Domain(id={self.id}, name='{self.long_name or self.short_name}')>"
    
    @property
    def name(self) -> str:
        """获取域名（优先长名称）"""
        return self.long_name or self.short_name or ""


class AttackAction(Base):
    """攻击行动记录"""
    __tablename__ = "attack_actions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("pentest_sessions.session_id"), nullable=False, index=True)
    stage_id = Column(Integer, ForeignKey("stage_executions.id"), nullable=True, index=True)
    
    # 行动信息
    action_name = Column(String(256), nullable=False)
    action_type = Column(String(50), nullable=False)  # scan, exploit, persistence, etc.
    attack_phase = Column(String(50), nullable=False)  # 攻击生命周期阶段
    
    # 命令信息
    command = Column(Text, nullable=True)
    arguments = Column(JSON, nullable=True)
    
    # 目标信息
    target_host = Column(String(256), nullable=True)
    target_port = Column(Integer, nullable=True)
    target_service = Column(String(128), nullable=True)
    
    # 执行结果
    success = Column(Boolean, nullable=True)
    output = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    
    # 摘要（LLM生成）
    summary = Column(Text, nullable=True)
    
    # 检测风险
    detection_risk = Column(Integer, nullable=True)  # 1-5
    
    # 时间戳
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    execution_time_seconds = Column(Integer, nullable=True)
    
    # 附加信息
    extra_data = Column(JSON, nullable=True)  # 额外元数据
    
    def __repr__(self):
        return f"<AttackAction(id={self.id}, name='{self.action_name}', success={self.success})>"


class Suggestion(Base):
    """建议记录（参考 harbinger）"""
    __tablename__ = "suggestions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("pentest_sessions.session_id"), nullable=False, index=True)
    
    # 建议信息
    name = Column(String(256), nullable=False)
    reason = Column(Text, nullable=False)
    priority = Column(Integer, default=3, nullable=False)  # 1-5，1最高
    
    # 关联信息
    target_host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    related_service_id = Column(Integer, ForeignKey("services.id"), nullable=True)
    related_credential_id = Column(Integer, ForeignKey("credentials.id"), nullable=True)
    
    # 执行信息
    playbook_template = Column(String(256), nullable=True)
    arguments = Column(JSON, nullable=True)
    
    # 状态
    status = Column(String(20), default="pending", nullable=False)  # pending, accepted, rejected, executed
    
    # 检测风险评估
    detection_risk = Column(Integer, nullable=True)  # 1-5
    
    # 时间戳
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    executed_at = Column(DateTime, nullable=True)
    
    # 附加信息
    notes = Column(Text, nullable=True)
    extra_data = Column(JSON, nullable=True)  # 额外元数据
    
    def __repr__(self):
        return f"<Suggestion(id={self.id}, name='{self.name}', status='{self.status}')>"
