"""
通用数据模型
定义项目中使用的通用数据结构
"""
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    """严重程度枚举"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TaskStatus(str, Enum):
    """任务状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class BaseResponse(BaseModel):
    """基础响应模型"""
    success: bool = Field(..., description="是否成功")
    message: str = Field("", description="响应消息")
    timestamp: datetime = Field(default_factory=datetime.now, description="时间戳")
    data: Optional[Dict[str, Any]] = Field(None, description="响应数据")


class ErrorResponse(BaseResponse):
    """错误响应模型"""
    success: bool = Field(False, description="是否成功")
    error_code: str = Field("", description="错误代码")
    error_details: Optional[Dict[str, Any]] = Field(None, description="错误详情")


class VulnerabilityInfo(BaseModel):
    """漏洞信息模型"""
    id: str = Field(..., description="漏洞ID")
    name: str = Field(..., description="漏洞名称")
    description: str = Field("", description="漏洞描述")
    severity: SeverityLevel = Field(..., description="严重程度")
    cve_id: Optional[str] = Field(None, description="CVE编号")
    cvss_score: Optional[float] = Field(None, description="CVSS评分")
    affected_services: List[str] = Field(default_factory=list, description="受影响的服务")
    references: List[str] = Field(default_factory=list, description="参考链接")


class ServiceInfo(BaseModel):
    """服务信息模型"""
    port: int = Field(..., description="端口号")
    protocol: str = Field(..., description="协议")
    service_name: str = Field("", description="服务名称")
    version: str = Field("", description="版本信息")
    banner: str = Field("", description="服务横幅")
    state: str = Field("open", description="端口状态")


class ScanResult(BaseModel):
    """扫描结果模型"""
    target: str = Field(..., description="目标地址")
    scan_type: str = Field(..., description="扫描类型")
    start_time: datetime = Field(..., description="开始时间")
    end_time: Optional[datetime] = Field(None, description="结束时间")
    status: TaskStatus = Field(..., description="扫描状态")
    services: List[ServiceInfo] = Field(default_factory=list, description="发现的服务")
    vulnerabilities: List[VulnerabilityInfo] = Field(default_factory=list, description="发现的漏洞")
    raw_data: Optional[Dict[str, Any]] = Field(None, description="原始数据")


class ExploitResult(BaseModel):
    """漏洞利用结果模型"""
    target: str = Field(..., description="目标地址")
    vulnerability: str = Field(..., description="漏洞类型")
    success: bool = Field(..., description="是否成功")
    payload: str = Field("", description="使用的载荷")
    result: Dict[str, Any] = Field(default_factory=dict, description="利用结果")
    evidence: List[str] = Field(default_factory=list, description="证据")
    timestamp: datetime = Field(default_factory=datetime.now, description="时间戳")


class PayloadInfo(BaseModel):
    """载荷信息模型"""
    id: str = Field(..., description="载荷ID")
    name: str = Field(..., description="载荷名称")
    type: str = Field(..., description="载荷类型")
    content: str = Field(..., description="载荷内容")
    description: str = Field("", description="载荷描述")
    risk_level: SeverityLevel = Field(..., description="风险等级")
    safe_mode: bool = Field(True, description="安全模式")
