"""
渗透测试日志记录服务
"""
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session

from .database import db_manager
from .models import (
    PenetrationTestSession, StageExecution, AgentLog, ToolExecution,
    HumanIntervention, SelfCorrection, VulnerabilityDiscovery
)
from ..orchestrator.states import KillChainState, TaskStatus, AgentType
from ..utils.i18n import t

logger = logging.getLogger(__name__)


class PentestLoggingService:
    """渗透测试日志记录服务"""
    
    def __init__(self):
        self.current_session_id: Optional[str] = None
        self.current_stage_id: Optional[int] = None
    
    def start_session(self, target_url: str, target_info: Dict[str, Any] = None, 
                     configuration: Dict[str, Any] = None, safe_mode: bool = True) -> str:
        """
        开始新的渗透测试会话
        
        Args:
            target_url: 目标URL
            target_info: 目标信息
            configuration: 配置信息
            safe_mode: 是否为安全模式
            
        Returns:
            str: 会话ID
        """
        session_id = str(uuid.uuid4())
        
        try:
            with db_manager.get_session() as db:
                session = PenetrationTestSession(
                    session_id=session_id,
                    target_url=target_url,
                    target_info=target_info or {},
                    configuration=configuration or {},
                    safe_mode=safe_mode,
                    status=TaskStatus.RUNNING,
                    current_stage=KillChainState.INITIALIZED
                )
                
                db.add(session)
                db.commit()
                
                self.current_session_id = session_id
                logger.info(t("db.session_started", session_id=session_id, target=target_url))
                
                return session_id
                
        except Exception as e:
            logger.error(t("db.create_session_failed", error=str(e)))
            raise
    
    def update_session_stage(self, session_id: str, stage: KillChainState, status: TaskStatus = None):
        """
        更新会话当前阶段
        
        Args:
            session_id: 会话ID
            stage: 当前阶段
            status: 会话状态
        """
        try:
            with db_manager.get_session() as db:
                session = db.query(PenetrationTestSession).filter(
                    PenetrationTestSession.session_id == session_id
                ).first()
                
                if session:
                    session.current_stage = stage
                    if status:
                        session.status = status
                    session.updated_at = datetime.utcnow()
                    
                    db.commit()
                    logger.debug(t("db.update_stage", session_id=session_id, stage=stage))
                
        except Exception as e:
            logger.error(t("db.update_session_stage_failed", error=str(e)))
    
    def complete_session(self, session_id: str, success: bool = True):
        """
        完成渗透测试会话
        
        Args:
            session_id: 会话ID
            success: 是否成功完成
        """
        try:
            with db_manager.get_session() as db:
                session = db.query(PenetrationTestSession).filter(
                    PenetrationTestSession.session_id == session_id
                ).first()
                
                if session:
                    session.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
                    session.completed_at = datetime.utcnow()
                    session.updated_at = datetime.utcnow()
                    
                    db.commit()
                logger.info(t("db.session_completed", 
                            session_id=session_id, 
                            status='成功' if success else '失败'))
                
        except Exception as e:
            logger.error(t("db.complete_session_failed", error=str(e)))
    def start_stage(self, session_id: str, stage: KillChainState, stage_name: str,
                   agent_type: AgentType, input_data: Dict[str, Any] = None) -> int:
        """
        开始新的阶段执行
        
        Args:
            session_id: 会话ID
            stage: 阶段类型
            stage_name: 阶段名称
            agent_type: Agent类型
            input_data: 输入数据
            
        Returns:
            int: 阶段执行ID
        """
        try:
            with db_manager.get_session() as db:
                stage_exec = StageExecution(
                    session_id=session_id,
                    stage=stage,
                    stage_name=stage_name,
                    agent_type=agent_type,
                    status=TaskStatus.RUNNING,
                    input_data=input_data or {},
                    started_at=datetime.utcnow()
                )
                
                db.add(stage_exec)
                db.commit()
                db.refresh(stage_exec)
                
                self.current_stage_id = stage_exec.id
                logger.info(t("db.start_stage_exec", stage=stage_name, id=stage_exec.id))
                
                return stage_exec.id
                
        except Exception as e:
            logger.error(t("db.start_stage_exec_failed", error=str(e)))
            raise
    
    def complete_stage(self, stage_id: int, success: bool, output_data: Dict[str, Any] = None,
                      error_message: str = None, tools_used: List[str] = None,
                      commands_executed: List[Dict[str, Any]] = None):
        """
        完成阶段执行
        
        Args:
            stage_id: 阶段执行ID
            success: 是否成功
            output_data: 输出数据
            error_message: 错误信息
            tools_used: 使用的工具列表
            commands_executed: 执行的命令列表
        """
        try:
            with db_manager.get_session() as db:
                stage_exec = db.query(StageExecution).filter(
                    StageExecution.id == stage_id
                ).first()
                
                if stage_exec:
                    stage_exec.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
                    stage_exec.output_data = output_data or {}
                    stage_exec.error_message = error_message
                    stage_exec.tools_used = tools_used or []
                    stage_exec.commands_executed = commands_executed or []
                    stage_exec.completed_at = datetime.utcnow()
                    
                    # 计算执行时间
                    if stage_exec.started_at:
                        execution_time = (datetime.utcnow() - stage_exec.started_at).total_seconds()
                        stage_exec.execution_time_seconds = int(execution_time)
                    
                    db.commit()
                logger.info(t("db.stage_exec_completed", 
                            stage_id=stage_id, 
                            status='成功' if success else '失败'))
                
        except Exception as e:
            logger.error(t("db.complete_stage_failed", error=str(e)))
    def log_agent_action(self, session_id: str, agent_name: str, agent_type: AgentType,
                        log_level: str, log_type: str, message: str,
                        details: Dict[str, Any] = None, stage_id: int = None):
        """
        记录Agent动作日志
        
        Args:
            session_id: 会话ID
            agent_name: Agent名称
            agent_type: Agent类型
            log_level: 日志级别
            log_type: 日志类型
            message: 日志消息
            details: 详细信息
            stage_id: 阶段ID
        """
        try:
            with db_manager.get_session() as db:
                agent_log = AgentLog(
                    session_id=session_id,
                    stage_id=stage_id or self.current_stage_id,
                    agent_name=agent_name,
                    agent_type=agent_type,
                    log_level=log_level,
                    log_type=log_type,
                    message=message,
                    details=details or {},
                    timestamp=datetime.utcnow()
                )
                
                db.add(agent_log)
                db.commit()
        
        except Exception as e:
            logger.error(t("db.log_agent_failed", error=str(e)))
                          risk_level: str = "LOW") -> int:
        """
        记录工具执行开始
        
        Args:
            session_id: 会话ID
            tool_name: 工具名称
            command: 执行命令
            parameters: 参数
            stage_id: 阶段ID
            tool_version: 工具版本
            safe_mode: 是否安全模式
            risk_level: 风险级别
            
        Returns:
            int: 工具执行记录ID
        """
        try:
            with db_manager.get_session() as db:
                tool_exec = ToolExecution(
                    session_id=session_id,
                    stage_id=stage_id or self.current_stage_id,
                    tool_name=tool_name,
                    tool_version=tool_version,
                    command=command,
                    parameters=parameters or {},
                    status=TaskStatus.RUNNING,
                    safe_mode=safe_mode,
                    risk_level=risk_level,
                    started_at=datetime.utcnow()
                )
                
                db.add(tool_exec)
                db.commit()
                db.refresh(tool_exec)
                
                return tool_exec.id
        
        except Exception as e:
            logger.error(t("db.tool_exec_failed", error=str(e)))
            return -1
    
    def complete_tool_execution(self, tool_exec_id: int, success: bool,
                               return_code: int = None, stdout: str = None,
                               stderr: str = None):
        """
        完成工具执行记录
        
        Args:
            tool_exec_id: 工具执行记录ID
            success: 是否成功
            return_code: 返回码
            stdout: 标准输出
            stderr: 标准错误
        """
        try:
            with db_manager.get_session() as db:
                tool_exec = db.query(ToolExecution).filter(
                    ToolExecution.id == tool_exec_id
                ).first()
                
                if tool_exec:
                    tool_exec.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
                    tool_exec.return_code = return_code
                    tool_exec.stdout = stdout
                    tool_exec.stderr = stderr
                    tool_exec.completed_at = datetime.utcnow()
                    
                    # 计算执行时间
                    if tool_exec.started_at:
                        execution_time = (datetime.utcnow() - tool_exec.started_at).total_seconds()
                        tool_exec.execution_time_seconds = int(execution_time)
                    
                    db.commit()
        
        except Exception as e:
            logger.error(t("db.complete_tool_failed", error=str(e)))
                              stage_id: int = None) -> int:
        """
        记录人工干预请求
        
        Args:
            session_id: 会话ID
            trigger_reason: 触发原因
            intervention_type: 干预类型
            request_data: 请求数据
            stage_id: 阶段ID
            
        Returns:
            int: 人工干预记录ID
        """
        try:
            with db_manager.get_session() as db:
                intervention = HumanIntervention(
                    session_id=session_id,
                    stage_id=stage_id or self.current_stage_id,
                    trigger_reason=trigger_reason,
                    intervention_type=intervention_type,
                    request_data=request_data,
                    requested_at=datetime.utcnow()
                )
                
                db.add(intervention)
                db.commit()
                db.refresh(intervention)
                
                return intervention.id
        
        except Exception as e:
            logger.error(t("db.log_intervention_failed", error=str(e)))
            return -1
    
    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """
        获取会话摘要
        
        Args:
            session_id: 会话ID
            
        Returns:
            Dict[str, Any]: 会话摘要
        """
        try:
            with db_manager.get_session() as db:
                session = db.query(PenetrationTestSession).filter(
                    PenetrationTestSession.session_id == session_id
                ).first()
                
                if not session:
                    return {}
                
                # 获取阶段执行统计
                stages = db.query(StageExecution).filter(
                    StageExecution.session_id == session_id
                ).all()
                
                # 获取日志统计
                log_count = db.query(AgentLog).filter(
                    AgentLog.session_id == session_id
                ).count()
                
                # 获取工具执行统计
                tool_count = db.query(ToolExecution).filter(
                    ToolExecution.session_id == session_id
                ).count()
                
                return {
                    "session_id": session.session_id,
                    "target_url": session.target_url,
                    "status": session.status.value,
                    "current_stage": session.current_stage.value,
                    "safe_mode": session.safe_mode,
                    "created_at": session.created_at.isoformat(),
                    "updated_at": session.updated_at.isoformat(),
                    "completed_at": session.completed_at.isoformat() if session.completed_at else None,
                    "stages_executed": len(stages),
                    "successful_stages": len([s for s in stages if s.status == TaskStatus.COMPLETED]),
                    "log_entries": log_count,
                    "tool_executions": tool_count
                }
        
        except Exception as e:
            logger.error(t("db.get_summary_failed", error=str(e)))
            return {}
    
    def get_current_executing_tasks(self, session_id: str) -> List[Dict[str, Any]]:
        """
        获取当前正在执行的任务列表
        
        Args:
            session_id: 会话ID
            
        Returns:
            List[Dict[str, Any]]: 当前执行的任务列表
        """
        try:
            with db_manager.get_session() as db:
                # 获取当前正在执行的工具
                running_tools = db.query(ToolExecution).filter(
                    ToolExecution.session_id == session_id,
                    ToolExecution.status == TaskStatus.RUNNING
                ).order_by(ToolExecution.started_at.desc()).limit(3).all()
                
                tasks = []
                for tool_exec in running_tools:
                    tool_name = tool_exec.tool_name
                    params = tool_exec.parameters or {}
                    command = tool_exec.command or ""
                    
                    # 根据工具类型生成友好的任务描述
                    task_desc = self._generate_task_description(tool_name, params, command)
                    tasks.append({
                        "tool": tool_name,
                        "description": task_desc,
                        "started_at": tool_exec.started_at.isoformat() if tool_exec.started_at else None
                    })
                
                return tasks
                
        except Exception as e:
            logger.error(t("db.get_current_task_failed", error=str(e)))
            return []
    
    def _generate_task_description(self, tool_name: str, parameters: Dict[str, Any], command: str) -> str:
        """
        根据工具名称和参数生成友好的任务描述
        
        Args:
            tool_name: 工具名称
            parameters: 工具参数
            command: 执行命令
            
        Returns:
            str: 任务描述
        """
        target = parameters.get("target") or parameters.get("domain") or "目标"
        
        if tool_name == "nmap":
            ports = parameters.get("ports", "常用端口")
            scan_type = parameters.get("scan_type", "tcp_connect")
            scan_type_name = "TCP连接扫描" if scan_type == "tcp_connect" else "TCP SYN扫描"
            return f"正在扫描 {target} 的开放端口（端口范围: {ports}，扫描类型: {scan_type_name}）"
        
        elif tool_name == "dns_enum":
            return f"正在获取 {target} 的DNS记录（A、AAAA、MX、NS、TXT等）"
        
        elif tool_name == "subdomain_enum":
            methods = parameters.get("methods", [])
            methods_str = "、".join(methods) if methods else "多种方法"
            return f"正在枚举 {target} 的子域名（方法: {methods_str}）"
        
        elif tool_name == "command_executor":
            cmd = command or parameters.get("command", "未知命令")
            return f"正在执行命令: {cmd}"
        
        else:
            # 通用描述
            if command:
                return f"正在使用 {tool_name} 执行: {command}"
            else:
                return f"正在使用 {tool_name} 处理 {target}"


# 单例日志服务，供各个 Agent 直接导入使用
pentest_logger = PentestLoggingService()
