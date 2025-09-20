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
                logger.info(f"开始渗透测试会话: {session_id}, 目标: {target_url}")
                
                return session_id
                
        except Exception as e:
            logger.error(f"创建渗透测试会话失败: {e}")
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
                    logger.debug(f"更新会话 {session_id} 阶段为: {stage}")
                
        except Exception as e:
            logger.error(f"更新会话阶段失败: {e}")
    
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
                    logger.info(f"会话 {session_id} 完成，状态: {'成功' if success else '失败'}")
        
        except Exception as e:
            logger.error(f"完成会话失败: {e}")
    
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
                logger.info(f"开始阶段执行: {stage_name} (ID: {stage_exec.id})")
                
                return stage_exec.id
                
        except Exception as e:
            logger.error(f"开始阶段执行失败: {e}")
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
                    logger.info(f"阶段执行 {stage_id} 完成，状态: {'成功' if success else '失败'}")
        
        except Exception as e:
            logger.error(f"完成阶段执行失败: {e}")
    
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
            logger.error(f"记录Agent日志失败: {e}")
    
    def log_tool_execution(self, session_id: str, tool_name: str, command: str,
                          parameters: Dict[str, Any] = None, stage_id: int = None,
                          tool_version: str = None, safe_mode: bool = True,
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
            logger.error(f"记录工具执行失败: {e}")
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
            logger.error(f"完成工具执行记录失败: {e}")
    
    def log_human_intervention(self, session_id: str, trigger_reason: str,
                              intervention_type: str, request_data: Dict[str, Any],
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
            logger.error(f"记录人工干预失败: {e}")
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
            logger.error(f"获取会话摘要失败: {e}")
            return {}


# 全局日志服务实例
pentest_logger = PentestLoggingService()
