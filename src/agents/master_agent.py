"""
主控Agent - 统筹管理整个渗透测试流程
负责协调各个专门Agent，处理信息整合，实现自我修正和对其他Agent的修正
参考PentestGPT的设计思路
"""
import asyncio
import logging
import uuid
import json
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum

from .base_agent import BaseAgent
from ..orchestrator.states import KillChainState, TaskStatus, AgentType
from ..database.logging_service import pentest_logger, PentestLoggingService
from ..database.database import db_manager
from ..core.todo_manager import TodoManager
from ..core.agent_tool_manager import AgentToolManager, global_tool_registry


class MasterAgentState(Enum):
    """主控Agent状态"""
    INITIALIZING = "initializing"
    PLANNING = "planning"
    EXECUTING = "executing"
    MONITORING = "monitoring"
    CORRECTING = "correcting"
    COMPLETED = "completed"
    ERROR = "error"
    PAUSED = "paused"


@dataclass
class AgentMessage:
    """Agent间通信消息"""
    source_agent: str
    target_agent: str
    message_type: str
    content: Dict[str, Any]
    timestamp: datetime
    session_id: str
    stage_id: Optional[int] = None


@dataclass
class CorrectionAction:
    """修正动作"""
    agent_name: str
    correction_type: str  # RETRY, PARAMETER_ADJUSTMENT, ALTERNATIVE_METHOD, HALT
    original_action: Dict[str, Any]
    corrected_action: Dict[str, Any]
    reasoning: str
    priority: int = 1  # 1-5, 5为最高优先级


class MasterAgent(BaseAgent):
    """主控Agent - 整个渗透测试的大脑和指挥中心"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("MasterAgent", safe_mode=config.get("safe_mode", True))
        
        self.config = config
        self.state = MasterAgentState.INITIALIZING
        self.session_id: Optional[str] = None
        self.current_stage_id: Optional[int] = None
        
        # Agent管理
        self.specialized_agents: Dict[AgentType, BaseAgent] = {}
        self.agent_status: Dict[str, Dict[str, Any]] = {}
        
        # 通信和协调
        self.message_queue: List[AgentMessage] = []
        self.pending_corrections: List[CorrectionAction] = []
        self.global_context: Dict[str, Any] = {}
        
        # 日志和监控
        self.logging_service = pentest_logger
        
        # TODO管理器
        self.todo_manager = TodoManager()
        
        # 工具管理器
        self.tool_manager: Optional[AgentToolManager] = None
        
        # 回调函数
        self.callbacks: Dict[str, List[Callable]] = {
            "on_stage_start": [],
            "on_stage_complete": [],
            "on_agent_error": [],
            "on_correction_needed": [],
            "on_human_intervention": [],
            "on_todo_created": [],
            "on_todo_updated": [],
            "on_todo_completed": []
        }
        
        # 策略配置
        self.max_retry_attempts = config.get("max_retry_attempts", 3)
        self.correction_threshold = config.get("correction_threshold", 0.7)
        self.auto_correction_enabled = config.get("auto_correction_enabled", True)
        
        logger.info(f"主控Agent初始化完成 - Safe Mode: {self.safe_mode}")
        
        # 初始化工具管理器
        self._initialize_tool_manager()
    
    def register_specialized_agent(self, agent_type: AgentType, agent: BaseAgent):
        """
        注册专门Agent
        
        Args:
            agent_type: Agent类型
            agent: Agent实例
        """
        self.specialized_agents[agent_type] = agent
        self.agent_status[agent.name] = {
            "type": agent_type,
            "status": "registered",
            "last_activity": datetime.now().isoformat(),
            "error_count": 0,
            "success_count": 0
        }
        
        self.logger.info(f"注册专门Agent: {agent_type.value} - {agent.name}")
        
        # 记录到数据库
        if self.session_id:
            self.logging_service.log_agent_action(
                session_id=self.session_id,
                agent_name=self.name,
                agent_type=AgentType.RECON_AGENT,  # 主控Agent暂时用RECON_AGENT类型
                log_level="INFO",
                log_type="AGENT_REGISTRATION",
                message=f"注册专门Agent: {agent_type.value}",
                details={"agent_name": agent.name, "agent_type": agent_type.value}
            )
    
    async def start_penetration_test(self, target: str, test_options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        启动渗透测试
        
        Args:
            target: 目标URL或IP
            test_options: 测试选项配置
            
        Returns:
            Dict[str, Any]: 执行结果
        """
        try:
            self.state = MasterAgentState.INITIALIZING
            
            # 创建新的测试会话
            self.session_id = self.logging_service.start_session(
                target_url=target,
                target_info={"target": target},
                configuration=test_options or {},
                safe_mode=self.safe_mode
            )
            
            self.logger.info(f"启动渗透测试 - 目标: {target}, 会话ID: {self.session_id}")
            
            # 初始化全局上下文
            self.global_context = {
                "target": target,
                "session_id": self.session_id,
                "start_time": datetime.now().isoformat(),
                "test_options": test_options or {},
                "safe_mode": self.safe_mode,
                "discovered_services": [],
                "identified_vulnerabilities": [],
                "exploitation_results": [],
                "current_access_level": "none",
                "gathered_intelligence": {}
            }
            
            # 创建TODO列表
            await self.create_penetration_test_todos(target, test_options)
            
            # 执行渗透测试流程（基于TODO）
            result = await self._execute_todo_based_kill_chain()
            
            # 完成会话
            self.logging_service.complete_session(self.session_id, result.get("success", False))
            
            return result
            
        except Exception as e:
            self.logger.error(f"渗透测试启动失败: {e}")
            if self.session_id:
                self.logging_service.complete_session(self.session_id, False)
            
            return self.create_result(
                success=False,
                error=str(e),
                data={"session_id": self.session_id}
            )
    
    async def _execute_todo_based_kill_chain(self) -> Dict[str, Any]:
        """基于TODO列表执行杀伤链流程"""
        self.state = MasterAgentState.EXECUTING
        
        try:
            execution_results = []
            
            while True:
                # 获取下一个TODO
                next_todo = await self.todo_manager.get_next_todo()
                
                if not next_todo:
                    self.logger.info("所有TODO已执行完成")
                    break
                
                # 执行TODO
                result = await self.execute_next_todo()
                execution_results.append(result)
                
                # 检查是否应该继续
                if not result.get("success", False) and not self.safe_mode:
                    self.logger.warning("非安全模式下，TODO执行失败，停止执行")
                    break
            
            self.state = MasterAgentState.COMPLETED
            
            # 获取TODO执行总结
            todo_summary = await self.todo_manager.get_summary()
            
            return {
                "success": True,
                "session_id": self.session_id,
                "target": self.global_context["target"],
                "execution_results": execution_results,
                "todo_summary": todo_summary,
                "global_context": self.global_context,
                "completion_time": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"TODO-based Kill Chain执行失败: {e}")
            self.state = MasterAgentState.ERROR
            
            return {
                "success": False,
                "error": str(e),
                "execution_results": execution_results if 'execution_results' in locals() else [],
                "todo_summary": await self.todo_manager.get_summary()
            }
    
    async def _execute_kill_chain(self) -> Dict[str, Any]:
        """执行完整的Cyber Kill Chain流程"""
        self.state = MasterAgentState.PLANNING
        
        # 定义杀伤链阶段
        kill_chain_stages = [
            (KillChainState.RECONNAISSANCE, AgentType.RECON_AGENT, "侦察阶段"),
            (KillChainState.WEAPONIZATION, AgentType.WEAPONIZE_AGENT, "武器化阶段"),
            (KillChainState.DELIVERY, AgentType.DELIVERY_AGENT, "投递阶段"),
            (KillChainState.EXPLOITATION, AgentType.EXPLOIT_AGENT, "利用阶段"),
            (KillChainState.INSTALLATION, AgentType.INSTALL_AGENT, "安装阶段"),
            (KillChainState.COMMAND_CONTROL, AgentType.C2_AGENT, "命令控制阶段"),
            (KillChainState.ACTIONS_ON_OBJECTIVES, AgentType.OBJECTIVES_AGENT, "目标行为阶段")
        ]
        
        execution_results = []
        
        for stage, agent_type, stage_name in kill_chain_stages:
            try:
                self.state = MasterAgentState.EXECUTING
                
                # 更新会话当前阶段
                self.logging_service.update_session_stage(self.session_id, stage, TaskStatus.RUNNING)
                
                # 执行阶段
                stage_result = await self._execute_stage(stage, agent_type, stage_name)
                execution_results.append(stage_result)
                
                # 检查是否需要修正
                if not stage_result.get("success", False):
                    correction_needed = await self._analyze_correction_need(stage_result)
                    if correction_needed and self.auto_correction_enabled:
                        self.state = MasterAgentState.CORRECTING
                        correction_result = await self._apply_correction(stage_result, agent_type)
                        if correction_result.get("success", False):
                            stage_result = correction_result
                            execution_results[-1] = stage_result
                
                # 更新全局上下文
                await self._update_global_context(stage, stage_result)
                
                # 检查是否应该继续
                if not self._should_continue(stage_result):
                    self.logger.warning(f"阶段 {stage_name} 失败，停止执行")
                    break
                    
            except Exception as e:
                self.logger.error(f"阶段 {stage_name} 执行异常: {e}")
                execution_results.append({
                    "stage": stage.value,
                    "success": False,
                    "error": str(e)
                })
                
                # 在安全模式下继续执行，否则停止
                if not self.safe_mode:
                    break
        
        self.state = MasterAgentState.COMPLETED
        
        return {
            "success": True,
            "session_id": self.session_id,
            "target": self.global_context["target"],
            "execution_results": execution_results,
            "global_context": self.global_context,
            "completion_time": datetime.now().isoformat()
        }
    
    async def _execute_stage(self, stage: KillChainState, agent_type: AgentType, stage_name: str) -> Dict[str, Any]:
        """
        执行单个阶段
        
        Args:
            stage: 阶段类型
            agent_type: 负责的Agent类型
            stage_name: 阶段名称
            
        Returns:
            Dict[str, Any]: 执行结果
        """
        try:
            # 记录阶段开始
            self.current_stage_id = self.logging_service.start_stage(
                session_id=self.session_id,
                stage=stage,
                stage_name=stage_name,
                agent_type=agent_type,
                input_data=self.global_context
            )
            
            self.logger.info(f"开始执行阶段: {stage_name}")
            
            # 触发阶段开始回调
            await self._trigger_callbacks("on_stage_start", {
                "stage": stage,
                "stage_name": stage_name,
                "agent_type": agent_type
            })
            
            # 获取专门Agent
            if agent_type not in self.specialized_agents:
                error_msg = f"未注册的Agent类型: {agent_type.value}"
                self.logger.error(error_msg)
                
                self.logging_service.complete_stage(
                    stage_id=self.current_stage_id,
                    success=False,
                    error_message=error_msg
                )
                
                return self.create_result(success=False, error=error_msg)
            
            agent = self.specialized_agents[agent_type]
            
            # 准备Agent执行上下文
            agent_context = {
                "session_id": self.session_id,
                "stage_id": self.current_stage_id,
                "global_context": self.global_context.copy(),
                "previous_results": self._get_previous_results(),
                "safe_mode": self.safe_mode
            }
            
            # 执行Agent任务
            result = await agent.execute(
                target_info={"target": self.global_context["target"]},
                context=[agent_context]
            )
            
            # 记录执行结果
            success = result.get("success", False)
            self.logging_service.complete_stage(
                stage_id=self.current_stage_id,
                success=success,
                output_data=result.get("data", {}),
                error_message=result.get("error"),
                tools_used=result.get("tools_used", []),
                commands_executed=result.get("commands_executed", [])
            )
            
            # 更新Agent状态
            agent_name = agent.name
            if success:
                self.agent_status[agent_name]["success_count"] += 1
            else:
                self.agent_status[agent_name]["error_count"] += 1
            
            self.agent_status[agent_name]["last_activity"] = datetime.now().isoformat()
            
            # 触发阶段完成回调
            await self._trigger_callbacks("on_stage_complete", {
                "stage": stage,
                "result": result,
                "success": success
            })
            
            self.logger.info(f"阶段 {stage_name} 执行完成 - 成功: {success}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"阶段 {stage_name} 执行失败: {e}")
            
            if self.current_stage_id:
                self.logging_service.complete_stage(
                    stage_id=self.current_stage_id,
                    success=False,
                    error_message=str(e)
                )
            
            # 触发错误回调
            await self._trigger_callbacks("on_agent_error", {
                "stage": stage,
                "error": str(e),
                "agent_type": agent_type
            })
            
            return self.create_result(success=False, error=str(e))
    
    async def _analyze_correction_need(self, stage_result: Dict[str, Any]) -> bool:
        """
        分析是否需要修正
        
        Args:
            stage_result: 阶段执行结果
            
        Returns:
            bool: 是否需要修正
        """
        if stage_result.get("success", False):
            return False
        
        error = stage_result.get("error", "")
        
        # 可修正的错误类型
        correctable_errors = [
            "timeout",
            "connection_error", 
            "parameter_error",
            "tool_error",
            "parsing_error"
        ]
        
        # 检查错误是否可修正
        for correctable in correctable_errors:
            if correctable.lower() in error.lower():
                return True
        
        return False
    
    async def _apply_correction(self, stage_result: Dict[str, Any], agent_type: AgentType) -> Dict[str, Any]:
        """
        应用修正措施
        
        Args:
            stage_result: 失败的阶段结果
            agent_type: Agent类型
            
        Returns:
            Dict[str, Any]: 修正后的执行结果
        """
        try:
            self.logger.info(f"开始修正Agent {agent_type.value} 的执行结果")
            
            # 分析错误原因并生成修正策略
            correction_strategy = await self._generate_correction_strategy(stage_result, agent_type)
            
            # 记录修正动作
            self.logging_service.log_agent_action(
                session_id=self.session_id,
                agent_name=self.name,
                agent_type=AgentType.RECON_AGENT,  # 主控Agent
                log_level="INFO",
                log_type="CORRECTION",
                message=f"对 {agent_type.value} 应用修正策略",
                details={
                    "original_error": stage_result.get("error"),
                    "correction_strategy": correction_strategy
                }
            )
            
            # 应用修正策略
            if correction_strategy["type"] == "retry":
                return await self._retry_with_adjustments(agent_type, correction_strategy)
            elif correction_strategy["type"] == "alternative_method":
                return await self._try_alternative_method(agent_type, correction_strategy)
            elif correction_strategy["type"] == "parameter_adjustment":
                return await self._adjust_parameters(agent_type, correction_strategy)
            else:
                return stage_result
                
        except Exception as e:
            self.logger.error(f"修正应用失败: {e}")
            return stage_result
    
    async def _generate_correction_strategy(self, stage_result: Dict[str, Any], agent_type: AgentType) -> Dict[str, Any]:
        """
        生成修正策略
        
        Args:
            stage_result: 失败的阶段结果
            agent_type: Agent类型
            
        Returns:
            Dict[str, Any]: 修正策略
        """
        error = stage_result.get("error", "").lower()
        
        # 基于错误类型生成策略
        if "timeout" in error:
            return {
                "type": "parameter_adjustment",
                "adjustments": {"timeout": "increase_by_factor", "factor": 2},
                "reasoning": "增加超时时间"
            }
        elif "connection" in error:
            return {
                "type": "retry",
                "max_attempts": 3,
                "delay": 5,
                "reasoning": "网络连接问题，重试"
            }
        elif "parameter" in error or "argument" in error:
            return {
                "type": "parameter_adjustment",
                "adjustments": {"validate_params": True, "use_defaults": True},
                "reasoning": "参数错误，使用默认参数"
            }
        else:
            return {
                "type": "alternative_method",
                "reasoning": "尝试备选方法"
            }
    
    async def _update_global_context(self, stage: KillChainState, stage_result: Dict[str, Any]):
        """
        更新全局上下文
        
        Args:
            stage: 当前阶段
            stage_result: 阶段执行结果
        """
        if not stage_result.get("success", False):
            return
        
        data = stage_result.get("data", {})
        
        # 根据阶段类型更新相应的上下文信息
        if stage == KillChainState.RECONNAISSANCE:
            if "services" in data:
                self.global_context["discovered_services"].extend(data["services"])
            if "vulnerabilities" in data:
                self.global_context["identified_vulnerabilities"].extend(data["vulnerabilities"])
                
        elif stage == KillChainState.EXPLOITATION:
            if "access_gained" in data:
                self.global_context["current_access_level"] = data["access_gained"]
            if "exploitation_results" in data:
                self.global_context["exploitation_results"].append(data["exploitation_results"])
                
        # 更新gathered_intelligence
        if "intelligence" in data:
            stage_key = f"{stage.value}_intelligence"
            self.global_context["gathered_intelligence"][stage_key] = data["intelligence"]
    
    def _should_continue(self, stage_result: Dict[str, Any]) -> bool:
        """
        判断是否应该继续执行下一阶段
        
        Args:
            stage_result: 当前阶段结果
            
        Returns:
            bool: 是否继续
        """
        # 在安全模式下，即使失败也继续执行
        if self.safe_mode:
            return True
        
        # 在非安全模式下，失败则停止
        return stage_result.get("success", False)
    
    def _get_previous_results(self) -> List[Dict[str, Any]]:
        """获取之前阶段的执行结果"""
        # 这里可以从数据库中查询之前的结果
        # 简化实现，返回空列表
        return []
    
    async def _trigger_callbacks(self, event_type: str, data: Any):
        """触发回调函数"""
        if event_type in self.callbacks:
            for callback in self.callbacks[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data)
                    else:
                        callback(data)
                except Exception as e:
                    self.logger.error(f"回调函数执行失败: {e}")
    
    def register_callback(self, event_type: str, callback: Callable):
        """注册回调函数"""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
    
    async def execute(self, target_info: Dict[str, Any], context: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        BaseAgent接口实现
        """
        target = target_info.get("target")
        test_options = context[0] if context else {}
        
        return await self.start_penetration_test(target, test_options)
    
    def get_capabilities(self) -> List[str]:
        """获取主控Agent的能力列表"""
        return [
            "penetration_test_orchestration",
            "agent_coordination",
            "error_correction",
            "context_management",
            "logging_and_monitoring",
            "kill_chain_execution"
        ]
    
    def get_status(self) -> Dict[str, Any]:
        """获取当前状态"""
        return {
            "state": self.state.value,
            "session_id": self.session_id,
            "current_stage_id": self.current_stage_id,
            "registered_agents": list(self.specialized_agents.keys()),
            "agent_status": self.agent_status,
            "global_context": self.global_context,
            "pending_corrections": len(self.pending_corrections),
            "message_queue_size": len(self.message_queue)
        }
    
    async def _retry_with_adjustments(self, agent_type: AgentType, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """带调整的重试"""
        # 实现重试逻辑
        agent = self.specialized_agents[agent_type]
        # TODO: 实现具体的重试逻辑
        return self.create_result(success=False, error="重试功能待实现")
    
    async def _try_alternative_method(self, agent_type: AgentType, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """尝试备选方法"""
        # TODO: 实现备选方法逻辑
        return self.create_result(success=False, error="备选方法功能待实现")
    
    async def _adjust_parameters(self, agent_type: AgentType, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """调整参数"""
        # TODO: 实现参数调整逻辑
        return self.create_result(success=False, error="参数调整功能待实现")
    
    def _initialize_tool_manager(self):
        """初始化工具管理器"""
        try:
            # 为主控Agent创建工具管理器
            # 主控Agent使用RECON_AGENT类型作为临时解决方案
            self.tool_manager = AgentToolManager(AgentType.RECON_AGENT, self.config.get("tools", {}))
            
            # 注册到全局工具注册表
            global_tool_registry.register_agent_manager(AgentType.RECON_AGENT, self.tool_manager)
            
            # 异步初始化
            asyncio.create_task(self.tool_manager.initialize())
            
        except Exception as e:
            self.logger.error(f"工具管理器初始化失败: {e}")
    
    async def create_penetration_test_todos(self, target: str, test_options: Dict[str, Any] = None) -> bool:
        """
        创建渗透测试TODO列表
        
        Args:
            target: 目标地址
            test_options: 测试选项
            
        Returns:
            bool: 是否创建成功
        """
        try:
            # 创建主要的杀伤链TODO列表
            killchain_todos = [
                {
                    "id": "reconnaissance",
                    "title": "侦察阶段",
                    "description": f"对目标 {target} 进行信息收集和侦察",
                    "status": "pending",
                    "phase": "reconnaissance",
                    "priority": 5,
                    "estimated_duration": 1800  # 30分钟
                },
                {
                    "id": "weaponization",
                    "title": "武器化阶段",
                    "description": "基于侦察结果准备攻击载荷",
                    "status": "pending",
                    "phase": "weaponization",
                    "priority": 4,
                    "dependencies": ["reconnaissance"],
                    "estimated_duration": 900  # 15分钟
                },
                {
                    "id": "delivery",
                    "title": "投递阶段",
                    "description": "将攻击载荷投递到目标系统",
                    "status": "pending",
                    "phase": "delivery",
                    "priority": 4,
                    "dependencies": ["weaponization"],
                    "estimated_duration": 600  # 10分钟
                },
                {
                    "id": "exploitation",
                    "title": "利用阶段",
                    "description": "利用发现的漏洞获取系统访问权限",
                    "status": "pending",
                    "phase": "exploitation",
                    "priority": 5,
                    "dependencies": ["delivery"],
                    "estimated_duration": 1200  # 20分钟
                },
                {
                    "id": "installation",
                    "title": "安装阶段",
                    "description": "在目标系统安装持久化机制",
                    "status": "pending",
                    "phase": "installation",
                    "priority": 3,
                    "dependencies": ["exploitation"],
                    "estimated_duration": 600  # 10分钟
                },
                {
                    "id": "command_control",
                    "title": "命令控制阶段",
                    "description": "建立与目标系统的命令控制通道",
                    "status": "pending",
                    "phase": "command_control",
                    "priority": 4,
                    "dependencies": ["installation"],
                    "estimated_duration": 900  # 15分钟
                },
                {
                    "id": "actions_on_objectives",
                    "title": "目标行为阶段",
                    "description": "执行最终的攻击目标",
                    "status": "pending",
                    "phase": "actions_on_objectives",
                    "priority": 3,
                    "dependencies": ["command_control"],
                    "estimated_duration": 1800  # 30分钟
                }
            ]
            
            # 创建详细的侦察子任务
            recon_subtasks = [
                {
                    "id": "recon_port_scan",
                    "title": "端口扫描",
                    "description": f"使用Nmap扫描目标 {target} 的开放端口",
                    "status": "pending",
                    "phase": "reconnaissance",
                    "tool": "nmap",
                    "priority": 5,
                    "estimated_duration": 600
                },
                {
                    "id": "recon_service_detection",
                    "title": "服务识别",
                    "description": "识别开放端口上运行的服务",
                    "status": "pending",
                    "phase": "reconnaissance",
                    "tool": "nmap",
                    "priority": 4,
                    "dependencies": ["recon_port_scan"],
                    "estimated_duration": 300
                },
                {
                    "id": "recon_subdomain_enum",
                    "title": "子域名枚举",
                    "description": "枚举目标域名的子域名",
                    "status": "pending",
                    "phase": "reconnaissance",
                    "tool": "subdomain_enum",
                    "priority": 3,
                    "estimated_duration": 900
                },
                {
                    "id": "recon_dns_enum",
                    "title": "DNS枚举",
                    "description": "收集DNS记录信息",
                    "status": "pending",
                    "phase": "reconnaissance",
                    "tool": "dns_enum",
                    "priority": 3,
                    "estimated_duration": 300
                }
            ]
            
            # 创建利用阶段子任务
            exploit_subtasks = [
                {
                    "id": "exploit_web_scan",
                    "title": "Web应用扫描",
                    "description": "扫描Web应用漏洞",
                    "status": "pending",
                    "phase": "exploitation",
                    "priority": 4,
                    "dependencies": ["reconnaissance"],
                    "estimated_duration": 900
                },
                {
                    "id": "exploit_sql_injection",
                    "title": "SQL注入检测",
                    "description": "检测和利用SQL注入漏洞",
                    "status": "pending",
                    "phase": "exploitation",
                    "tool": "sql_injection",
                    "priority": 5,
                    "dependencies": ["exploit_web_scan"],
                    "estimated_duration": 600
                }
            ]
            
            # 创建TODO列表
            await self.todo_manager.create_todo_list("killchain_main", killchain_todos)
            await self.todo_manager.create_todo_list("reconnaissance_tasks", recon_subtasks)
            await self.todo_manager.create_todo_list("exploitation_tasks", exploit_subtasks)
            
            self.logger.info("渗透测试TODO列表创建完成")
            
            # 触发回调
            await self._trigger_callbacks("on_todo_created", {
                "lists": ["killchain_main", "reconnaissance_tasks", "exploitation_tasks"],
                "total_todos": len(killchain_todos) + len(recon_subtasks) + len(exploit_subtasks)
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"创建TODO列表失败: {e}")
            return False
    
    async def get_current_todos(self) -> Dict[str, Any]:
        """获取当前TODO状态"""
        try:
            # 获取所有TODO列表
            all_todos = await self.todo_manager.get_all_todos()
            
            # 获取进度信息
            progress = await self.todo_manager.get_progress()
            
            # 获取下一个待执行的TODO
            next_todo = await self.todo_manager.get_next_todo()
            
            # 获取正在进行的TODOs
            in_progress_todos = await self.todo_manager.get_todos_by_status("in_progress")
            
            return {
                "all_todos": all_todos,
                "progress": progress,
                "next_todo": next_todo,
                "in_progress_todos": in_progress_todos,
                "summary": await self.todo_manager.get_summary()
            }
            
        except Exception as e:
            self.logger.error(f"获取TODO状态失败: {e}")
            return {}
    
    async def update_todo_progress(self, todo_id: str, status: str, error_message: str = None) -> bool:
        """
        更新TODO进度
        
        Args:
            todo_id: TODO ID
            status: 新状态
            error_message: 错误信息（如果失败）
            
        Returns:
            bool: 是否更新成功
        """
        try:
            success = await self.todo_manager.update_todo_status(todo_id, status, error_message)
            
            if success:
                # 记录日志
                self.logging_service.log_agent_action(
                    session_id=self.session_id,
                    agent_name=self.name,
                    agent_type=AgentType.RECON_AGENT,  # 主控Agent暂时使用RECON_AGENT类型
                    log_level="INFO",
                    log_type="TODO_UPDATE",
                    message=f"TODO状态更新: {todo_id} -> {status}",
                    details={
                        "todo_id": todo_id,
                        "new_status": status,
                        "error_message": error_message
                    }
                )
                
                # 触发回调
                await self._trigger_callbacks("on_todo_updated", {
                    "todo_id": todo_id,
                    "status": status,
                    "error_message": error_message
                })
                
                # 如果TODO完成，触发完成回调
                if status == "completed":
                    await self._trigger_callbacks("on_todo_completed", {
                        "todo_id": todo_id
                    })
            
            return success
            
        except Exception as e:
            self.logger.error(f"更新TODO进度失败: {e}")
            return False
    
    async def execute_next_todo(self) -> Dict[str, Any]:
        """
        执行下一个待处理的TODO
        
        Returns:
            Dict[str, Any]: 执行结果
        """
        try:
            # 获取下一个TODO
            next_todo = await self.todo_manager.get_next_todo()
            
            if not next_todo:
                return self.create_result(
                    success=True,
                    data={"message": "没有待执行的TODO"}
                )
            
            todo_id = next_todo["id"]
            phase = next_todo["phase"]
            
            self.logger.info(f"开始执行TODO: {todo_id} - {next_todo['title']}")
            
            # 标记TODO开始执行
            await self.todo_manager.mark_todo_started(todo_id)
            
            # 根据阶段选择对应的Agent执行
            agent_type = self._get_agent_type_for_phase(phase)
            
            if agent_type not in self.specialized_agents:
                error_msg = f"未注册的Agent类型: {agent_type.value}"
                await self.todo_manager.mark_todo_failed(todo_id, error_msg)
                return self.create_result(success=False, error=error_msg)
            
            # 执行TODO
            agent = self.specialized_agents[agent_type]
            execution_context = {
                "todo_id": todo_id,
                "todo_info": next_todo,
                "session_id": self.session_id,
                "global_context": self.global_context.copy()
            }
            
            start_time = datetime.now()
            result = await agent.execute(
                target_info={"target": self.global_context.get("target")},
                context=[execution_context]
            )
            end_time = datetime.now()
            
            actual_duration = int((end_time - start_time).total_seconds())
            
            # 更新TODO状态
            if result.get("success", False):
                await self.todo_manager.mark_todo_completed(todo_id, actual_duration)
                self.logger.info(f"TODO执行成功: {todo_id}")
            else:
                error_msg = result.get("error", "执行失败")
                await self.todo_manager.mark_todo_failed(todo_id, error_msg)
                self.logger.error(f"TODO执行失败: {todo_id} - {error_msg}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"执行TODO失败: {e}")
            return self.create_result(success=False, error=str(e))
    
    def _get_agent_type_for_phase(self, phase: str) -> AgentType:
        """根据阶段获取对应的Agent类型"""
        mapping = {
            "reconnaissance": AgentType.RECON_AGENT,
            "weaponization": AgentType.WEAPONIZE_AGENT,
            "delivery": AgentType.DELIVERY_AGENT,
            "exploitation": AgentType.EXPLOIT_AGENT,
            "installation": AgentType.INSTALL_AGENT,
            "command_control": AgentType.C2_AGENT,
            "actions_on_objectives": AgentType.OBJECTIVES_AGENT
        }
        return mapping.get(phase, AgentType.RECON_AGENT)
    
    async def export_todo_report(self, filename: str = None) -> str:
        """
        导出TODO报告
        
        Args:
            filename: 文件名（可选）
            
        Returns:
            str: 文件路径
        """
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"pentest_todos_{timestamp}.json"
            
            success = await self.todo_manager.export_todos(filename)
            
            if success:
                self.logger.info(f"TODO报告导出成功: {filename}")
                return filename
            else:
                raise Exception("导出失败")
                
        except Exception as e:
            self.logger.error(f"导出TODO报告失败: {e}")
            raise
