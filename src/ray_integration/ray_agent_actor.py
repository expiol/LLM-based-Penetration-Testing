"""
Ray Agent Actor
使用Ray Actor封装LangChain Agent，支持分布式执行
"""
import logging
from typing import Any, Dict, List, Optional
import ray

from ..agents.base_agent import LangChainBaseAgent
from ..orchestrator.states import AgentType

logger = logging.getLogger(__name__)


@ray.remote
class RayAgentActor:
    """
    Ray Actor封装的Agent
    支持分布式执行和状态管理
    """
    
    def __init__(self, agent_class: type, agent_type: AgentType, config: Dict[str, Any]):
        """
        初始化 Ray Actor
        
        Args:
            agent_class: Agent 类（不是实例）
            agent_type: Agent 类型
            config: Agent 配置
        """
        self.config = config
        self.agent_type = agent_type
        self.agent_class = agent_class
        self.logger = logging.getLogger(f"ray_actor.{agent_type.value}")
        
        # Actor状态
        self.is_initialized = False
        self.execution_count = 0
        self.last_execution_time = None
        
        # 执行历史
        self.execution_history: List[Dict[str, Any]] = []
        
        # Agent实例将在initialize时创建（此时工具已注册）
        self.agent: Optional[LangChainBaseAgent] = None
    
    async def initialize(self) -> bool:
        """初始化Actor"""
        try:
            if not self.is_initialized:
                # 在Ray Actor进程中，需要重新注册工具
                await self._ensure_tools_registered()
                
                # 创建Agent实例（此时工具已注册）
                if self.agent is None:
                    self.agent = self.agent_class(self.config)
                
                # 初始化Agent
                await self.agent.initialize()
                self.is_initialized = True
                self.logger.info(f"Ray Actor for {self.agent.name} initialized")
            return True
        except Exception as e:
            self.logger.error(f"Ray Actor initialization failed: {e}", exc_info=True)
            return False
    
    async def _ensure_tools_registered(self):
        """确保工具在Ray Actor进程中已注册"""
        try:
            from ..core.agent_tool_manager import AgentToolManager, global_tool_registry
            from ..agents.tools_adapter import langchain_tool_registry
            
            # 检查工具是否已注册
            tools = langchain_tool_registry.get_tools_for_agent(self.agent_type)
            if not tools:
                # 工具未注册，需要重新创建和注册
                self.logger.info(f"Tools not registered for {self.agent_type.value} in Ray Actor, re-registering...")
                
                # 创建工具管理器
                tool_manager = AgentToolManager(self.agent_type, self.config)
                
                # 初始化工具管理器
                await tool_manager.initialize()
                
                # 注册到全局注册表
                global_tool_registry.register_agent_manager(self.agent_type, tool_manager)
                
                # 注册到LangChain工具注册表
                langchain_tool_registry.register_tool_manager(self.agent_type, tool_manager)
                
                self.logger.info(f"Tools re-registered for {self.agent_type.value} in Ray Actor")
        except Exception as e:
            self.logger.warning(f"Failed to ensure tools registered in Ray Actor: {e}", exc_info=True)
            # 不抛出异常，允许继续，Agent会在_get_agent_tools时再次尝试获取工具
    
    async def execute(self, target_info: Dict[str, Any], context: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        执行Agent任务
        
        Args:
            target_info: 目标信息
            context: 执行上下文
            
        Returns:
            Dict[str, Any]: 执行结果
        """
        if not self.is_initialized or self.agent is None:
            await self.initialize()
        
        if self.agent is None:
            return {
                "agent": self.agent_type.value,
                "success": False,
                "error": "Agent not initialized",
                "timestamp": None
            }
        
        try:
            self.execution_count += 1
            self.logger.info(f"Starting execution #{self.execution_count}")
            
            # 执行Agent
            result = await self.agent.execute(target_info, context)
            
            # 记录执行
            from datetime import datetime
            self.last_execution_time = datetime.now().isoformat()
            
            # 保存历史
            self.execution_history.append({
                "execution_id": self.execution_count,
                "timestamp": self.last_execution_time,
                "target": target_info.get("target"),
                "success": result.get("success", False),
                "error": result.get("error")
            })
            
            # 限制历史记录数量
            if len(self.execution_history) > 100:
                self.execution_history = self.execution_history[-100:]
            
            return result
            
        except Exception as e:
            self.logger.error(f"Execution failed: {e}")
            return {
                "agent": self.agent.name,
                "success": False,
                "error": str(e),
                "timestamp": self.last_execution_time
            }
    
    def get_status(self) -> Dict[str, Any]:
        """获取Actor状态"""
        return {
            "agent_name": self.agent.name if self.agent else None,
            "agent_type": self.agent_type.value,
            "is_initialized": self.is_initialized,
            "execution_count": self.execution_count,
            "last_execution_time": self.last_execution_time,
            "history_size": len(self.execution_history)
        }
    
    def get_execution_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """获取执行历史"""
        return self.execution_history[-limit:]
    
    def reset(self):
        """重置Actor状态"""
        self.execution_count = 0
        self.last_execution_time = None
        self.execution_history = []
        self.logger.info(f"Ray Actor for {self.agent.name} reset")


class RayAgentPool:
    """
    Ray Agent池
    管理多个Ray Agent Actor
    """
    
    def __init__(self, config: Dict[str, Any]):
        from ..core.execution_manager import get_execution_manager
        
        self.config = config
        self.actors: Dict[AgentType, RayAgentActor] = {}
        self.logger = logging.getLogger("ray_agent_pool")
        self.execution_manager = get_execution_manager()
    
    async def create_actor(
        self,
        agent_class: type,
        agent_type: AgentType,
        agent_config: Dict[str, Any],
        num_cpus: float = 1.0,
        num_gpus: float = 0.0
    ) -> RayAgentActor:
        """
        创建Ray Actor
        
        Args:
            agent_class: Agent类（不是实例）
            agent_type: Agent类型
            agent_config: Agent配置
            num_cpus: CPU资源
            num_gpus: GPU资源
            
        Returns:
            RayAgentActor: Actor引用
        """
        try:
            # 创建Ray Actor，指定资源
            # 传递类和配置，而不是实例（避免序列化问题）
            actor = RayAgentActor.options(
                num_cpus=num_cpus,
                num_gpus=num_gpus,
                max_concurrency=1  # 每个Actor一次只执行一个任务
            ).remote(agent_class, agent_type, agent_config)
            
            # 初始化Actor（使用执行管理器统一处理）
            init_future = actor.initialize.remote()
            await self.execution_manager.run_ray_get(init_future)
            
            # 注册到池中
            self.actors[agent_type] = actor
            
            self.logger.info(f"Created Ray Actor for {agent_type.value}")
            return actor
            
        except Exception as e:
            self.logger.error(f"Failed to create Ray Actor: {e}")
            raise
    
    def get_actor(self, agent_type: AgentType) -> Optional[RayAgentActor]:
        """获取指定类型的Actor"""
        return self.actors.get(agent_type)
    
    async def execute_parallel(
        self,
        tasks: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        并行执行多个任务
        
        Args:
            tasks: 任务列表，每个任务包含 agent_type, target_info, context
            
        Returns:
            List[Dict[str, Any]]: 执行结果列表
        """
        futures = []
        
        for task in tasks:
            agent_type = task["agent_type"]
            target_info = task["target_info"]
            context = task["context"]
            
            actor = self.get_actor(agent_type)
            if actor:
                # 异步执行
                future = actor.execute.remote(target_info, context)
                futures.append((agent_type, future))
            else:
                self.logger.warning(f"No actor found for {agent_type}")
        
        # 等待所有任务完成（使用执行管理器统一处理）
        results = []
        for agent_type, future in futures:
            try:
                result = await self.execution_manager.run_ray_get(future)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Task execution failed for {agent_type}: {e}")
                results.append({
                    "agent_type": agent_type.value,
                    "success": False,
                    "error": str(e)
                })
        
        return results
    
    async def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        """获取所有Actor的状态"""
        status = {}
        for agent_type, actor in self.actors.items():
            try:
                future = actor.get_status.remote()
                actor_status = await self.execution_manager.run_ray_get(future)
                status[agent_type.value] = actor_status
            except Exception as e:
                self.logger.error(f"Failed to get status for {agent_type}: {e}")
                status[agent_type.value] = {"error": str(e)}
        
        return status
    
    def shutdown(self):
        """关闭所有Actor"""
        for agent_type, actor in self.actors.items():
            try:
                ray.kill(actor)
                self.logger.info(f"Killed actor for {agent_type}")
            except Exception as e:
                self.logger.error(f"Failed to kill actor {agent_type}: {e}")
        
        self.actors.clear()

