"""
自动化渗透测试框架
整合 LangChain（Agent层）+ Ray（执行层）
"""
import asyncio
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

from ..agents.base_agent import LangChainBaseAgent
from ..agents.recon_agent import LangChainReconAgent
from ..agents.tools_adapter import langchain_tool_registry
from ..core.master_controller import RayMasterController
from ..core.agent_tool_manager import global_tool_registry
from ..database.database import db_manager

logger = logging.getLogger(__name__)


class AutoPentestFramework:
    """
    自动化渗透测试框架
    基于 LangChain + Ray 的架构
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("auto_framework")
        
        # Ray Master Controller
        self.master_controller: Optional[RayMasterController] = None
        
        # Agent实例
        self.agents: Dict[str, LangChainBaseAgent] = {}
        
        # 初始化标志
        self._initialized = False
    
    async def initialize(self):
        """初始化框架"""
        if self._initialized:
            return
        
        try:
            from ..core.execution_manager import get_execution_manager
            
            self.logger.info("Initializing AutoPentestFramework...")
            
            # 初始化执行管理器
            execution_manager = get_execution_manager()
            execution_manager.initialize()
            
            # 1. 初始化数据库
            if db_manager.SessionLocal is None:
                self.logger.info("Initializing database...")
                success = await execution_manager.run_in_thread(db_manager.initialize)
                if not success:
                    raise RuntimeError("Database initialization failed")
                self.logger.info("✅ Database initialized")
            
            # 2. 初始化Ray（通过执行管理器，线程安全）
            self.logger.info("Initializing Ray...")
            ray_config = self.config.get("ray", {})
            def _init_ray():
                execution_manager.initialize_ray(ray_config)
            await execution_manager.run_in_thread(_init_ray, timeout=60.0)
            
            # 3. 初始化Ray Master Controller
            self.logger.info("Initializing Ray Master Controller...")
            def _init_ray_controller():
                self.master_controller = RayMasterController(self.config)
            
            await execution_manager.run_in_thread(_init_ray_controller, timeout=60.0)
            self.logger.info("✅ Ray Master Controller initialized")
            
            # 3. 创建和初始化工具管理器（必须在Agent创建之前）
            self.logger.info("Creating and initializing tool managers...")
            await self._create_and_initialize_tool_managers()
            self.logger.info("✅ Tool managers initialized")
            
            # 4. 注册工具到LangChain
            self.logger.info("Registering tools to LangChain...")
            await self._register_tools()
            self.logger.info("✅ Tools registered")
            
            # 5. 创建和注册Agent
            self.logger.info("Creating and registering agents...")
            await self._create_and_register_agents()
            self.logger.info("✅ Agents registered")
            
            self._initialized = True
            self.logger.info("✅ AutoPentestFramework initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Framework initialization failed: {e}")
            raise
    
    async def _create_and_initialize_tool_managers(self):
        """创建并初始化所有Agent的工具管理器"""
        try:
            from ..core.agent_tool_manager import AgentToolManager
            from ..orchestrator.states import AgentType
            
            # 为每个Agent类型创建工具管理器
            agent_types = [
                AgentType.RECON_AGENT,
                AgentType.WEAPONIZE_AGENT,
                AgentType.DELIVERY_AGENT,
                AgentType.EXPLOIT_AGENT,
                AgentType.INSTALL_AGENT,
                AgentType.C2_AGENT,
                AgentType.OBJECTIVES_AGENT
            ]
            
            for agent_type in agent_types:
                try:
                    # 获取Agent配置
                    agent_config_key = agent_type.value.lower().replace("_agent", "")
                    agent_config = self.config.get("agents", {}).get(agent_config_key, {})
                    
                    # 创建工具管理器
                    tool_manager = AgentToolManager(agent_type, agent_config)
                    
                    # 初始化工具管理器（加载工具）
                    await tool_manager.initialize()
                    
                    # 注册到全局工具注册表
                    global_tool_registry.register_agent_manager(agent_type, tool_manager)
                    
                    self.logger.info(f"✅ Tool manager for {agent_type.value} initialized")
                    
                except Exception as e:
                    self.logger.warning(f"Failed to initialize tool manager for {agent_type.value}: {e}")
                    # 继续初始化其他Agent的工具管理器
                    continue
                    
        except Exception as e:
            self.logger.error(f"Tool manager creation failed: {e}")
            # 不抛出异常，允许继续初始化
    
    async def _register_tools(self):
        """注册工具到LangChain工具注册表"""
        try:
            # 从全局工具注册表获取已注册的工具管理器
            for agent_type, tool_manager in global_tool_registry.agent_managers.items():
                langchain_tool_registry.register_tool_manager(agent_type, tool_manager)
                tool_count = len(tool_manager.get_available_tools())
                self.logger.info(f"✅ Registered {tool_count} tools for {agent_type.value}")
        except Exception as e:
            self.logger.error(f"Tool registration failed: {e}")
            # 不抛出异常，允许继续初始化
    
    async def _create_and_register_agents(self):
        """创建并注册所有Agent"""
        try:
            from ..agents.recon_agent import LangChainReconAgent
            from ..agents.weaponize_agent import LangChainWeaponizeAgent
            from ..agents.delivery_agent import LangChainDeliveryAgent
            from ..agents.exploit_agent import LangChainExploitAgent
            from ..agents.install_agent import LangChainInstallAgent
            from ..agents.c2_agent import LangChainC2Agent
            from ..agents.objectives_agent import LangChainObjectivesAgent
            from ..orchestrator.states import AgentType
            
            # Agent注册映射 - 注册所有已实现的Agent
            agent_registry = [
                {
                    "class": LangChainReconAgent,
                    "type": AgentType.RECON_AGENT,
                    "config_key": "recon"
                },
                {
                    "class": LangChainWeaponizeAgent,
                    "type": AgentType.WEAPONIZE_AGENT,
                    "config_key": "weaponize"
                },
                {
                    "class": LangChainDeliveryAgent,
                    "type": AgentType.DELIVERY_AGENT,
                    "config_key": "delivery"
                },
                {
                    "class": LangChainExploitAgent,
                    "type": AgentType.EXPLOIT_AGENT,
                    "config_key": "exploit"
                },
                {
                    "class": LangChainInstallAgent,
                    "type": AgentType.INSTALL_AGENT,
                    "config_key": "install"
                },
                {
                    "class": LangChainC2Agent,
                    "type": AgentType.C2_AGENT,
                    "config_key": "c2"
                },
                {
                    "class": LangChainObjectivesAgent,
                    "type": AgentType.OBJECTIVES_AGENT,
                    "config_key": "objectives"
                },
            ]
            
            # 注册所有可用的Agent
            for agent_info in agent_registry:
                try:
                    agent_config = self.config.get("agents", {}).get(agent_info["config_key"], {})
                    await self.master_controller.register_agent(
                        agent_class=agent_info["class"],
                        agent_type=agent_info["type"],
                        agent_config=agent_config,
                        num_cpus=agent_config.get("num_cpus", 1.0),
                        num_gpus=agent_config.get("num_gpus", 0.0)
                    )
                    
                    self.agents[agent_info["config_key"]] = agent_info["class"].__name__
                    self.logger.info(f"✅ Registered {agent_info['type'].value}")
                    
                except Exception as e:
                    self.logger.warning(f"Failed to register {agent_info['type'].value}: {e}")
                    # 继续注册其他Agent，不中断
            
            self.logger.info(f"Registered {len(self.agents)} agents total")
            
        except Exception as e:
            self.logger.error(f"Agent creation/registration failed: {e}")
            raise
    
    async def start_automated_test(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        启动自动化渗透测试
        
        Args:
            target: 目标地址
            options: 测试选项
                - safe_mode: 安全模式（默认True）
                - parallel: 并行执行（默认False）
                - max_agents: 最大并发Agent数
                
        Returns:
            Dict[str, Any]: 执行结果
        """
        print(f"🔄 start_automated_test() 被调用，target={target}, options={options}", flush=True)
        
        if not self._initialized:
            print("⚠️  框架未初始化，正在初始化...", flush=True)
            await self.initialize()
            print("✅ 框架初始化完成", flush=True)
        
        try:
            self.logger.info(f"Starting automated penetration test - Target: {target}")
            print(f"📋 开始启动渗透测试，目标: {target}", flush=True)
            
            # 确保配置选项
            options = options or {}
            options.setdefault("safe_mode", True)
            options.setdefault("parallel", False)
            print(f"📋 测试选项已设置: {options}", flush=True)
            
            # 调用Ray Master Controller执行测试
            print(f"🔄 准备调用 master_controller.start_penetration_test()...", flush=True)
            result = await self.master_controller.start_penetration_test(
                target=target,
                options=options,
                parallel=options.get("parallel", False),
                async_mode=options.get("async_mode", False)
            )
            print(f"✅ master_controller.start_penetration_test() 返回", flush=True)
            
            self.logger.info(f"Test completed - Success: {result.get('success')}")
            return result
            
        except Exception as e:
            self.logger.error(f"Automated test failed: {e}")
            print(f"❌ start_automated_test() 失败: {e}", flush=True)
            import traceback
            traceback.print_exc()
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def get_session_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取会话状态"""
        if not self.master_controller:
            return None
        return await self.master_controller.get_session_status(session_id)
    
    async def list_sessions(self) -> list:
        """列出所有会话"""
        if not self.master_controller:
            return []
        return await self.master_controller.list_sessions()
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取会话信息"""
        if not self.master_controller:
            return None
        return await self.master_controller.get_session_status(session_id)
    
    async def get_live_view(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取会话的实时视图"""
        session = await self.get_session(session_id)
        if not session:
            return None
        
        # 构建实时视图
        execution_plan = session.get("execution_plan", {})
        stages = execution_plan.get("stages", [])
        
        # 获取已完成和待执行的阶段
        completed_stages = []
        pending_stages = []
        
        results = session.get("results", [])
        completed_stage_ids = {r.get("stage_id") for r in results if r.get("success")}
        
        for stage in stages:
            stage_id = stage.get("id", "")
            if stage_id in completed_stage_ids:
                completed_stages.append(stage)
            else:
                pending_stages.append(stage)
        
        return {
            "session": session,
            "pending_stages": pending_stages,
            "completed_stages": completed_stages,
            "context": session.get("global_context")
        }
    
    async def get_all_sessions(self) -> List[Dict[str, Any]]:
        """获取所有会话"""
        if not self.master_controller:
            return []
        try:
            session_ids = await self.master_controller.list_sessions()
            sessions = []
            for session_id in session_ids:
                session = await self.get_session(session_id)
                if session:
                    sessions.append(session)
            return sessions
        except Exception as e:
            self.logger.error(f"获取所有会话失败: {e}")
            return []
    
    async def request_pause(self, session_id: str, reason: str = ""):
        """请求暂停会话"""
        if not self.master_controller:
            raise ValueError("Master controller not initialized")
        # TODO: 实现暂停逻辑
        self.logger.info(f"Request pause for session {session_id}: {reason}")
    
    async def resume_session(self, session_id: str):
        """恢复暂停的会话"""
        if not self.master_controller:
            raise ValueError("Master controller not initialized")
        # TODO: 实现恢复逻辑
        self.logger.info(f"Resume session {session_id}")
    
    async def add_operator_intel(self, session_id: str, note: str):
        """添加操作员情报"""
        if not self.master_controller:
            raise ValueError("Master controller not initialized")
        # TODO: 实现添加情报逻辑
        self.logger.info(f"Add operator intel for session {session_id}: {note}")
    
    async def replan_session(self, session_id: str, hint: str):
        """根据提示重新规划会话"""
        if not self.master_controller:
            raise ValueError("Master controller not initialized")
        # TODO: 实现重新规划逻辑
        self.logger.info(f"Replan session {session_id} with hint: {hint}")
    
    def describe(self) -> Dict[str, Any]:
        """描述框架状态"""
        return {
            "initialized": self._initialized,
            "agents": list(self.agents.keys()),
            "ray_initialized": self.master_controller is not None,
            "config": {
                "safe_mode": self.config.get("safe_mode", True),
                "parallel": self.config.get("parallel", False)
            }
        }
    
    async def shutdown(self):
        """关闭框架"""
        try:
            from ..core.execution_manager import get_execution_manager
            
            if self.master_controller:
                self.master_controller.shutdown()
            
            # 关闭执行管理器（包括 Ray 和线程池）
            execution_manager = get_execution_manager()
            execution_manager.shutdown(wait=True)
            
            self.logger.info("Framework shutdown complete")
        except Exception as e:
            self.logger.error(f"Shutdown error: {e}")
