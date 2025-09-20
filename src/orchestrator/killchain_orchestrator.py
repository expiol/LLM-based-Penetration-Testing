"""
Cyber Kill Chain 编排器
负责协调各个阶段的Agent执行渗透测试流程
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from .states import KillChainState, TaskStatus, AgentType

logger = logging.getLogger(__name__)


class KillChainOrchestrator:
    """Cyber Kill Chain 编排器"""
    
    def __init__(self):
        self.current_state = KillChainState.INITIALIZED
        self.target_info: Dict[str, Any] = {}
        self.execution_history: List[Dict[str, Any]] = []
        self.agents: Dict[AgentType, Any] = {}
        self.safe_mode = True
        
    def initialize(self, target: str, safe_mode: bool = True) -> bool:
        """
        初始化渗透测试任务
        
        Args:
            target: 目标地址
            safe_mode: 安全模式
            
        Returns:
            bool: 初始化是否成功
        """
        try:
            self.target_info = {
                "target": target,
                "start_time": datetime.now().isoformat(),
                "safe_mode": safe_mode
            }
            self.safe_mode = safe_mode
            self.current_state = KillChainState.RECONNAISSANCE
            
            logger.info(f"初始化渗透测试任务: {target}, 安全模式: {safe_mode}")
            return True
            
        except Exception as e:
            logger.error(f"任务初始化失败: {e}")
            return False
    
    async def execute_kill_chain(self) -> Dict[str, Any]:
        """
        执行完整的Kill Chain流程
        
        Returns:
            Dict[str, Any]: 执行结果
        """
        try:
            logger.info("开始执行Cyber Kill Chain流程")
            
            # 按顺序执行各个阶段
            stages = [
                (KillChainState.RECONNAISSANCE, "侦察阶段"),
                (KillChainState.WEAPONIZATION, "武器化阶段"),
                (KillChainState.DELIVERY, "投递阶段"),
                (KillChainState.EXPLOITATION, "利用阶段"),
                (KillChainState.INSTALLATION, "安装阶段"),
                (KillChainState.COMMAND_CONTROL, "命令与控制阶段"),
                (KillChainState.ACTIONS_ON_OBJECTIVES, "目标行为阶段")
            ]
            
            for state, stage_name in stages:
                logger.info(f"执行{stage_name}")
                
                result = await self._execute_stage(state)
                
                self.execution_history.append({
                    "stage": stage_name,
                    "state": state.value,
                    "result": result,
                    "timestamp": datetime.now().isoformat()
                })
                
                if not result.get("success", False):
                    logger.warning(f"{stage_name}执行失败: {result.get('error', '未知错误')}")
                    # 根据配置决定是否继续执行
                    if not self._should_continue_on_failure():
                        break
            
            self.current_state = KillChainState.COMPLETED
            
            return {
                "success": True,
                "target": self.target_info["target"],
                "execution_history": self.execution_history,
                "completion_time": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Kill Chain执行失败: {e}")
            self.current_state = KillChainState.ERROR
            return {
                "success": False,
                "error": str(e),
                "execution_history": self.execution_history
            }
    
    async def _execute_stage(self, state: KillChainState) -> Dict[str, Any]:
        """
        执行特定阶段
        
        Args:
            state: 阶段状态
            
        Returns:
            Dict[str, Any]: 执行结果
        """
        try:
            # 根据状态选择对应的Agent
            agent_type = self._get_agent_type_for_state(state)
            
            if agent_type not in self.agents:
                logger.warning(f"Agent {agent_type} 未注册")
                return {
                    "success": False,
                    "error": f"Agent {agent_type} 未注册"
                }
            
            agent = self.agents[agent_type]
            
            # 执行Agent
            result = await agent.execute(self.target_info, self.execution_history)
            
            return {
                "success": True,
                "agent_type": agent_type.value,
                "result": result
            }
            
        except Exception as e:
            logger.error(f"阶段执行失败: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _get_agent_type_for_state(self, state: KillChainState) -> AgentType:
        """
        根据状态获取对应的Agent类型
        
        Args:
            state: 阶段状态
            
        Returns:
            AgentType: Agent类型
        """
        mapping = {
            KillChainState.RECONNAISSANCE: AgentType.RECON_AGENT,
            KillChainState.WEAPONIZATION: AgentType.WEAPONIZE_AGENT,
            KillChainState.DELIVERY: AgentType.DELIVERY_AGENT,
            KillChainState.EXPLOITATION: AgentType.EXPLOIT_AGENT,
            KillChainState.INSTALLATION: AgentType.INSTALL_AGENT,
            KillChainState.COMMAND_CONTROL: AgentType.C2_AGENT,
            KillChainState.ACTIONS_ON_OBJECTIVES: AgentType.OBJECTIVES_AGENT
        }
        
        return mapping.get(state, AgentType.RECON_AGENT)
    
    def _should_continue_on_failure(self) -> bool:
        """
        判断失败时是否应该继续执行
        
        Returns:
            bool: 是否继续执行
        """
        # 在安全模式下，即使失败也继续执行以收集更多信息
        return self.safe_mode
    
    def register_agent(self, agent_type: AgentType, agent: Any) -> None:
        """
        注册Agent
        
        Args:
            agent_type: Agent类型
            agent: Agent实例
        """
        self.agents[agent_type] = agent
        logger.info(f"注册Agent: {agent_type.value}")
    
    def get_status(self) -> Dict[str, Any]:
        """
        获取当前状态
        
        Returns:
            Dict[str, Any]: 状态信息
        """
        return {
            "current_state": self.current_state.value,
            "target": self.target_info.get("target", ""),
            "safe_mode": self.safe_mode,
            "execution_history": self.execution_history,
            "registered_agents": list(self.agents.keys())
        }
