"""
基础Agent类
定义所有Agent的通用接口和基础功能
"""
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..core.agent_tool_manager import AgentToolManager, global_tool_registry
from ..orchestrator.states import AgentType

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """基础Agent抽象类"""
    
    def __init__(self, name: str, safe_mode: bool = True, agent_type: AgentType = None):
        self.name = name
        self.safe_mode = safe_mode
        self.agent_type = agent_type
        self.logger = logging.getLogger(f"agent.{name}")
        
        # 工具管理器
        self.tool_manager: Optional[AgentToolManager] = None
        
        # 如果指定了agent_type，初始化工具管理器
        if agent_type:
            self._initialize_tool_manager()
        
    @abstractmethod
    async def execute(self, target_info: Dict[str, Any], context: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        执行Agent任务
        
        Args:
            target_info: 目标信息
            context: 执行上下文（历史记录）
            
        Returns:
            Dict[str, Any]: 执行结果
        """
        pass
    
    @abstractmethod
    def get_capabilities(self) -> List[str]:
        """
        获取Agent能力列表
        
        Returns:
            List[str]: 能力列表
        """
        pass
    
    def validate_input(self, target_info: Dict[str, Any]) -> bool:
        """
        验证输入参数
        
        Args:
            target_info: 目标信息
            
        Returns:
            bool: 验证是否通过
        """
        required_fields = ["target"]
        for field in required_fields:
            if field not in target_info:
                self.logger.error(f"缺少必需字段: {field}")
                return False
        return True
    
    def log_execution(self, action: str, result: Dict[str, Any]) -> None:
        """
        记录执行日志
        
        Args:
            action: 执行动作
            result: 执行结果
        """
        self.logger.info(f"执行动作: {action}")
        self.logger.debug(f"执行结果: {result}")
    
    def create_result(self, success: bool, data: Dict[str, Any] = None, error: str = None) -> Dict[str, Any]:
        """
        创建标准化的执行结果
        
        Args:
            success: 是否成功
            data: 结果数据
            error: 错误信息
            
        Returns:
            Dict[str, Any]: 标准化结果
        """
        result = {
            "agent": self.name,
            "success": success,
            "timestamp": datetime.now().isoformat(),
            "safe_mode": self.safe_mode
        }
        
        if data:
            result["data"] = data
        
        if error:
            result["error"] = error
            
        return result
    
    def _initialize_tool_manager(self):
        """初始化工具管理器"""
        try:
            if self.agent_type:
                self.tool_manager = AgentToolManager(self.agent_type, {})
                global_tool_registry.register_agent_manager(self.agent_type, self.tool_manager)
                self.logger.info(f"工具管理器初始化完成 - Agent类型: {self.agent_type.value}")
        except Exception as e:
            self.logger.error(f"工具管理器初始化失败: {e}")
    
    async def initialize_tools(self):
        """初始化工具（异步方法）"""
        if self.tool_manager:
            try:
                await self.tool_manager.initialize()
                self.logger.info("工具初始化完成")
            except Exception as e:
                self.logger.error(f"工具初始化失败: {e}")
    
    async def execute_tool(self, tool_name: str, parameters: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        执行工具
        
        Args:
            tool_name: 工具名称
            parameters: 工具参数
            context: 执行上下文
            
        Returns:
            Dict[str, Any]: 执行结果
        """
        if not self.tool_manager:
            return self.create_result(
                success=False, 
                error="工具管理器未初始化"
            )
        
        try:
            result = await self.tool_manager.execute_tool(tool_name, parameters, context)
            
            # 记录工具执行
            self.log_execution(f"工具执行: {tool_name}", result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"工具执行失败: {e}")
            return self.create_result(
                success=False,
                error=f"工具执行失败: {str(e)}"
            )
    
    def get_available_tools(self) -> List[str]:
        """获取可用工具列表"""
        if self.tool_manager:
            return self.tool_manager.get_available_tools()
        return []
    
    def get_tools_by_capability(self, capability: str) -> List[str]:
        """根据能力获取工具列表"""
        if self.tool_manager:
            return self.tool_manager.get_tools_by_capability(capability)
        return []
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """获取工具信息"""
        if self.tool_manager:
            return self.tool_manager.get_tool_info(tool_name)
        return None
    
    def get_tool_usage_statistics(self) -> Dict[str, Any]:
        """获取工具使用统计"""
        if self.tool_manager:
            return self.tool_manager.get_tool_usage_statistics()
        return {}
    
    @abstractmethod
    def get_agent_type(self) -> AgentType:
        """
        获取Agent类型
        
        Returns:
            AgentType: Agent类型
        """
        pass
