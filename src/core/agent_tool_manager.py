"""
Agent工具管理器
为每个Agent提供私有工具集和公有工具集的管理
"""
import asyncio
import logging
import importlib
import inspect
from typing import Dict, Any, List, Optional, Type, Union
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from enum import Enum

from ..orchestrator.states import AgentType

logger = logging.getLogger(__name__)


class ToolScope(Enum):
    """工具作用域"""
    PRIVATE = "private"  # 私有工具，只能被特定Agent使用
    PUBLIC = "public"    # 公有工具，所有Agent都可以使用


class ToolInterface(ABC):
    """工具接口基类"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.logger = logging.getLogger(f"tool.{name}")
        self.scope = ToolScope.PUBLIC  # 默认为公有工具
        self.allowed_agents: List[AgentType] = []  # 允许使用的Agent类型
        
    @abstractmethod
    async def execute(self, parameters: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """执行工具"""
        pass
    
    @abstractmethod
    def get_description(self) -> str:
        """获取工具描述"""
        pass
    
    @abstractmethod
    def get_parameters(self) -> Dict[str, Any]:
        """获取工具参数"""
        pass
    
    @abstractmethod
    def get_capabilities(self) -> List[str]:
        """获取工具能力"""
        pass
    
    def validate_parameters(self, parameters: Dict[str, Any]) -> bool:
        """验证参数"""
        required_params = self.get_parameters().get("required", [])
        return all(param in parameters for param in required_params)
    
    def can_be_used_by(self, agent_type: AgentType) -> bool:
        """检查是否可以被指定Agent使用"""
        if self.scope == ToolScope.PUBLIC:
            return True
        elif self.scope == ToolScope.PRIVATE:
            return agent_type in self.allowed_agents
        return False


class AgentToolManager:
    """Agent工具管理器"""
    
    def __init__(self, agent_type: AgentType, config: Dict[str, Any]):
        self.agent_type = agent_type
        self.config = config
        self.logger = logging.getLogger(f"tool_manager.{agent_type.value}")
        
        # 工具存储
        self.private_tools: Dict[str, ToolInterface] = {}
        self.public_tools: Dict[str, ToolInterface] = {}
        
        # 工具使用历史
        self.tool_usage_history: List[Dict[str, Any]] = []
        
        # 工具分类
        self.tool_categories: Dict[str, List[str]] = {
            "scanning": [],
            "exploitation": [],
            "payload": [],
            "communication": [],
            "analysis": [],
            "utility": []
        }
        
    async def initialize(self):
        """初始化工具管理器"""
        try:
            # 加载公有工具
            await self._load_public_tools()
            
            # 加载Agent专有工具
            await self._load_private_tools()
            
            # 注册工具到分类
            self._categorize_tools()
            
            self.logger.info(f"Agent {self.agent_type.value} 工具管理器初始化完成")
            self.logger.info(f"可用工具: {len(self.get_available_tools())} 个")
            
        except Exception as e:
            self.logger.error(f"工具管理器初始化失败: {e}")
            raise
    
    async def register_tool(self, tool: ToolInterface, scope: ToolScope = ToolScope.PRIVATE) -> bool:
        """
        注册工具
        
        Args:
            tool: 工具实例
            scope: 工具作用域
            
        Returns:
            bool: 是否注册成功
        """
        try:
            tool.scope = scope
            
            if scope == ToolScope.PRIVATE:
                tool.allowed_agents = [self.agent_type]
                self.private_tools[tool.name] = tool
            elif scope == ToolScope.PUBLIC:
                self.public_tools[tool.name] = tool
            
            self.logger.info(f"工具注册成功: {tool.name} ({scope.value})")
            return True
            
        except Exception as e:
            self.logger.error(f"工具注册失败: {e}")
            return False
    
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
        try:
            tool = self._get_tool(tool_name)
            if not tool:
                return {"success": False, "error": f"工具不存在: {tool_name}"}
            
            # 检查权限
            if not tool.can_be_used_by(self.agent_type):
                return {"success": False, "error": f"Agent {self.agent_type.value} 无权使用工具 {tool_name}"}
            
            # 验证参数
            if not tool.validate_parameters(parameters):
                return {"success": False, "error": "参数验证失败"}
            
            # 添加执行上下文
            execution_context = {
                "agent_type": self.agent_type.value,
                "tool_name": tool_name,
                "timestamp": datetime.now().isoformat(),
                **(context or {})
            }
            
            # 执行工具
            start_time = datetime.now()
            result = await tool.execute(parameters, execution_context)
            end_time = datetime.now()
            
            # 记录使用历史
            usage_record = {
                "tool_name": tool_name,
                "scope": tool.scope.value,
                "parameters": parameters,
                "result": {"success": result.get("success", False)},
                "execution_time": (end_time - start_time).total_seconds(),
                "timestamp": start_time.isoformat()
            }
            self.tool_usage_history.append(usage_record)
            
            self.logger.info(f"工具执行完成: {tool_name} - 成功: {result.get('success', False)}")
            return result
            
        except Exception as e:
            self.logger.error(f"工具执行失败: {e}")
            return {"success": False, "error": str(e)}
    
    def get_available_tools(self) -> List[str]:
        """获取可用工具列表"""
        all_tools = []
        all_tools.extend(self.private_tools.keys())
        all_tools.extend(self.public_tools.keys())
        return list(set(all_tools))
    
    def get_tools_by_capability(self, capability: str) -> List[str]:
        """根据能力获取工具列表"""
        matching_tools = []
        
        for tool_dict in [self.private_tools, self.public_tools]:
            for name, tool in tool_dict.items():
                if capability in tool.get_capabilities():
                    matching_tools.append(name)
        
        return list(set(matching_tools))
    
    def get_tools_by_category(self, category: str) -> List[str]:
        """根据分类获取工具列表"""
        return self.tool_categories.get(category, [])
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """获取工具信息"""
        tool = self._get_tool(tool_name)
        if not tool:
            return None
        
        return {
            "name": tool.name,
            "scope": tool.scope.value,
            "description": tool.get_description(),
            "parameters": tool.get_parameters(),
            "capabilities": tool.get_capabilities(),
            "allowed_agents": [agent.value for agent in tool.allowed_agents],
            "can_use": tool.can_be_used_by(self.agent_type)
        }
    
    def get_tool_usage_statistics(self) -> Dict[str, Any]:
        """获取工具使用统计"""
        total_usage = len(self.tool_usage_history)
        if total_usage == 0:
            return {"total_usage": 0}
        
        # 成功率统计
        success_count = sum(1 for usage in self.tool_usage_history if usage["result"]["success"])
        success_rate = success_count / total_usage
        
        # 最常用工具
        tool_counts = {}
        for usage in self.tool_usage_history:
            tool_name = usage["tool_name"]
            tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1
        
        most_used = sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "total_usage": total_usage,
            "success_rate": success_rate,
            "most_used_tools": most_used,
            "available_tools_count": len(self.get_available_tools())
        }
    
    def _get_tool(self, tool_name: str) -> Optional[ToolInterface]:
        """获取工具实例"""
        # 按优先级查找：私有 -> 公有
        if tool_name in self.private_tools:
            return self.private_tools[tool_name]
        elif tool_name in self.public_tools:
            return self.public_tools[tool_name]
        return None
    
    async def _load_public_tools(self):
        """加载公有工具"""
        try:
            # 从配置文件或默认位置加载公有工具
            public_tools_config = self.config.get("public_tools", [])
            
            for tool_config in public_tools_config:
                tool = await self._create_tool_from_config(tool_config)
                if tool:
                    await self.register_tool(tool, ToolScope.PUBLIC)
                    
        except Exception as e:
            self.logger.error(f"加载公有工具失败: {e}")
    
    async def _load_private_tools(self):
        """加载Agent私有工具"""
        try:
            # 根据Agent类型加载特定的私有工具
            private_tools_path = f"src.tools.private.{self.agent_type.value.lower()}"
            
            try:
                module = importlib.import_module(private_tools_path)
                
                # 查找工具类
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and 
                        issubclass(obj, ToolInterface) and 
                        obj != ToolInterface):
                        
                        tool_config = self.config.get("private_tools", {}).get(name, {})
                        tool_instance = obj(tool_config)
                        await self.register_tool(tool_instance, ToolScope.PRIVATE)
                        
            except ImportError:
                self.logger.info(f"未找到 {self.agent_type.value} 的私有工具模块")
                
        except Exception as e:
            self.logger.error(f"加载私有工具失败: {e}")
    
    
    async def _create_tool_from_config(self, tool_config: Dict[str, Any]) -> Optional[ToolInterface]:
        """从配置创建工具实例"""
        try:
            module_name = tool_config.get("module")
            class_name = tool_config.get("class")
            
            if not module_name or not class_name:
                return None
            
            module = importlib.import_module(module_name)
            tool_class = getattr(module, class_name)
            
            tool_instance_config = tool_config.get("config", {})
            return tool_class(tool_instance_config)
            
        except Exception as e:
            self.logger.error(f"创建工具实例失败: {e}")
            return None
    
    def _categorize_tools(self):
        """将工具分类"""
        all_tools = {**self.private_tools, **self.public_tools}
        
        for tool_name, tool in all_tools.items():
            capabilities = tool.get_capabilities()
            
            # 根据能力将工具分类
            for capability in capabilities:
                if any(scan_keyword in capability.lower() for scan_keyword in ["scan", "recon", "discovery"]):
                    self.tool_categories["scanning"].append(tool_name)
                elif any(exploit_keyword in capability.lower() for exploit_keyword in ["exploit", "attack", "injection"]):
                    self.tool_categories["exploitation"].append(tool_name)
                elif any(payload_keyword in capability.lower() for payload_keyword in ["payload", "shell", "backdoor"]):
                    self.tool_categories["payload"].append(tool_name)
                elif any(comm_keyword in capability.lower() for comm_keyword in ["communication", "c2", "command"]):
                    self.tool_categories["communication"].append(tool_name)
                elif any(analysis_keyword in capability.lower() for analysis_keyword in ["analysis", "parse", "decode"]):
                    self.tool_categories["analysis"].append(tool_name)
                else:
                    self.tool_categories["utility"].append(tool_name)
        
        # 去重
        for category in self.tool_categories:
            self.tool_categories[category] = list(set(self.tool_categories[category]))


class GlobalToolRegistry:
    """全局工具注册表"""
    
    def __init__(self):
        self.public_tools: Dict[str, ToolInterface] = {}
        self.agent_managers: Dict[AgentType, AgentToolManager] = {}
        
    def register_public_tool(self, tool: ToolInterface):
        """注册公有工具"""
        self.public_tools[tool.name] = tool
        
        # 同步到所有Agent管理器
        for manager in self.agent_managers.values():
            asyncio.create_task(manager.register_tool(tool, ToolScope.PUBLIC))
    
    def register_agent_manager(self, agent_type: AgentType, manager: AgentToolManager):
        """注册Agent工具管理器"""
        self.agent_managers[agent_type] = manager
    
    def get_global_tool_statistics(self) -> Dict[str, Any]:
        """获取全局工具统计"""
        total_tools = len(self.public_tools)
        agent_stats = {}
        
        for agent_type, manager in self.agent_managers.items():
            agent_stats[agent_type.value] = manager.get_tool_usage_statistics()
        
        return {
            "total_public_tools": total_tools,
            "registered_agents": len(self.agent_managers),
            "agent_statistics": agent_stats
        }


# 全局工具注册表实例
global_tool_registry = GlobalToolRegistry()
