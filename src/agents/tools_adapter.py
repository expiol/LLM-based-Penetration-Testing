"""
LangChain Tools适配器
将现有的工具系统适配为LangChain Tools
"""
import logging
from typing import Any, Dict, Optional, Type
from langchain.tools import BaseTool
from langchain.callbacks.manager import CallbackManagerForToolRun, AsyncCallbackManagerForToolRun
from pydantic import BaseModel, Field
import threading

from ..core.agent_tool_manager import ToolInterface, AgentToolManager
from ..orchestrator.states import AgentType

logger = logging.getLogger(__name__)

# 全局上下文存储（使用thread-local storage）
_context_storage = threading.local()


class ToolInputSchema(BaseModel):
    """工具输入的基础Schema"""
    parameters: Dict[str, Any] = Field(description="工具执行参数")
    context: Optional[Dict[str, Any]] = Field(default=None, description="执行上下文")


class LangChainToolAdapter(BaseTool):
    """
    LangChain Tool适配器
    将现有的ToolInterface适配为LangChain BaseTool
    """
    
    name: str = Field(description="工具名称")
    description: str = Field(description="工具描述")
    args_schema: Type[BaseModel] = ToolInputSchema
    
    # 原始工具实例
    original_tool: ToolInterface = Field(exclude=True)
    
    class Config:
        arbitrary_types_allowed = True
    
    def _run(
        self,
        parameters: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        """同步执行（LangChain要求，但我们主要使用异步）"""
        from ..core.execution_manager import get_execution_manager
        
        # 使用统一的执行管理器在新事件循环中运行异步代码
        execution_manager = get_execution_manager()
        if not execution_manager._initialized:
            execution_manager.initialize()
        
        try:
            # 尝试获取当前事件循环
            asyncio.get_running_loop()
            # 如果有运行的事件循环，使用执行管理器在新线程中运行
            return execution_manager.run_in_new_loop(
                self._arun(parameters, context, run_manager)
            )
        except RuntimeError:
            # 没有运行的事件循环，可以直接使用 asyncio.run
            return asyncio.run(self._arun(parameters, context, run_manager))
    
    async def _arun(
        self,
        parameters: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> str:
        """异步执行工具"""
        try:
            if run_manager:
                await run_manager.on_tool_start(
                    {"name": self.name, "description": self.description},
                    {"parameters": parameters, "context": context}
                )
            
            # 处理参数：LangChain可能会将参数包装在parameters字段中
            actual_params = parameters
            if isinstance(parameters, dict) and "parameters" in parameters:
                actual_params = parameters["parameters"]
            
            # 构建工具执行上下文
            tool_context = context or {}
            
            # 1. 从thread-local storage获取Agent的执行上下文
            try:
                agent_context = getattr(_context_storage, 'agent_context', {})
                if agent_context:
                    tool_context.update(agent_context)
                    logger.debug(f"Tool {self.name} using agent context: session_id={agent_context.get('session_id')}")
            except:
                pass
            
            # 2. 如果参数中包含context，合并它
            if isinstance(parameters, dict) and "context" in parameters:
                param_context = parameters.get("context", {})
                if isinstance(param_context, dict):
                    tool_context.update(param_context)
            
            # 3. 确保至少有一个空的context字典
            if not tool_context:
                tool_context = {}
            
            # 调用原始工具
            logger.info(f"Tool {self.name} executing with parameters: {actual_params}")
            result = await self.original_tool.execute(actual_params, tool_context)
            
            if run_manager:
                await run_manager.on_tool_end(str(result))
            
            # 返回字符串格式的结果
            if result.get("success"):
                result_data = result.get('result') or result.get('data', {})
                if isinstance(result_data, dict):
                    # 格式化字典输出
                    import json
                    return f"Success: {json.dumps(result_data, ensure_ascii=False, indent=2)}"
                else:
                    return f"Success: {result_data}"
            else:
                error_msg = result.get('error', 'Unknown error')
                return f"Error: {error_msg}"
                
        except Exception as e:
            logger.error(f"Tool {self.name} execution failed: {e}", exc_info=True)
            if run_manager:
                await run_manager.on_tool_error(e)
            return f"Error: {str(e)}"


class LangChainToolRegistry:
    """
    LangChain工具注册表
    管理所有适配后的LangChain Tools
    """
    
    def __init__(self):
        self.tools: Dict[str, LangChainToolAdapter] = {}
        self.tool_managers: Dict[AgentType, AgentToolManager] = {}
    
    def register_tool_manager(self, agent_type: AgentType, tool_manager: AgentToolManager):
        """注册Agent的工具管理器"""
        self.tool_managers[agent_type] = tool_manager
        
        # 将工具管理器中的工具适配为LangChain Tools
        for tool_name in tool_manager.get_available_tools():
            tool_info = tool_manager.get_tool_info(tool_name)
            if tool_info:
                self._adapt_tool(tool_name, tool_manager, tool_info)
    
    def _adapt_tool(self, tool_name: str, tool_manager: AgentToolManager, tool_info: Dict[str, Any]):
        """将工具适配为LangChain Tool"""
        try:
            original_tool = tool_manager._get_tool(tool_name)
            if not original_tool:
                return
            
            # 创建LangChain Tool适配器
            langchain_tool = LangChainToolAdapter(
                name=tool_name,
                description=tool_info.get("description", f"Tool: {tool_name}"),
                original_tool=original_tool
            )
            
            self.tools[tool_name] = langchain_tool
            logger.info(f"Tool {tool_name} adapted to LangChain")
            
        except Exception as e:
            logger.error(f"Failed to adapt tool {tool_name}: {e}")
    
    def get_tools_for_agent(self, agent_type: AgentType) -> list[LangChainToolAdapter]:
        """获取特定Agent可用的工具列表"""
        tool_manager = self.tool_managers.get(agent_type)
        if not tool_manager:
            return []
        
        available_tool_names = tool_manager.get_available_tools()
        return [
            self.tools[name]
            for name in available_tool_names
            if name in self.tools
        ]
    
    def get_all_tools(self) -> list[LangChainToolAdapter]:
        """获取所有工具"""
        return list(self.tools.values())
    
    def get_tool(self, tool_name: str) -> Optional[LangChainToolAdapter]:
        """获取单个工具"""
        return self.tools.get(tool_name)


# 全局LangChain工具注册表
langchain_tool_registry = LangChainToolRegistry()

