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
    """工具输入的基础Schema - 支持两种格式：
    1. 直接传入参数: {"target": "192.168.1.1", "ports": "1-1000"}
    2. 包装格式: {"parameters": {"target": "192.168.1.1"}, "context": {...}}
    """
    # 允许任意字段，因为不同工具的参数不同
    class Config:
        extra = "allow"
    
    # 可选字段：如果使用包装格式
    parameters: Optional[Dict[str, Any]] = Field(default=None, description="工具执行参数（包装格式）")
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
        *args,
        **kwargs
    ) -> str:
        """异步执行工具"""
        try:
            # 注意：AsyncCallbackManagerForToolRun 没有 on_tool_start/on_tool_end 方法
            # 这些方法在回调处理器中，run_manager只用于传递回调
            # 如果需要记录工具执行，应该在回调处理器中处理
            
            # LangChain可能以多种方式调用：
            # 1. _arun(parameters_dict) - 位置参数
            # 2. _arun(parameters=dict, context=dict, run_manager=obj) - 关键字参数
            # 3. _arun(target="xxx", ports="1-1000") - 直接关键字参数
            
            # 处理参数
            parameters = None
            context = None
            run_manager = None
            
            if args and len(args) > 0:
                # 位置参数：第一个是parameters
                parameters = args[0] if isinstance(args[0], dict) else {}
                if len(args) > 1:
                    context = args[1] if isinstance(args[1], dict) else None
                if len(args) > 2:
                    run_manager = args[2]
            
            # 从关键字参数中提取
            if "parameters" in kwargs:
                parameters = kwargs["parameters"]
            if "context" in kwargs:
                context = kwargs.get("context")
            if "run_manager" in kwargs:
                run_manager = kwargs.get("run_manager")
            
            # 如果没有parameters，尝试从kwargs中提取（LangChain可能直接传递工具参数）
            if not parameters:
                # 排除特殊字段，其余都是工具参数
                parameters = {k: v for k, v in kwargs.items() 
                            if k not in ["context", "run_manager", "parameters"]}
            
            # 如果parameters是None，使用空字典
            if parameters is None:
                parameters = {}
            
            # 处理参数：LangChain可能有两种格式
            # 1. 直接传入参数: {"target": "192.168.1.1", "ports": "1-1000"}
            # 2. 包装格式: {"parameters": {"target": "192.168.1.1"}, "context": {...}}
            actual_params = {}
            if isinstance(parameters, dict):
                if "parameters" in parameters and parameters["parameters"]:
                    # 包装格式：从parameters字段提取
                    actual_params = parameters["parameters"]
                else:
                    # 直接格式：排除context字段，其余都是参数
                    actual_params = {k: v for k, v in parameters.items() if k != "context"}
            
            # 如果actual_params为空，说明可能是验证错误，尝试使用整个parameters
            if not actual_params and isinstance(parameters, dict):
                actual_params = {k: v for k, v in parameters.items() if k != "context"}
            
            logger.debug(f"Tool {self.name} parsed parameters: {actual_params}")
            
            # 构建工具执行上下文
            tool_context = context or {}
            
            # 1. 从thread-local storage获取Agent的执行上下文
            try:
                agent_context = getattr(_context_storage, 'agent_context', {})
                if agent_context:
                    tool_context.update(agent_context)
                    logger.debug(f"Tool {self.name} using agent context: session_id={agent_context.get('session_id')}")
                    
                    # 从todos中查找当前工具的timeout配置
                    todos = agent_context.get("todos", [])
                    for todo in todos:
                        todo_config = todo.get("config", {})
                        todo_tool = todo_config.get("tool") or todo.get("tool")
                        # 如果todo配置的工具名称匹配，提取timeout
                        if todo_tool == self.name:
                            todo_timeout = todo_config.get("timeout")
                            if todo_timeout:
                                tool_context["timeout"] = todo_timeout
                                logger.info(f"Tool {self.name} using timeout from todo config: {todo_timeout}秒")
                                break
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
            
            # 注意：AsyncCallbackManagerForToolRun 没有 on_tool_end 方法
            # 工具执行完成，结果会在回调处理器中处理
            
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
            
            # 构建详细的工具描述，包含参数信息
            description = tool_info.get("description", f"Tool: {tool_name}")
            params_info = original_tool.get_parameters()
            
            # 添加参数说明到描述中
            if params_info:
                required = params_info.get("required", [])
                optional = params_info.get("optional", {})
                
                param_desc = "\n\n参数说明:\n"
                if required:
                    param_desc += "必需参数:\n"
                    for param in required:
                        param_desc += f"  - {param}: (必需)\n"
                
                if optional:
                    param_desc += "可选参数:\n"
                    # 处理两种格式：列表或字典
                    if isinstance(optional, list):
                        # 列表格式：["param1", "param2"]
                        for param in optional:
                            # 尝试从params_info中获取该参数的详细信息
                            param_detail = params_info.get(param, {})
                            if isinstance(param_detail, dict):
                                desc = param_detail.get("description", "")
                                param_desc += f"  - {param}: {desc}\n"
                            else:
                                param_desc += f"  - {param}\n"
                    elif isinstance(optional, dict):
                        # 字典格式：{"param1": "description1", "param2": "description2"}
                        for param, desc in optional.items():
                            param_desc += f"  - {param}: {desc}\n"
                
                description = description + param_desc
            
            # 创建LangChain Tool适配器
            langchain_tool = LangChainToolAdapter(
                name=tool_name,
                description=description,
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

