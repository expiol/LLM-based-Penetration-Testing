"""
基于LangChain的Agent基类
使用LangChain的Agent框架替代原有的自定义Agent
"""
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from datetime import datetime

from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain.memory import ConversationBufferWindowMemory
from langchain_core.callbacks import AsyncCallbackHandler
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.language_models import BaseLLM
from langchain_openai import ChatOpenAI

from ..orchestrator.states import AgentType
from .tools_adapter import langchain_tool_registry, LangChainToolAdapter

logger = logging.getLogger(__name__)


class AgentCallbackHandler(AsyncCallbackHandler):
    """Agent执行回调处理器"""
    
    def __init__(self, agent_name: str, session_id: Optional[str] = None):
        self.agent_name = agent_name
        self.session_id = session_id
        self.execution_logs: List[Dict[str, Any]] = []
    
    async def on_agent_action(self, action, **kwargs):
        """当Agent执行动作时"""
        logger.info(f"Agent {self.agent_name} executing action: {action.tool}")
        self.execution_logs.append({
            "type": "action",
            "tool": action.tool,
            "input": action.tool_input,
            "timestamp": datetime.now().isoformat()
        })
    
    async def on_agent_finish(self, finish, **kwargs):
        """当Agent完成时"""
        logger.info(f"Agent {self.agent_name} finished")
        self.execution_logs.append({
            "type": "finish",
            "output": finish.return_values,
            "timestamp": datetime.now().isoformat()
        })
    
    async def on_tool_start(self, serialized: Dict[str, Any], input_str: str, **kwargs):
        """当工具开始执行时"""
        logger.debug(f"Tool started: {serialized.get('name')}")
    
    async def on_tool_end(self, output: str, **kwargs):
        """当工具执行完成时"""
        logger.debug(f"Tool completed: {output[:100]}")


class LangChainBaseAgent(ABC):
    """
    基于LangChain的Agent基类
    所有Agent都继承此类
    """
    
    def __init__(
        self,
        name: str,
        agent_type: AgentType,
        llm: Optional[BaseLLM] = None,
        safe_mode: bool = True,
        config: Optional[Dict[str, Any]] = None
    ):
        self.name = name
        self.agent_type = agent_type
        self.safe_mode = safe_mode
        self.config = config or {}
        self.logger = logging.getLogger(f"langchain_agent.{name}")
        
        # LLM配置
        self.llm = llm or self._create_default_llm()
        
        # Memory配置
        self.memory = ConversationBufferWindowMemory(
            memory_key="chat_history",
            return_messages=True,
            k=10  # 保留最近10轮对话
        )
        
        # 获取该Agent可用的工具
        self.tools = self._get_agent_tools()
        
        # 创建Prompt模板
        self.prompt = self._create_prompt()
        
        # 创建Agent Executor
        self.agent_executor: Optional[AgentExecutor] = None
        
        # 回调处理器
        self.callback_handler: Optional[AgentCallbackHandler] = None
        
        # 初始化状态
        self._initialized = False
        
        # 当前执行上下文（供工具调用时使用）
        self._current_session_id: Optional[str] = None
        self._current_global_context: Dict[str, Any] = {}
        self._current_target_info: Dict[str, Any] = {}
    
    def _create_default_llm(self) -> BaseLLM:
        """创建默认的LLM"""
        import os
        import json
        from pathlib import Path
        
        # 从配置读取LLM设置
        llm_config = self.config.get("llm", {})
        
        # 尝试从 llm_runtime.json 读取 API Key
        api_key = llm_config.get("api_key")
        base_url = llm_config.get("base_url")
        
        if not api_key:
            # 尝试从环境变量读取
            api_key = os.getenv("OPENAI_API_KEY")
        
        if not api_key:
            # 尝试从 llm_runtime.json 读取
            try:
                runtime_config_path = Path(__file__).parent.parent.parent / "configs" / "llm_runtime.json"
                if runtime_config_path.exists():
                    with open(runtime_config_path) as f:
                        runtime_config = json.load(f)
                        api_key = runtime_config.get("api_key")
                        
                        # 构建 base_url
                        if not base_url and runtime_config.get("host"):
                            protocol = runtime_config.get("protocol", "https")
                            host = runtime_config.get("host")
                            port = runtime_config.get("port", 443)
                            base_url = f"{protocol}://{host}:{port}/v1"
            except Exception as e:
                self.logger.warning(f"Failed to read llm_runtime.json: {e}")
        
        # 如果还是没有 API Key，给出友好提示
        if not api_key:
            raise ValueError(
                "未配置 OpenAI API Key！\n"
                "请设置环境变量或在配置文件中配置：\n"
                "1. 环境变量: export OPENAI_API_KEY='your-key'\n"
                "2. configs/framework_config.yaml 中配置 llm.api_key\n"
                "3. configs/llm_runtime.json 中配置 api_key"
            )
        
        # 创建 ChatOpenAI 实例
        kwargs = {
            "model": llm_config.get("model", "gpt-4"),
            "temperature": llm_config.get("temperature", 0.7),
            "max_tokens": llm_config.get("max_tokens", 2048),
            "api_key": api_key
        }
        
        if base_url:
            kwargs["base_url"] = base_url
        
        return ChatOpenAI(**kwargs)
    
    def _get_agent_tools(self) -> List[LangChainToolAdapter]:
        """获取Agent可用的工具"""
        # 延迟获取工具，因为在Ray Actor中，工具可能需要在初始化时重新注册
        tools = langchain_tool_registry.get_tools_for_agent(self.agent_type)
        if not tools:
            self.logger.warning(f"Agent {self.name} has no tools available. Tools may not be registered yet.")
            # 在Ray Actor中，可能需要重新注册工具
            # 尝试从全局工具注册表重新注册
            try:
                from ..core.agent_tool_manager import global_tool_registry
                tool_manager = global_tool_registry.agent_managers.get(self.agent_type)
                if tool_manager:
                    # 重新注册工具管理器到LangChain工具注册表
                    langchain_tool_registry.register_tool_manager(self.agent_type, tool_manager)
                    tools = langchain_tool_registry.get_tools_for_agent(self.agent_type)
                    if tools:
                        self.logger.info(f"Agent {self.name} tools re-registered, loaded {len(tools)} tools")
            except Exception as e:
                self.logger.debug(f"Failed to re-register tools: {e}")
        else:
            self.logger.info(f"Agent {self.name} loaded {len(tools)} tools: {[t.name for t in tools]}")
        return tools
    
    @abstractmethod
    def _create_prompt(self) -> ChatPromptTemplate:
        """
        创建Agent的Prompt模板
        每个具体Agent需要实现此方法
        """
        pass
    
    @abstractmethod
    def get_system_prompt(self) -> str:
        """
        获取Agent的系统提示词
        每个具体Agent需要实现此方法
        """
        pass
    
    async def initialize(self):
        """初始化Agent"""
        if self._initialized:
            return
        
        try:
            # 创建Agent
            agent = create_openai_tools_agent(
                llm=self.llm,
                tools=self.tools,
                prompt=self.prompt
            )
            
            # 创建Agent Executor
            self.agent_executor = AgentExecutor(
                agent=agent,
                tools=self.tools,
                memory=self.memory,
                verbose=True,
                max_iterations=10,
                max_execution_time=300,  # 5分钟超时
                handle_parsing_errors=True
            )
            
            self._initialized = True
            self.logger.info(f"Agent {self.name} initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Agent {self.name} initialization failed: {e}")
            raise
    
    async def execute(self, target_info: Dict[str, Any], context: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        执行Agent任务
        
        Args:
            target_info: 目标信息
            context: 执行上下文
            
        Returns:
            Dict[str, Any]: 执行结果
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # 提取session_id和全局上下文
            session_context = context[0] if context else {}
            session_id = session_context.get("session_id")
            global_context = session_context.get("global_context", {})
            
            # 创建回调处理器
            self.callback_handler = AgentCallbackHandler(self.name, session_id)
            
            # 保存执行上下文到类属性和thread-local storage，供工具调用时使用
            self._current_session_id = session_id
            self._current_global_context = global_context
            self._current_target_info = target_info
            
            # 设置thread-local context（供工具调用时使用）
            from .tools_adapter import _context_storage
            _context_storage.agent_context = {
                "session_id": session_id,
                "agent_type": self.agent_type.value,
                "global_context": global_context,
                "target": target_info.get("target", ""),
                "stage": session_context.get("stage", ""),
                "stage_id": session_context.get("stage_id", "")
            }
            
            # 准备输入
            input_data = {
                "input": self._prepare_input(target_info, context),
                "target": target_info.get("target", ""),
                "safe_mode": self.safe_mode
            }
            
            # 执行Agent
            self.logger.info(f"Agent {self.name} starting execution for target: {target_info.get('target', 'unknown')}")
            if session_id:
                self.logger.info(f"Session ID: {session_id}")
            
            result = await self.agent_executor.ainvoke(
                input_data,
                config={
                    "callbacks": [self.callback_handler],
                    "metadata": {
                        "session_id": session_id,
                        "agent_type": self.agent_type.value
                    }
                }
            )
            
            # 处理结果
            execution_result = self._process_result(result, target_info, context)
            
            # 清理thread-local context
            try:
                from .tools_adapter import _context_storage
                if hasattr(_context_storage, 'agent_context'):
                    delattr(_context_storage, 'agent_context')
            except:
                pass
            
            return execution_result
            
        except Exception as e:
            self.logger.error(f"Agent {self.name} execution failed: {e}", exc_info=True)
            
            # 清理thread-local context（即使出错也要清理）
            try:
                from .tools_adapter import _context_storage
                if hasattr(_context_storage, 'agent_context'):
                    delattr(_context_storage, 'agent_context')
            except:
                pass
            
            return self.create_result(success=False, error=str(e))
    
    def _prepare_input(self, target_info: Dict[str, Any], context: List[Dict[str, Any]]) -> str:
        """准备Agent输入"""
        target = target_info.get("target", "")
        session_context = context[0] if context else {}
        
        # 获取任务列表
        todos = session_context.get("todos", [])
        stage_config = session_context.get("stage_config", {})
        stage = session_context.get("stage", "")
        
        # 构建任务描述
        tasks_description = ""
        if todos:
            tasks_description = "\n\n需要执行的任务列表:\n"
            for idx, todo in enumerate(todos, 1):
                todo_name = todo.get("name", todo.get("title", "未命名任务"))
                todo_desc = todo.get("description", "")
                todo_tool = todo.get("tool", "")
                tasks_description += f"{idx}. {todo_name}"
                if todo_desc:
                    tasks_description += f": {todo_desc}"
                if todo_tool:
                    tasks_description += f" (使用工具: {todo_tool})"
                tasks_description += "\n"
        
        # 构建阶段配置信息
        config_info = ""
        if stage_config:
            config_info = f"\n阶段配置信息:\n{json.dumps(stage_config, ensure_ascii=False, indent=2)}\n"
        
        input_text = f"""
目标: {target}
阶段: {stage}
安全模式: {'启用' if self.safe_mode else '禁用'}
{tasks_description}
{config_info}
请根据你的职责和上述任务列表，使用可用工具完成相应的渗透测试任务。

可用工具: {', '.join([tool.name for tool in self.tools])}

请按照任务列表的顺序执行，每个任务完成后报告结果。
        """.strip()
        
        return input_text
    
    def _process_result(
        self,
        result: Dict[str, Any],
        target_info: Dict[str, Any],
        context: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """处理Agent执行结果"""
        output = result.get("output", "")
        
        # 判断是否成功
        success = not ("error" in output.lower() or "failed" in output.lower())
        
        return self.create_result(
            success=success,
            data={
                "output": output,
                "execution_logs": self.callback_handler.execution_logs if self.callback_handler else [],
                "tools_used": [log["tool"] for log in (self.callback_handler.execution_logs if self.callback_handler else []) if log["type"] == "action"]
            },
            error=None if success else output
        )
    
    def create_result(self, success: bool, data: Dict[str, Any] = None, error: str = None) -> Dict[str, Any]:
        """创建标准化的执行结果"""
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
    
    def get_capabilities(self) -> List[str]:
        """获取Agent能力列表"""
        return [tool.name for tool in self.tools]
    
    def get_agent_type(self) -> AgentType:
        """获取Agent类型"""
        return self.agent_type

