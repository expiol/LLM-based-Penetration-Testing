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
    """Agent执行回调处理器 - 实时显示任务执行详情"""
    
    def __init__(self, agent_name: str, session_id: Optional[str] = None):
        self.agent_name = agent_name
        self.session_id = session_id
        self.execution_logs: List[Dict[str, Any]] = []
    
    async def on_agent_action(self, action, **kwargs):
        """当Agent执行动作时 - 实时显示"""
        tool_name = action.tool
        tool_input = action.tool_input
        
        # 构建友好的任务描述
        task_desc = self._format_task_description(tool_name, tool_input)
        # 只在工具开始执行时显示一次，避免重复刷屏
        if not hasattr(self, '_last_tool_action') or self._last_tool_action != f"{tool_name}_{task_desc}":
            print(f"\n🔧 [{self.agent_name}] 正在执行: {task_desc}", flush=True)
            self._last_tool_action = f"{tool_name}_{task_desc}"
        
        logger.info(f"Agent {self.agent_name} executing action: {tool_name}")
        self.execution_logs.append({
            "type": "action",
            "tool": tool_name,
            "input": tool_input,
            "timestamp": datetime.now().isoformat()
        })
    
    def _format_task_description(self, tool_name: str, tool_input: Any) -> str:
        """格式化任务描述，使其更易读"""
        if isinstance(tool_input, dict):
            # 处理包装格式的参数
            actual_input = tool_input.get("parameters", tool_input)
            
            # 根据工具类型生成描述
            if tool_name == "nmap" or tool_name == "nmap_scan":
                target = actual_input.get("target", tool_input.get("target", "未知目标"))
                ports = actual_input.get("ports", tool_input.get("ports", "默认端口"))
                return f"使用nmap扫描 {target} 的端口 {ports}"
            elif tool_name == "subdomain_enumeration":
                domain = actual_input.get("domain", tool_input.get("domain", "未知域名"))
                return f"枚举 {domain} 的子域名"
            elif tool_name == "sql_injection_test":
                url = actual_input.get("url", tool_input.get("url", "未知URL"))
                return f"测试 {url} 的 SQL 注入漏洞"
            else:
                # 通用描述
                params_str = ", ".join([f"{k}={v}" for k, v in actual_input.items() if k != "target"][:2])
                target = actual_input.get("target", tool_input.get("target", ""))
                if target:
                    return f"{tool_name} 处理 {target}" + (f" ({params_str})" if params_str else "")
                return f"{tool_name}" + (f" ({params_str})" if params_str else "")
        return f"{tool_name}"
    
    async def on_agent_finish(self, finish, **kwargs):
        """当Agent完成时"""
        logger.info(f"Agent {self.agent_name} finished")
        output = finish.return_values
        if output:
            result_summary = self._format_result_summary(output)
            if result_summary:
                print(f"✅ [{self.agent_name}] 完成: {result_summary}", flush=True)
        
        self.execution_logs.append({
            "type": "finish",
            "output": output,
            "timestamp": datetime.now().isoformat()
        })
    
    def _format_result_summary(self, output: Any) -> str:
        """格式化结果摘要"""
        if isinstance(output, dict):
            if "open_ports" in output:
                ports = output.get("open_ports", [])
                return f"发现 {len(ports)} 个开放端口"
            if "subdomains" in output:
                subdomains = output.get("subdomains", [])
                return f"发现 {len(subdomains)} 个子域名"
            if "vulnerabilities" in output:
                vulns = output.get("vulnerabilities", [])
                return f"发现 {len(vulns)} 个潜在漏洞"
            if "success" in output:
                return "任务执行成功" if output.get("success") else "任务执行失败"
        return ""
    
    async def on_tool_start(self, serialized: Dict[str, Any], input_str: str, **kwargs):
        """当工具开始执行时 - 实时显示（只显示一次，避免刷屏）"""
        tool_name = serialized.get('name', 'unknown')
        # 只在工具第一次启动时显示，避免重复刷屏
        tool_key = f"{tool_name}_{input_str[:50]}"
        if not hasattr(self, '_started_tools'):
            self._started_tools = set()
        if tool_key not in self._started_tools:
            print(f"  ⚙️  工具启动: {tool_name}", flush=True)
            self._started_tools.add(tool_key)
        logger.debug(f"Tool started: {tool_name}")
    
    async def on_tool_end(self, output: str, **kwargs):
        """当工具执行完成时 - 实时显示结果摘要（只显示一次）"""
        # 只显示前100个字符，避免输出过长
        output_preview = output[:100] + "..." if len(output) > 100 else output
        # 只在工具完成时显示一次
        if not hasattr(self, '_completed_tools'):
            self._completed_tools = set()
        output_key = f"{output_preview[:50]}"
        if output_key not in self._completed_tools:
            print(f"  ✓ 工具完成，结果: {output_preview}", flush=True)
            self._completed_tools.add(output_key)
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
        """创建默认的LLM - 从配置读取子Agent的LLM配置"""
        import os
        
        # 从配置读取LLM设置（已经由 build_framework_config 从 llm_runtime.json 构建）
        llm_config = self.config.get("llm", {})
        
        api_key = llm_config.get("api_key")
        base_url = llm_config.get("base_url")
        model_name = llm_config.get("model_name") or llm_config.get("model", "gpt-4")
        
        # 如果配置中没有，尝试从环境变量读取
        if not api_key:
            api_key = os.getenv("OPENAI_API_KEY")
        
        # 如果还是没有 API Key，给出友好提示
        if not api_key:
            raise ValueError(
                "未配置子Agent OpenAI API Key！\n"
                "请设置环境变量或在配置文件中配置：\n"
                "1. 环境变量: export OPENAI_API_KEY='your-key'\n"
                "2. configs/llm_runtime.json 中配置 sub_agents.api_key"
            )
        
        # 创建 ChatOpenAI 实例
        kwargs = {
            "model": model_name,
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
            # 获取当前任务的todos，以便工具可以访问timeout配置
            todos = session_context.get("todos", [])
            _context_storage.agent_context = {
                "session_id": session_id,
                "agent_type": self.agent_type.value,
                "global_context": global_context,
                "target": target_info.get("target", ""),
                "stage": session_context.get("stage", ""),
                "stage_id": session_context.get("stage_id", ""),
                "todos": todos  # 添加todos，工具可以从这里读取timeout
            }
            
            # 准备输入
            # Memory期望只有一个输入key，所以将所有信息合并到input中
            prepared_input = self._prepare_input(target_info, context)
            
            # 将target和safe_mode信息也包含在input中，而不是作为单独的key
            full_input = f"""{prepared_input}

目标: {target_info.get("target", "")}
安全模式: {'启用' if self.safe_mode else '禁用'}
"""
            
            input_data = {
                "input": full_input
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

