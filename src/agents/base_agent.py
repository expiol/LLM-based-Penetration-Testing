"""
基于LangChain的Agent基类
使用LangChain的Agent框架替代原有的自定义Agent
"""
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from datetime import datetime
import threading

from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain.memory import ConversationBufferWindowMemory
from langchain_core.callbacks import AsyncCallbackHandler
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.language_models import BaseLLM
from langchain_openai import ChatOpenAI

from ..orchestrator.states import AgentType
from .tools_adapter import langchain_tool_registry, LangChainToolAdapter
from ..utils.llm_retry import LLMRetryHandler, InputOptimizer, invoke_with_retry
from ..utils.i18n import t

logger = logging.getLogger(__name__)


# ===== 全局执行状态管理器 =====
import json
import tempfile
import os
from pathlib import Path

# 共享状态文件路径（所有进程都可以访问）
_STATE_FILE_PATH = Path(tempfile.gettempdir()) / "pentest_execution_state.json"


class ExecutionStateManager:
    """
    全局执行状态管理器 - 用于实时UI获取当前执行信息
    使用文件共享状态，支持跨进程访问（Ray Actor 和主进程）
    """
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.show_output = True  # 是否显示输出
        self.max_output_lines = 100  # 增加输出行数
        self._data_lock = threading.Lock()
        self._state_file = _STATE_FILE_PATH
        # 初始化状态文件
        self._init_state_file()
    
    def _init_state_file(self):
        """初始化状态文件"""
        try:
            if not self._state_file.exists():
                self._write_state({
                    "agent": "",
                    "tool": "",
                    "command": "",
                    "description": "",
                    "output_lines": [],
                    "show_output": True,
                    "timestamp": ""
                })
        except Exception:
            pass
    
    def _write_state(self, state: Dict[str, Any]):
        """写入状态到文件"""
        try:
            import time
            state["timestamp"] = time.time()
            # 确保目录存在
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            # 写入临时文件然后重命名，确保原子性
            temp_file = self._state_file.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(state, f, ensure_ascii=False)
            temp_file.replace(self._state_file)
            # 调试日志
            if state.get("command") or state.get("output_lines"):
                logger.debug(t("agent.state_written", tool=state.get('tool'), lines=len(state.get('output_lines', []))))
        except Exception as e:
            logger.warning(t("agent.write_state_failed", error=str(e)))
    
    def _read_state(self) -> Dict[str, Any]:
        """从文件读取状态"""
        default_state = {
            "agent": "",
            "tool": "",
            "command": "",
            "description": "",
            "output_lines": [],
            "show_output": True
        }
        try:
            if self._state_file.exists():
                with open(self._state_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content.strip():
                        state = json.loads(content)
                        # 确保所有必要的字段都存在
                        for key in default_state:
                            if key not in state:
                                state[key] = default_state[key]
                        return state
        except json.JSONDecodeError as e:
            logger.debug(f"JSON解析失败，重置状态: {e}")
        except Exception as e:
            logger.debug(t("agent.read_state_file_failed", error=str(e)))
        return default_state
    
    def set_current_execution(self, agent: str, tool: str, command: str, description: str = ""):
        """设置当前执行的命令"""
        with self._data_lock:
            import time
            current_state = self._read_state()
            
            # 标准化Agent名称进行比较和存储
            # 统一格式为 "Recon Agent" 这样的显示格式
            def normalize_agent_name(name: str) -> str:
                """标准化agent名称用于比较"""
                if not name:
                    return ""
                # 统一转为小写，移除空格和下划线
                return name.lower().replace(" ", "").replace("_", "").replace("-", "")
            
            def format_agent_name(name: str) -> str:
                """格式化agent名称用于显示"""
                if not name:
                    return ""
                # 统一格式化为 "Recon Agent" 样式
                # 先标准化，然后格式化
                normalized = name.lower().replace("-", "_")
                # 移除多余的空格
                normalized = " ".join(normalized.split())
                # 如果是下划线格式如 recon_agent，转换为空格格式
                if "_" in normalized:
                    parts = normalized.split("_")
                    return " ".join(p.title() for p in parts)
                # 如果已经是空格格式，直接title
                return normalized.title()
            
            current_agent_normalized = normalize_agent_name(current_state.get("agent", ""))
            new_agent_normalized = normalize_agent_name(agent)
            
            # 格式化新的agent名称
            formatted_agent = format_agent_name(agent)
            
            # 如果Agent切换了（标准化后不同），添加分隔符
            if current_agent_normalized and new_agent_normalized and current_agent_normalized != new_agent_normalized:
                # Agent切换，保留之前的输出但添加分隔符
                output_lines = current_state.get("output_lines", [])
                current_formatted = format_agent_name(current_state.get("agent", ""))
                output_lines.append(f"--- {current_formatted} 执行完成，切换到 {formatted_agent} ---")
                # 限制输出行数
                if len(output_lines) > self.max_output_lines:
                    output_lines = output_lines[-self.max_output_lines:]
            else:
                # 同一Agent，保留输出
                output_lines = current_state.get("output_lines", [])
            
            state = {
                "agent": formatted_agent,  # 使用格式化后的名称
                "tool": tool,
                "command": command,
                "description": description,
                "output_lines": output_lines,  # 保留之前的输出
                "show_output": self.show_output,
                "execution_id": f"{new_agent_normalized}_{int(time.time())}"  # 使用标准化名称作为ID
            }
            self._write_state(state)
    
    def add_output_line(self, line: str):
        """添加输出行"""
        if not self.show_output:
            return
        with self._data_lock:
            # 清理行尾空白
            line = line.rstrip()
            if line:  # 只添加非空行
                state = self._read_state()
                output_lines = state.get("output_lines", [])
                output_lines.append(line)
                # 限制行数
                if len(output_lines) > self.max_output_lines:
                    output_lines = output_lines[-self.max_output_lines:]
                state["output_lines"] = output_lines
                self._write_state(state)
    
    def toggle_output(self):
        """切换输出显示"""
        with self._data_lock:
            self.show_output = not self.show_output
            state = self._read_state()
            state["show_output"] = self.show_output
            self._write_state(state)
        return self.show_output
    
    def get_state(self) -> Dict[str, Any]:
        """获取当前状态"""
        with self._data_lock:
            state = self._read_state()
            state["show_output"] = self.show_output
            return state
    
    def clear(self):
        """清除状态"""
        with self._data_lock:
            self._write_state({
                "agent": "",
                "tool": "",
                "command": "",
                "description": "",
                "output_lines": [],
                "show_output": self.show_output
            })


# 全局实例
execution_state = ExecutionStateManager()


class AgentCallbackHandler(AsyncCallbackHandler):
    """Agent执行回调处理器 - 实时更新执行状态，跟踪多轮LLM交互"""
    
    def __init__(self, agent_name: str, session_id: Optional[str] = None):
        self.agent_name = agent_name
        self.session_id = session_id
        self.execution_logs: List[Dict[str, Any]] = []
        self.iteration_count = 0  # LLM交互轮数
        self._started_tools = set()
        self._completed_tools = set()
    
    async def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str], **kwargs):
        """当LLM开始推理时 - 跟踪每轮交互"""
        self.iteration_count += 1
        
        # 提取提示词的关键信息
        prompt_preview = ""
        task_type = ""
        if prompts:
            prompt_text = prompts[0] if isinstance(prompts[0], str) else str(prompts[0])
            # 提取关键信息
            if "nmap" in prompt_text.lower() or "扫描" in prompt_text or "scan" in prompt_text.lower():
                prompt_preview = "分析扫描任务"
                task_type = "扫描分析"
            elif "工具" in prompt_text or "tool" in prompt_text.lower() or "action" in prompt_text.lower():
                prompt_preview = "选择工具"
                task_type = "工具选择"
            elif "结果" in prompt_text or "result" in prompt_text.lower() or "output" in prompt_text.lower():
                prompt_preview = "分析工具执行结果"
                task_type = "结果分析"
            elif "完成" in prompt_text or "finish" in prompt_text.lower():
                prompt_preview = "总结任务完成情况"
                task_type = "任务总结"
            else:
                prompt_preview = prompt_text[:50] + "..." if len(prompt_text) > 50 else prompt_text
                task_type = "推理中"
        
        # 显示LLM推理信息，包含Agent名称和任务类型
        execution_state.add_output_line(f"🤖 [{self.agent_name}] LLM推理 (第{self.iteration_count}轮): {task_type}")
        logger.info(f"Agent {self.agent_name} LLM iteration {self.iteration_count}: {task_type}")
        
        self.execution_logs.append({
            "type": "llm_start",
            "iteration": self.iteration_count,
            "task_type": task_type,
            "prompt_preview": prompt_preview,
            "timestamp": datetime.now().isoformat()
        })
    
    async def on_llm_end(self, response, **kwargs):
        """当LLM完成推理时"""
        # 提取LLM的决策和工具调用
        decision_summary = ""
        try:
            # 尝试从response中提取内容
            if hasattr(response, 'generations') and response.generations:
                for gen in response.generations:
                    if gen and len(gen) > 0:
                        content = gen[0].text if hasattr(gen[0], 'text') else str(gen[0])
                        # 检查是否包含工具调用
                        if "tool_calls" in content.lower() or "action" in content.lower():
                            # 提取工具名
                            tool_match = re.search(r'(?:tool|action)[_ ]?name["\']?\s*[:=]\s*["\']?(\w+)', content, re.IGNORECASE)
                            if tool_match:
                                decision_summary = f"决定使用工具: {tool_match.group(1)}"
                            else:
                                decision_summary = "决定调用工具"
                        elif "final answer" in content.lower() or "完成" in content:
                            decision_summary = "完成当前任务"
                        else:
                            # 提取前50个字符作为摘要
                            decision_summary = content[:80].replace('\n', ' ')
                            if len(content) > 80:
                                decision_summary += "..."
            
            # 如果没有从generations提取到，尝试从其他属性
            if not decision_summary:
                if hasattr(response, 'content'):
                    content = str(response.content)
                    decision_summary = content[:80].replace('\n', ' ')
                elif hasattr(response, 'text'):
                    decision_summary = response.text[:80].replace('\n', ' ')
            
            if decision_summary:
                execution_state.add_output_line(f"💭 LLM决策: {decision_summary}")
                logger.info(f"LLM decision: {decision_summary}")
            else:
                execution_state.add_output_line(f"✅ LLM推理完成 (第{self.iteration_count}轮)")
                
        except Exception as e:
            logger.debug(t("agent.parse_llm_failed", error=str(e)))
            execution_state.add_output_line(f"✅ LLM推理完成 (第{self.iteration_count}轮)")
        
        self.execution_logs.append({
            "type": "llm_end",
            "iteration": self.iteration_count,
            "decision": decision_summary,
            "timestamp": datetime.now().isoformat()
        })
    
    async def on_chain_start(self, serialized: Dict[str, Any], inputs: Dict[str, Any], **kwargs):
        """当Agent链开始执行时"""
        if serialized.get("name") == "AgentExecutor":
            execution_state.add_output_line(f"🚀 Agent {self.agent_name} 开始执行任务")
            logger.info(f"Agent {self.agent_name} chain started")
    
    async def on_chain_end(self, outputs: Dict[str, Any], **kwargs):
        """当Agent链结束执行时"""
        if "output" in outputs:
            execution_state.add_output_line(f"🏁 Agent {self.agent_name} 任务完成")
            logger.info(f"Agent {self.agent_name} chain ended")
    
    async def on_agent_action(self, action, **kwargs):
        """当Agent执行动作时 - 更新全局状态"""
        tool_name = action.tool
        tool_input = action.tool_input
        
        # 构建友好的任务描述
        task_desc = self._format_task_description(tool_name, tool_input)
        
        # 更新全局执行状态（供实时UI使用）
        command = self._extract_command(tool_name, tool_input)
        execution_state.set_current_execution(
            agent=self.agent_name,
            tool=tool_name,
            command=command,
            description=task_desc
        )
        
        # 实时显示Agent决策
        execution_state.add_output_line(f"🎯 Agent决定使用工具: {tool_name}")
        if task_desc:
            execution_state.add_output_line(f"📝 任务: {task_desc}")
        
        logger.info(f"Agent {self.agent_name} executing action: {tool_name}")
        self.execution_logs.append({
            "type": "action",
            "tool": tool_name,
            "input": tool_input,
            "timestamp": datetime.now().isoformat()
        })
    
    def _extract_command(self, tool_name: str, tool_input: Any) -> str:
        """从工具输入提取实际命令（临时显示，实际命令会在工具执行后更新）"""
        if isinstance(tool_input, dict):
            actual_input = tool_input.get("parameters", tool_input)
            
            if tool_name in ["nmap", "nmap_scan"]:
                target = actual_input.get("target", "")
                ports = actual_input.get("ports", "")
                scan_type = actual_input.get("scan_type", "tcp_connect")
                service_detection = actual_input.get("service_detection", True)
                
                # 构建更完整的命令字符串
                cmd_parts = ["nmap"]
                
                # 扫描类型
                if scan_type == "tcp_syn":
                    cmd_parts.append("-sS")
                elif scan_type == "tcp_connect":
                    cmd_parts.append("-sT")
                elif scan_type == "udp":
                    cmd_parts.append("-sU")
                
                # 服务检测
                if service_detection:
                    cmd_parts.extend(["-sV", "--version-intensity", "5"])
                
                # 端口
                if ports:
                    cmd_parts.extend(["-p", str(ports)])
                
                # 目标
                if target:
                    cmd_parts.append(target)
                
                return " ".join(cmd_parts)
            elif tool_name == "subdomain_enumeration":
                domain = actual_input.get("domain", "")
                return f"subdomain-enum {domain}"
            elif tool_name in ["cmd_exec", "execute_command"]:
                return actual_input.get("command", str(tool_input))
        return f"{tool_name}"
    
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
            from ..utils.i18n import t
            from ..utils.unified_logger import get_logger
            agent_logger = get_logger(f"agent.{self.agent_name}")
            result_summary = self._format_result_summary(output)
            if result_summary:
                agent_logger.success(t("agent.completed", agent_name=self.agent_name, summary=result_summary))
        
        self.execution_logs.append({
            "type": "finish",
            "output": output,
            "timestamp": datetime.now().isoformat()
        })
    
    def _format_result_summary(self, output: Any) -> str:
        """格式化结果摘要"""
        from ..utils.i18n import t
        if isinstance(output, dict):
            if "open_ports" in output:
                ports = output.get("open_ports", [])
                return t("agent.ports_found", count=len(ports))
            if "subdomains" in output:
                subdomains = output.get("subdomains", [])
                return t("agent.subdomains_found", count=len(subdomains))
            if "vulnerabilities" in output:
                vulns = output.get("vulnerabilities", [])
                return t("agent.vulnerabilities_found", count=len(vulns))
            if "success" in output:
                return t("agent.task_success") if output.get("success") else t("agent.task_failed")
        return ""
    
    async def on_tool_start(self, serialized: Dict[str, Any], input_str: str, **kwargs):
        """当工具开始执行时 - 实时更新状态"""
        tool_name = serialized.get('name', 'unknown')
        tool_key = f"{tool_name}_{input_str[:50]}"
        
        if tool_key not in self._started_tools:
            # 解析输入参数，显示更友好的信息
            try:
                input_data = json.loads(input_str) if input_str.startswith('{') else {"input": input_str}
                target = input_data.get("target", input_data.get("url", ""))
                if target:
                    execution_state.add_output_line(f"⚙️ 启动 {tool_name}: {target}")
                else:
                    execution_state.add_output_line(f"⚙️ 启动工具: {tool_name}")
            except:
                execution_state.add_output_line(f"⚙️ 启动工具: {tool_name}")
            
            self._started_tools.add(tool_key)
            
        logger.info(f"Tool started: {tool_name}, input: {input_str[:100]}")
        
        self.execution_logs.append({
            "type": "tool_start",
            "tool": tool_name,
            "input": input_str[:500],
            "timestamp": datetime.now().isoformat()
        })
    
    async def on_tool_end(self, output: str, **kwargs):
        """当工具执行完成时 - 结构化过滤输出并实时更新"""
        # 使用输出解析器过滤和结构化输出
        try:
            from ..core.output_parser import output_manager
            
            # 获取最后使用的工具名（从最近的action或tool_start）
            last_tool = None
            for log in reversed(self.execution_logs):
                if log.get("type") in ["action", "tool_start"]:
                    last_tool = log.get("tool")
                    break
            
            if last_tool:
                # 结构化解析输出
                parsed = output_manager.parse_output(last_tool, output)
                summary = parsed.get("_summary", "")
                
                # 显示摘要和关键信息
                if summary:
                    execution_state.add_output_line(f"✅ {last_tool} 完成: {summary}")
                    
                    # 对于nmap，额外显示关键发现
                    if last_tool in ["nmap", "nmap_scan"]:
                        open_ports = parsed.get("open_ports", [])
                        services = parsed.get("services", [])
                        if open_ports:
                            execution_state.add_output_line(f"📌 发现开放端口: {', '.join(map(str, open_ports[:10]))}")
                        if services:
                            unique_services = list(set(s.get("service", "unknown") for s in services))
                            if unique_services:
                                execution_state.add_output_line(f"📌 发现服务: {', '.join(unique_services[:5])}")
                else:
                    # 如果没有摘要，尝试提取关键信息
                    if len(output) > 500:
                        # 对于长输出，只显示前几行和后几行
                        lines = output.split('\n')
                        if len(lines) > 10:
                            preview = '\n'.join(lines[:3] + ['...'] + lines[-3:])
                        else:
                            preview = output[:200]
                        execution_state.add_output_line(f"✅ {last_tool} 完成: {preview}")
                    else:
                        execution_state.add_output_line(f"✅ {last_tool} 完成: {output[:150]}")
                
                # 记录解析后的结构化数据
                self.execution_logs.append({
                    "type": "tool_end",
                    "tool": last_tool,
                    "output": output[:2000],  # 保留更多输出用于后续分析
                    "parsed": parsed,
                    "summary": summary,
                    "timestamp": datetime.now().isoformat()
                })
            else:
                # 没有工具名，显示原始输出（截断）
                output_preview = output[:150] + "..." if len(output) > 150 else output
                execution_state.add_output_line(f"✅ 工具执行完成: {output_preview}")
                self.execution_logs.append({
                    "type": "tool_end",
                    "output": output[:1000],
                    "timestamp": datetime.now().isoformat()
                })
                
        except Exception as e:
            logger.error(t("agent.output_parse_failed", error=str(e)), exc_info=True)
            # 解析失败时，至少显示基本信息
            output_preview = output[:150] + "..." if len(output) > 150 else output
            execution_state.add_output_line(f"✅ 工具执行完成: {output_preview}")
            self.execution_logs.append({
                "type": "tool_end",
                "output": output[:1000],
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
        
        logger.info(f"Tool completed, output length: {len(output)}")
    
    async def on_tool_error(self, error: Exception, **kwargs):
        """当工具执行出错时"""
        error_msg = str(error)[:100]
        execution_state.add_output_line(f"❌ 工具错误: {error_msg}")
        logger.error(f"Tool error: {error}")
        
        self.execution_logs.append({
            "type": "tool_error",
            "error": str(error),
            "timestamp": datetime.now().isoformat()
        })


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
        
        # Memory配置 - 限制对话历史长度防止token过长
        self.memory = ConversationBufferWindowMemory(
            memory_key="chat_history",
            return_messages=True,
            k=5  # 只保留最近5轮对话，防止历史过长
        )
        
        # 输入长度限制（字符数）
        self._max_input_length = config.get("max_input_length", 8000) if config else 8000
        
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
        self._model_name: Optional[str] = None  # 保存模型名称用于输入优化
        self._retry_handler: Optional[LLMRetryHandler] = None  # 重试处理器
    
    def _create_default_llm(self) -> BaseLLM:
        """创建默认的LLM - 从配置读取子Agent的LLM配置"""
        import os
        
        # 从配置读取LLM设置（已经由 build_framework_config 从 llm_runtime.json 构建）
        llm_config = self.config.get("llm", {})
        
        api_key = llm_config.get("api_key")
        base_url = llm_config.get("base_url")
        model_name = llm_config.get("model_name") or llm_config.get("model", "gpt-4")
        
        # 保存模型名称用于输入优化
        self._model_name = model_name
        
        # 如果配置中没有，尝试从环境变量读取
        if not api_key:
            api_key = os.getenv("OPENAI_API_KEY")
        
        # 如果还是没有 API Key，给出友好提示
        if not api_key:
            from ..utils.i18n import t
            raise ValueError(t("agent.api_key_not_configured"))
        
        # 创建重试处理器
        max_retries = self.config.get("max_retries", 3)
        self._retry_handler = LLMRetryHandler(max_retries=max_retries)
        
        # 创建 ChatOpenAI 实例
        # 🔧 禁用streaming模式：第三方API在streaming模式下返回的tool_call_id格式不正确
        # 会导致多个ID片段被拼接成超长ID，引发503错误
        kwargs = {
            "model": model_name,
            "temperature": llm_config.get("temperature", 0.7),
            "max_tokens": llm_config.get("max_tokens", 2048),
            "api_key": api_key,
            "streaming": False  # 禁用streaming，避免tool_call_id拼接问题
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
            # 🔧 直接使用LLM，不使用bind_tools（避免第三方API不支持parallel_tool_calls参数）
            # create_openai_tools_agent会自动处理工具绑定
            
            # 创建Agent - 直接传递LLM和工具
            agent = create_openai_tools_agent(
                llm=self.llm,
                tools=self.tools,
                prompt=self.prompt
            )
            
            # 从配置获取执行参数
            max_iterations = self.config.get("max_iterations", 15)  # 增加迭代次数
            max_execution_time = self.config.get("max_execution_time", 600)  # 10分钟超时
            
            # 创建Agent Executor - 支持多轮LLM交互
            self.agent_executor = AgentExecutor(
                agent=agent,
                tools=self.tools,
                memory=self.memory,
                verbose=True,
                max_iterations=max_iterations,  # 允许更多迭代
                max_execution_time=max_execution_time,
                handle_parsing_errors=True,
                return_intermediate_steps=True,  # 返回中间步骤，便于分析
                early_stopping_method="generate"  # 让LLM决定何时停止
            )
            
            self._initialized = True
            self.logger.info(f"Agent {self.name} initialized: max_iterations={max_iterations}, timeout={max_execution_time}s")
            
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
            
            # 创建回调处理器（使用agent_type.value作为显示名称）
            agent_display_name = self.agent_type.value.replace("_", " ").title()  # recon_agent -> Recon Agent
            self.callback_handler = AgentCallbackHandler(agent_display_name, session_id)
            
            # 在Agent开始执行时，立即更新执行状态
            from ..utils.i18n import t
            execution_state.set_current_execution(
                agent=agent_display_name,
                tool="",
                command="",
                description=t("agent.starting_task", agent_name=agent_display_name)
            )
            execution_state.add_output_line(t("agent.starting_task", agent_name=agent_display_name))
            
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
安全模式: {t("agent.safe_mode_enabled") if self.safe_mode else t("agent.safe_mode_disabled")}
"""
            
            # 优化输入长度
            if self._model_name:
                optimizer = InputOptimizer(model_name=self._model_name)
                full_input = optimizer.optimize_input(full_input)
            
            input_data = {
                "input": full_input
            }
            
            # 执行Agent
            self.logger.info(f"Agent {self.name} starting execution for target: {target_info.get('target', 'unknown')}")
            if session_id:
                self.logger.info(f"Session ID: {session_id}")
            
            # 使用重试机制执行Agent
            async def _execute_agent():
                return await self.agent_executor.ainvoke(
                    input_data,
                    config={
                        "callbacks": [self.callback_handler],
                        "metadata": {
                            "session_id": session_id,
                            "agent_type": self.agent_type.value
                        }
                    }
                )
            
            # 使用重试处理器执行
            if self._retry_handler:
                result = await self._retry_handler.retry_async(_execute_agent)
            else:
                result = await _execute_agent()
            
            # 处理结果
            execution_result = self._process_result(result, target_info, context)
            
            # Agent执行完成，更新状态
            from ..utils.i18n import t
            agent_display_name = self.agent_type.value.replace("_", " ").title()
            if execution_result.get("success"):
                execution_state.add_output_line(t("agent.task_success_msg", agent_name=agent_display_name))
            else:
                error = execution_result.get("error", t("common.unknown_error"))
                execution_state.add_output_line(t("agent.task_failed_msg", agent_name=agent_display_name, error=error[:100]))
            
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
        """准备Agent输入，包含长度检查和压缩"""
        target = target_info.get("target", "")
        session_context = context[0] if context else {}
        
        # 获取任务列表
        todos = session_context.get("todos", [])
        stage_config = session_context.get("stage_config", {})
        stage = session_context.get("stage", "")
        global_context = session_context.get("global_context", {})
        
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
        
        # 构建阶段配置信息（压缩）
        config_info = ""
        if stage_config:
            # 只保留关键配置，避免太长
            key_config = {k: v for k, v in stage_config.items() 
                         if k in ["target", "ports", "scan_type", "timeout"]}
            if key_config:
                config_info = f"\n阶段配置: {json.dumps(key_config, ensure_ascii=False)}\n"
        
        # 构建全局上下文摘要（压缩历史信息）
        context_summary = ""
        if global_context:
            context_summary = self._compress_global_context(global_context)
        
        input_text = f"""
目标: {target}
阶段: {stage}
安全模式: {'启用' if self.safe_mode else '禁用'}
{tasks_description}
{config_info}
{context_summary}
请根据你的职责和上述任务列表，使用可用工具完成相应的渗透测试任务。

可用工具: {', '.join([tool.name for tool in self.tools])}

请按照任务列表的顺序执行，每个任务完成后报告结果。
        """.strip()
        
        # 🔧 检查输入长度，如果过长则压缩
        if len(input_text) > self._max_input_length:
            self.logger.warning(t("agent.input_too_long", length=len(input_text)))
            input_text = self._compress_input(input_text, target, stage, todos)
            self.logger.info(t("agent.input_compressed", length=len(input_text)))
        
        return input_text
    
    def _compress_global_context(self, global_context: Dict[str, Any]) -> str:
        """压缩全局上下文为简洁摘要"""
        summary_parts = []
        
        # 只保留关键信息
        services = global_context.get("discovered_services", [])
        if services:
            service_names = [s.get("name", str(s)) if isinstance(s, dict) else str(s) for s in services[:10]]
            summary_parts.append(f"已发现服务: {', '.join(service_names)}")
        
        vulns = global_context.get("identified_vulnerabilities", [])
        if vulns:
            vuln_names = [v.get("name", str(v)) if isinstance(v, dict) else str(v) for v in vulns[:5]]
            summary_parts.append(f"已发现漏洞: {', '.join(vuln_names)}")
        
        access_level = global_context.get("current_access_level", "none")
        if access_level != "none":
            summary_parts.append(f"当前权限: {access_level}")
        
        # 检查是否有LLM总结
        llm_summary = global_context.get("_llm_summary", {})
        if llm_summary:
            key_findings = llm_summary.get("key_findings", [])
            if key_findings:
                summary_parts.append(f"关键发现: {'; '.join(key_findings[:3])}")
        
        if summary_parts:
            return "\n### 上下文摘要\n" + "\n".join(summary_parts) + "\n"
        return ""
    
    def _compress_input(self, input_text: str, target: str, stage: str, todos: List[Dict[str, Any]]) -> str:
        """压缩过长的输入"""
        # 生成最简化的输入
        tasks_summary = ""
        if todos:
            task_names = [t.get("name", t.get("title", "任务"))[:30] for t in todos[:5]]
            tasks_summary = f"任务: {', '.join(task_names)}"
        
        compressed = f"""
目标: {target}
阶段: {stage}
{tasks_summary}

可用工具: {', '.join([tool.name for tool in self.tools])}

请执行上述任务。
        """.strip()
        
        return compressed
    
    def _process_result(
        self,
        result: Dict[str, Any],
        target_info: Dict[str, Any],
        context: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """处理Agent执行结果"""
        output = result.get("output", "")
        
        execution_logs = self.callback_handler.execution_logs if self.callback_handler else []
        tools_used = [log["tool"] for log in execution_logs if log.get("type") == "action"]
        
        # 使用LLM判断任务是否成功
        success, extracted_data, error_msg = self._evaluate_result_with_llm(output, target_info, tools_used)
        
        self.logger.info(t("agent.llm_eval_result", success=success, tools=tools_used))
        
        return self.create_result(
            success=success,
            data={
                "output": output,
                "execution_logs": execution_logs,
                "tools_used": tools_used,
                **extracted_data  # 合并LLM提取的结构化数据
            },
            error=error_msg if not success else None
        )
    
    def _evaluate_result_with_llm(
        self, 
        output: str, 
        target_info: Dict[str, Any],
        tools_used: List[str]
    ) -> tuple:
        """
        使用LLM评估任务执行结果
        
        Returns:
            tuple: (success: bool, extracted_data: dict, error_msg: str)
        """
        try:
            # 构建评估提示
            evaluation_prompt = f"""请分析以下渗透测试任务的执行结果，判断任务是否成功完成。

## 目标信息
目标: {target_info.get('target', '未知')}
Agent类型: {self.agent_type.value}
使用的工具: {', '.join(tools_used) if tools_used else '无'}

## 任务输出
{output[:3000]}  # 限制长度避免token过多

## 请以JSON格式返回评估结果：
{{
    "success": true/false,  // 任务是否成功完成
    "reason": "判断理由",
    "findings": {{  // 从输出中提取的关键发现
        "open_ports": [],  // 发现的开放端口列表
        "services": [],  // 发现的服务列表
        "vulnerabilities": [],  // 发现的漏洞
        "other_info": {{}}  // 其他重要信息
    }},
    "error": null  // 如果失败，描述失败原因
}}

判断标准：
1. 如果工具成功执行并返回了有意义的结果（即使没有发现漏洞），视为成功
2. 如果扫描完成但目标不可达或被过滤，仍视为成功（任务本身完成了）
3. 只有在工具执行出错、权限不足、网络不可达等情况才视为失败
4. 请从输出中提取结构化的发现数据

请只返回JSON，不要有其他内容。"""

            # 使用同步方式调用LLM（因为这个方法可能在同步上下文中被调用）
            from langchain_core.messages import HumanMessage
            
            response = self.llm.invoke([HumanMessage(content=evaluation_prompt)])
            response_text = response.content if hasattr(response, 'content') else str(response)
            
            # 解析JSON响应
            import re
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                evaluation = json.loads(json_match.group(0))
                success = evaluation.get("success", False)
                findings = evaluation.get("findings", {})
                error = evaluation.get("error")
                reason = evaluation.get("reason", "")
                
                self.logger.info(t("agent.llm_eval_success", success=success, reason=reason))
                
                return success, findings, error
            else:
                # 无法解析，默认成功（如果有工具执行）
                self.logger.warning(t("agent.cannot_parse_llm_eval", text=response_text[:200]))
                return len(tools_used) > 0, {}, None
                
        except Exception as e:
            self.logger.error(t("agent.llm_eval_failed", error=str(e)))
            # 评估失败时，如果有工具执行就认为成功
            return len(tools_used) > 0, {}, None
    
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

