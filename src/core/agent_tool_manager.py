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
from ..utils.i18n import t

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
        self._execution_state = None  # 缓存执行状态管理器
        
    def _get_execution_state(self):
        """获取执行状态管理器（懒加载）"""
        if self._execution_state is None:
            try:
                from ..agents.base_agent import execution_state
                self._execution_state = execution_state
            except ImportError:
                self._execution_state = None
        return self._execution_state
    
    def _update_execution_status(self, command: str, description: str = "", agent: str = ""):
        """更新执行状态（供所有工具使用）"""
        exec_state = self._get_execution_state()
        if exec_state:
            # 尝试从thread-local context获取agent类型
            actual_agent = agent
            if not actual_agent:
                try:
                    from ..agents.tools_adapter import _context_storage
                    if hasattr(_context_storage, 'agent_context'):
                        # 获取原始agent_type (如 "recon_agent")
                        raw_agent = _context_storage.agent_context.get("agent_type", "")
                        # 转换为显示格式 (如 "Recon Agent")，与base_agent.py保持一致
                        if raw_agent:
                            actual_agent = raw_agent.replace("_", " ").title()
                except Exception:
                    pass
            
            exec_state.set_current_execution(
                agent=actual_agent or "Agent",
                tool=self.name,
                command=command,
                description=description or f"执行 {self.name}"
            )
            self.logger.info(f"[状态更新] Agent={actual_agent}, 工具={self.name}, 命令={command[:50]}...")
    
    def _add_output_line(self, line: str):
        """添加输出行到执行状态"""
        exec_state = self._get_execution_state()
        if exec_state and line and line.strip():
            exec_state.add_output_line(line.strip())
            self.logger.debug(f"[输出] {line.strip()[:80]}")
    
    def _should_show_output_line(self, line: str) -> bool:
        line = line.strip()
        if not line:
            return False
        
        # 跳过纯XML标签行
        if line.startswith('<?xml') or line.startswith('<!DOCTYPE'):
            return False
        if line.startswith('<') and line.endswith('>') and '/' in line:
            # 闭合标签如 </host> </port>
            if line.startswith('</') or '/>' in line:
                return False
            # 开始标签如 <verbose level="0"/>
            if not any(keyword in line.lower() for keyword in ['port', 'service', 'state', 'script', 'output', 'host', 'address']):
                return False
        
        # 过滤nmap的taskprogress更新
        if '<taskprogress' in line:
            return False
        
        # 保留有意义的信息
        meaningful_keywords = [
            'open', 'closed', 'filtered', 'port', 'service',
            'http', 'ssh', 'ftp', 'smtp', 'mysql', 'dns',
            'vuln', 'error', 'warning', 'found', 'detected',
            'version', 'product', 'script', 'output',
            '发现', '扫描', '完成', '失败', '成功'
        ]
        
        line_lower = line.lower()
        for keyword in meaningful_keywords:
            if keyword in line_lower:
                return True
        
        # 如果是端口信息，显示
        if '/tcp' in line or '/udp' in line:
            return True
        
        # 默认不显示
        return False
    
    async def run_command_with_streaming(
        self, 
        cmd: List[str], 
        timeout: float = 300,
        working_directory: str = None,
        env: Dict[str, str] = None,
        description: str = "",
        agent_type: str = ""
    ) -> Dict[str, Any]:
        """
        通用的流式命令执行方法 - 所有工具都可以使用
        支持实时输出捕获和执行状态更新
        
        Args:
            cmd: 命令列表
            timeout: 超时时间（秒）
            working_directory: 工作目录
            env: 环境变量
            description: 命令描述
            agent_type: Agent类型
            
        Returns:
            Dict[str, Any]: 包含success, stdout, stderr, returncode, command的结果
        """
        import os
        import signal
        import sys
        
        try:
            full_command = " ".join(cmd)
            
            # 更新执行状态（不再在这里调用，由调用者在execute开始时设置）
            # 只添加命令执行日志
            self._add_output_line(f"$ {full_command}")
            self.logger.info(t("tool.execute_cmd", command=full_command))
            
            # 准备环境变量
            process_env = os.environ.copy()
            if env:
                process_env.update(env)
            
            # 定义preexec_fn，确保子进程完全独立于父进程的信号处理
            def preexec_fn():
                """在子进程中执行，设置新的会话和忽略SIGINT"""
                # 创建新会话
                os.setsid()
                # 在子进程中忽略SIGINT，让nmap等工具能正常完成
                signal.signal(signal.SIGINT, signal.SIG_IGN)
            
            # 创建子进程，设置start_new_session=True使子进程不受父进程信号影响
            # 使用preexec_fn进一步确保子进程不受信号影响（仅Unix系统）
            if sys.platform != 'win32':
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=working_directory,
                    env=process_env,
                    start_new_session=True,  # 创建新会话
                    preexec_fn=preexec_fn  # 子进程中忽略SIGINT
                )
            else:
                # Windows系统
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=working_directory,
                    env=process_env,
                    creationflags=0x00000008  # DETACHED_PROCESS
                )
            
            stdout_data = b""
            stderr_data = b""
            
            async def read_streams():
                """读取stdout和stderr流"""
                nonlocal stdout_data, stderr_data
                
                # 创建读取任务
                async def read_stdout():
                    nonlocal stdout_data
                    line_count = 0
                    last_progress_time = asyncio.get_event_loop().time()
                    last_heartbeat_time = asyncio.get_event_loop().time()
                    last_heartbeat_line_count = 0
                    heartbeat_interval = 15  # 心跳间隔：15秒
                    
                    while True:
                        try:
                            line = await asyncio.wait_for(
                                process.stdout.readline(),
                                timeout=1.0  # 更短的超时，更频繁检查
                            )
                            if not line:
                                break
                            stdout_data += line
                            line_count += 1
                            # 实时添加输出（过滤XML标签，只显示有意义的信息）
                            line_text = line.decode('utf-8', errors='ignore').rstrip()
                            if line_text:
                                # 过滤掉纯XML标签行，保留有意义的内容
                                if self._should_show_output_line(line_text):
                                    self._add_output_line(line_text)
                                # 每30行或每10秒输出一个进度提示（有实际输出时）
                                current_time = asyncio.get_event_loop().time()
                                if line_count % 30 == 0 or (current_time - last_progress_time) >= 10:
                                    self._add_output_line(f"📊 扫描进行中... 已处理 {line_count} 行数据")
                                    last_progress_time = current_time
                                    last_heartbeat_time = current_time  # 有输出时重置心跳时间
                                    last_heartbeat_line_count = line_count
                        except asyncio.TimeoutError:
                            # 超时时检查进程状态
                            if process.returncode is not None:
                                break
                            
                            # 只在长时间无输出时才输出心跳（避免刷屏）
                            current_time = asyncio.get_event_loop().time()
                            time_since_last_heartbeat = current_time - last_heartbeat_time
                            
                            # 条件：超过心跳间隔 且 行数没有变化（真正卡住了）
                            if (time_since_last_heartbeat >= heartbeat_interval and 
                                line_count == last_heartbeat_line_count):
                                self._add_output_line(f"⏳ 扫描执行中... (已处理 {line_count} 行，等待更多输出...)")
                                last_heartbeat_time = current_time
                                last_heartbeat_line_count = line_count
                            
                            continue
                        except Exception:
                            break
                
                async def read_stderr():
                    nonlocal stderr_data
                    while True:
                        try:
                            line = await asyncio.wait_for(
                                process.stderr.readline(),
                                timeout=1.0
                            )
                            if not line:
                                break
                            stderr_data += line
                            # 实时添加错误输出
                            line_text = line.decode('utf-8', errors='ignore').rstrip()
                            if line_text:
                                self._add_output_line(f"[stderr] {line_text}")
                        except asyncio.TimeoutError:
                            if process.returncode is not None:
                                break
                            continue
                        except Exception:
                            break
                
                # 并行读取stdout和stderr
                await asyncio.gather(read_stdout(), read_stderr())
            
            try:
                await asyncio.wait_for(read_streams(), timeout=timeout)
                await process.wait()
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                self._add_output_line(f"⚠️ 命令超时 ({timeout}秒)")
                self.logger.warning(t("tool.timeout_warn", command=full_command))
                return {
                    "success": False,
                    "error": f"命令执行超时 ({timeout}秒)",
                    "stdout": stdout_data.decode('utf-8', errors='ignore'),
                    "stderr": stderr_data.decode('utf-8', errors='ignore'),
                    "returncode": -1,
                    "command": full_command
                }
            
            stdout_str = stdout_data.decode('utf-8', errors='ignore')
            stderr_str = stderr_data.decode('utf-8', errors='ignore')
            success = process.returncode == 0
            
            # 添加完成状态
            if success:
                self._add_output_line(f"✓ 命令执行成功")
            else:
                self._add_output_line(f"✗ 命令退出码: {process.returncode}")
                if stderr_str:
                    # 只添加前几行错误信息
                    for line in stderr_str.split('\n')[:3]:
                        if line.strip():
                            self._add_output_line(f"  {line.strip()}")
            
            return {
                "success": success,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "returncode": process.returncode,
                "command": full_command
            }
            
        except Exception as e:
            error_msg = str(e)
            self._add_output_line(f"✗ 执行错误: {error_msg}")
            self.logger.error(t("tool.stream_cmd_failed", error=str(e)))
            return {
                "success": False,
                "error": error_msg,
                "stdout": "",
                "stderr": error_msg,
                "returncode": -1,
                "command": " ".join(cmd) if cmd else ""
            }
        
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
    
    def _build_command_string(self, parameters: Dict[str, Any]) -> str:
        """构建命令字符串（供工具子类重写）"""
        # 默认实现：尝试从工具返回结果中获取command字段
        return f"{self.name}"


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
            await asyncio.sleep(0)  # 让出控制权
            
            # 加载Agent专有工具
            await self._load_private_tools()
            await asyncio.sleep(0)  # 让出控制权
            
            # 注册工具到分类（同步操作，但很快）
            self._categorize_tools()
            await asyncio.sleep(0)  # 让出控制权
            
            tool_count = len(self.get_available_tools())
            self.logger.info(t("tool.manager_init", agent=self.agent_type.value))
            self.logger.info(t("tool.available_count", count=tool_count))
            
        except Exception as e:
            self.logger.error(t("tool.manager_init_failed", error=str(e)))
            # 不抛出异常，允许继续初始化其他组件
            pass
    
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
            
            self.logger.info(t("tool.register_success", name=tool.name, scope=scope.value))
            return True
            
        except Exception as e:
            self.logger.error(t("tool.register_failed", error=str(e)))
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
                # 检查是否有替代工具
                available_tools = self.get_available_tools()
                self.logger.warning(t("tool.not_found", name=tool_name, available=', '.join(available_tools)))
                
                # 尝试自动安装工具（如果是系统命令工具）
                install_result = await self._try_install_tool(tool_name)
                if install_result.get("success"):
                    # 重新获取工具
                    tool = self._get_tool(tool_name)
                    if tool:
                        self.logger.info(t("tool.install_success", name=tool_name))
                    else:
                        return {
                            "success": False, 
                            "error": f"工具不存在: {tool_name}",
                            "available_tools": available_tools,
                            "suggestion": f"请检查工具是否已正确注册，或使用替代工具"
                        }
                else:
                    return {
                        "success": False, 
                        "error": f"工具不存在: {tool_name}",
                        "available_tools": available_tools,
                        "suggestion": f"请检查工具是否已正确注册，或使用替代工具",
                        "install_attempted": True,
                        "install_error": install_result.get("error")
                    }
            
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
            
            # 记录工具执行开始（如果context中有session_id）
            session_id = (context or {}).get("session_id")
            tool_exec_id = None
            if session_id:
                try:
                    from ..database.logging_service import pentest_logger
                    command_desc = self._build_command_description(tool_name, parameters)
                    tool_exec_id = pentest_logger.log_tool_execution(
                        session_id=session_id,
                        tool_name=tool_name,
                        command=command_desc,
                        parameters=parameters,
                        safe_mode=True,
                        risk_level="LOW"
                    )
                except Exception as e:
                    self.logger.debug(t("tool.log_exec_failed", error=str(e)))
            
            # 更新执行状态（工具开始执行）- 优先于AgentCallbackHandler
            self._update_execution_state(tool, parameters, "start")
            self.logger.info(t("tool.exec_started", name=tool_name))
            
            # 执行工具
            start_time = datetime.now()
            try:
                result = await tool.execute(parameters, execution_context)
                # 确保result是字典
                if not isinstance(result, dict):
                    result = {"success": False, "error": "工具返回了非字典结果", "tool": tool_name}
            except Exception as e:
                self.logger.error(t("tool.exec_exception", name=tool_name, error=str(e)))
                result = {
                    "success": False,
                    "error": str(e),
                    "tool": tool_name
                }
            end_time = datetime.now()
            
            # 捕获工具输出并更新执行状态
            self._capture_tool_output(tool, parameters, result)
            self.logger.debug(t("tool.exec_completed", name=tool_name))
            
            # 完成工具执行记录
            if tool_exec_id and session_id:
                try:
                    from ..database.logging_service import pentest_logger
                    pentest_logger.complete_tool_execution(
                        tool_exec_id=tool_exec_id,
                        success=result.get("success", False),
                        return_code=0 if result.get("success") else 1,
                        stdout=str(result.get("result", "")),
                        stderr=result.get("error", "")
                    )
                except Exception as e:
                    self.logger.debug(t("tool.complete_log_failed", error=str(e)))
            
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
            
            self.logger.info(t("tool.exec_complete", name=tool_name, success=result.get('success', False)))
            return result
            
        except Exception as e:
            self.logger.error(t("tool.exec_failed", error=str(e)))
            return {"success": False, "error": str(e)}
    
    def _build_command_description(self, tool_name: str, parameters: Dict[str, Any]) -> str:
        """构建命令描述"""
        target = parameters.get("target") or parameters.get("domain", "")
        if tool_name == "nmap":
            ports = parameters.get("ports", "1-1000")
            scan_type = parameters.get("scan_type", "tcp_connect")
            return f"nmap -{scan_type[4:]} -p {ports} {target}"
        elif tool_name == "dns_enum":
            return f"dns_enum {target}"
        elif tool_name == "subdomain_enum":
            return f"subdomain_enum {target}"
        else:
            return f"{tool_name} {target}"
    
    def _update_execution_state(self, tool: ToolInterface, parameters: Dict[str, Any], action: str = "start"):
        """更新全局执行状态"""
        try:
            from ..agents.base_agent import execution_state
            
            # 构建命令字符串（工具可以重写_build_command_string方法）
            if hasattr(tool, '_build_command_string'):
                command = tool._build_command_string(parameters)
            else:
                command = self._build_command_description(tool.name, parameters)
            
            # 构建描述
            target = parameters.get("target") or parameters.get("domain") or parameters.get("url", "")
            description = f"{tool.name} 处理 {target}" if target else f"执行 {tool.name}"
            
            if action == "start":
                # 统一使用显示格式的agent名称 (如 "Recon Agent")
                agent_display_name = self.agent_type.value.replace("_", " ").title()
                execution_state.set_current_execution(
                    agent=agent_display_name,
                    tool=tool.name,
                    command=command,
                    description=description
                )
                # 添加日志
                execution_state.add_output_line(f"开始执行: {tool.name}")
                self.logger.info(t("tool.state_updated", name=tool.name, command=command))
        except Exception as e:
            self.logger.warning(t("tool.update_state_failed", error=str(e)), exc_info=True)
    
    def _capture_tool_output(self, tool: ToolInterface, parameters: Dict[str, Any], result: Dict[str, Any]):
        """捕获工具输出并添加到执行状态 - 通用方法"""
        try:
            from ..agents.base_agent import execution_state
            
            # 🔧 无论成功失败，都先更新命令（使用工具返回的实际执行命令）
            # 但只更新状态，不重复添加命令日志（命令日志已在工具执行时添加）
            command = result.get("command")
            if command:
                # 使用实际执行的完整命令更新状态（统一使用显示格式的agent名称）
                agent_display_name = self.agent_type.value.replace("_", " ").title()
                execution_state.set_current_execution(
                    agent=agent_display_name,
                    tool=tool.name,
                    command=command,
                    description=execution_state.current_description or f"执行 {tool.name}"
                )
                # 🔧 移除这里的日志输出，避免重复：命令日志已在工具的run_command_with_streaming中输出
                self.logger.info(t("tool.cmd_updated", command=command))
            elif not result.get("success"):
                # 如果失败且没有command，尝试从参数构建命令
                try:
                    if hasattr(tool, "_build_command_string"):
                        command = tool._build_command_string(parameters)
                    elif hasattr(tool, "build_command_string"):
                        command = tool.build_command_string(parameters)
                    else:
                        command = self._build_command_description(tool.name, parameters)
                    
                    if command:
                        agent_display_name = self.agent_type.value.replace("_", " ").title()
                        execution_state.set_current_execution(
                            agent=agent_display_name,
                            tool=tool.name,
                            command=command,
                            description=execution_state.current_description or f"执行 {tool.name}"
                        )
                        # 🔧 只在失败且之前没有命令日志时才添加
                        execution_state.add_output_line(f"🔧 执行命令: {command}")
                except Exception as e:
                    self.logger.warning(t("tool.build_cmd_failed", error=str(e)))
            
            # 如果工具执行成功，提取关键输出
            if result.get("success"):
                
                # 2. 提取结构化结果并转换为可读输出
                tool_result = result.get("result")
                if tool_result:
                    self._extract_and_add_output(tool.name, tool_result, execution_state)
                    self.logger.debug(t("tool.output_extracted", name=tool.name))
                
                # 3. 提取raw_output（如果存在）
                raw_output = result.get("raw_output")
                if raw_output:
                    # 解析raw_output的关键信息
                    self._parse_raw_output(tool.name, raw_output, execution_state)
                    self.logger.debug(t("tool.raw_output_parsed", name=tool.name))
                
                # 4. 添加成功消息
                if not tool_result and not raw_output:
                    execution_state.add_output_line(f"{tool.name} 执行成功")
                    self.logger.debug(t("tool.success_msg_added", name=tool.name))
            else:
                # 执行失败，添加错误信息
                error = result.get("error", "工具执行失败")
                execution_state.add_output_line(f"错误: {error}")
                self.logger.warning(t("tool.exec_failed_warn", name=tool.name, error=error))
                
        except Exception as e:
            self.logger.error(t("tool.capture_output_failed", error=str(e)), exc_info=True)
    
    def _extract_and_add_output(self, tool_name: str, result: Any, execution_state):
        """从结构化结果中提取并添加输出"""
        try:
            if isinstance(result, dict):
                # Nmap结果
                if "hosts" in result:
                    for host in result.get("hosts", []):
                        if host.get("ports"):
                            ports = host["ports"]
                            ports_info = ", ".join([f"{p.get('port')}/{p.get('protocol', 'tcp')}" for p in ports[:10]])
                            execution_state.add_output_line(f"发现开放端口: {ports_info}")
                            if len(ports) > 10:
                                execution_state.add_output_line(f"... 还有 {len(ports) - 10} 个端口")
                
                # 子域名结果
                if "subdomains" in result:
                    subdomains = result.get("subdomains", [])
                    execution_state.add_output_line(f"发现 {len(subdomains)} 个子域名")
                    for subdomain in subdomains[:5]:
                        execution_state.add_output_line(f"  - {subdomain}")
                    if len(subdomains) > 5:
                        execution_state.add_output_line(f"... 还有 {len(subdomains) - 5} 个子域名")
                
                # DNS结果
                if "records" in result:
                    records = result.get("records", [])
                    execution_state.add_output_line(f"发现 {len(records)} 条DNS记录")
                    for record in records[:5]:
                        execution_state.add_output_line(f"  {record.get('type')}: {record.get('value')}")
                
                # 漏洞结果
                if "vulnerabilities" in result:
                    vulns = result.get("vulnerabilities", [])
                    execution_state.add_output_line(f"发现 {len(vulns)} 个潜在漏洞")
                    for vuln in vulns[:3]:
                        execution_state.add_output_line(f"  - {vuln.get('name', 'Unknown')}")
                
                # 通用成功消息
                if "message" in result:
                    execution_state.add_output_line(result["message"])
                    
        except Exception as e:
            self.logger.debug(t("tool.extract_output_failed", error=str(e)))
    
    def _parse_raw_output(self, tool_name: str, raw_output: str, execution_state):
        """解析原始输出并提取关键信息"""
        try:
            if not raw_output:
                return
            
            # 根据工具类型解析输出
            if tool_name == "nmap":
                # Nmap XML输出已在上层处理，这里处理文本输出
                lines = raw_output.split('\n')
                for line in lines[:20]:  # 只处理前20行
                    line = line.strip()
                    if line and ("open" in line.lower() or "port" in line.lower()):
                        execution_state.add_output_line(line[:80])  # 限制长度
            else:
                # 通用处理：提取前几行关键信息
                lines = raw_output.split('\n')
                for line in lines[:10]:  # 只处理前10行
                    line = line.strip()
                    if line and len(line) > 3:
                        execution_state.add_output_line(line[:80])  # 限制长度
                        
        except Exception as e:
            self.logger.debug(t("tool.parse_raw_failed", error=str(e)))
    
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
            # 首先从全局注册表获取已注册的公有工具
            global_public_tools = global_tool_registry.get_all_public_tools()
            for tool_name, tool in global_public_tools.items():
                if tool_name not in self.public_tools:
                    self.public_tools[tool_name] = tool
                    self.logger.info(t("tool.load_from_global", name=tool_name))
            
            # 从配置文件加载额外的公有工具
            public_tools_config = self.config.get("public_tools", [])
            
            for tool_config in public_tools_config:
                tool = await self._create_tool_from_config(tool_config)
                if tool:
                    await self.register_tool(tool, ToolScope.PUBLIC)
            
            # 自动发现并注册默认公有工具（如果未配置）
            if not public_tools_config:
                await self._auto_discover_public_tools()
                    
        except Exception as e:
            self.logger.error(t("tool.load_public_failed", error=str(e)))
    
    async def _auto_discover_public_tools(self):
        """自动发现并注册默认公有工具"""
        try:
            # 默认公有工具列表
            # 从agent配置中获取超时时间
            agent_timeout = self.config.get("timeout") or self.config.get("scan_timeout", 300)
            default_public_tools = [
                {
                    "module": "src.tools.public.nmap_tool",
                    "class": "NmapTool",
                    "config": {
                        "timeout": agent_timeout  # 使用agent配置的超时时间
                    }
                },
                {
                    "module": "src.tools.public.cmd_executer",
                    "class": "CommandExecutorTool",
                    "config": {}
                },
                {
                    "module": "src.tools.public.auto_decode",
                    "class": "AutoDecodeTool",
                    "config": {}
                }
            ]
            
            for tool_config in default_public_tools:
                try:
                    tool = await self._create_tool_from_config(tool_config)
                    if tool:
                        await self.register_tool(tool, ToolScope.PUBLIC)
                        # 同时注册到全局注册表
                        global_tool_registry.register_public_tool(tool)
                        self.logger.info(t("tool.auto_discovered", name=tool.name))
                except Exception as e:
                    self.logger.warning(t("tool.auto_discover_failed", cls=tool_config.get('class'), error=str(e)))
                    continue
                    
        except Exception as e:
            self.logger.error(t("tool.auto_discover_all_failed", error=str(e)))
    
    async def _load_private_tools(self):
        """加载Agent私有工具"""
        try:
            # 根据Agent类型加载特定的私有工具
            private_tools_path = f"src.tools.private.{self.agent_type.value.lower()}"
            
            try:
                # 将同步的模块导入放到线程中执行，避免阻塞事件循环
                module = await asyncio.to_thread(importlib.import_module, private_tools_path)
                
                # 将同步的inspect操作也放到线程中执行
                def _find_tool_classes():
                    tool_classes = []
                    for name, obj in inspect.getmembers(module):
                        if (inspect.isclass(obj) and 
                            issubclass(obj, ToolInterface) and 
                            obj != ToolInterface):
                            tool_classes.append((name, obj))
                    return tool_classes
                
                tool_classes = await asyncio.to_thread(_find_tool_classes)
                
                if not tool_classes:
                    # 这是正常的，某些Agent可能还没有私有工具
                    self.logger.debug(f"Agent {self.agent_type.value} 的私有工具模块 {private_tools_path} 中没有工具类（这是正常的，如果该Agent还没有实现私有工具）")
                
                # 注册找到的工具类
                for name, obj in tool_classes:
                    try:
                        tool_config = self.config.get("private_tools", {}).get(name, {})
                        tool_instance = obj(tool_config)
                        await self.register_tool(tool_instance, ToolScope.PRIVATE)
                        self.logger.info(t("tool.private_loaded", name=name))
                        await asyncio.sleep(0)  # 让出控制权
                    except Exception as e:
                        self.logger.error(t("tool.load_failed", name=name, error=str(e)), exc_info=True)
                        # 尝试安装缺失的依赖
                        await self._try_install_missing_dependencies(str(e))
                        continue
                        
            except ImportError as e:
                error_msg = str(e)
                # 模块不存在是正常的，某些Agent可能还没有私有工具模块
                # 只在debug模式下显示，避免产生过多警告
                if "No module named" in error_msg:
                    # 模块不存在，这是正常的
                    self.logger.debug(f"Agent {self.agent_type.value} 的私有工具模块 {private_tools_path} 不存在（这是正常的，如果该Agent还没有实现私有工具）")
                else:
                    # 其他导入错误，可能是依赖问题
                    self.logger.warning(t("tool.import_private_failed", agent=self.agent_type.value, error=error_msg))
                    await self._try_install_missing_dependencies(error_msg)
            except Exception as e:
                # 其他错误才显示为警告或错误
                self.logger.warning(t("tool.load_private_module_failed", agent=self.agent_type.value, error=str(e)))
                await self._try_install_missing_dependencies(str(e))
                
        except Exception as e:
            self.logger.error(t("tool.load_private_all_failed", error=str(e)), exc_info=True)
    
    async def _try_install_missing_dependencies(self, error_msg: str):
        """尝试根据错误信息安装缺失的依赖"""
        import platform
        
        # 检测缺失的Python包
        missing_packages = []
        
        if "No module named 'dns'" in error_msg or "No module named 'dnspython'" in error_msg:
            missing_packages.append("dnspython")
        elif "No module named 'requests'" in error_msg:
            missing_packages.append("requests")
        elif "No module named 'nmap'" in error_msg:
            missing_packages.append("python-nmap")
        
        if not missing_packages:
            return
        
        self.logger.info(t("tool.missing_deps", packages=', '.join(missing_packages)))
        
        for package in missing_packages:
            try:
                cmd = ["python", "-m", "pip", "install", package]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    self.logger.info(t("tool.dep_installed", package=package))
                    # 重新加载模块
                    try:
                        importlib.reload(importlib.import_module(f"src.tools.private.{self.agent_type.value.lower()}"))
                    except:
                        pass
                else:
                    self.logger.warning(t("tool.dep_install_failed", package=package, error=stderr.decode('utf-8', errors='ignore')))
            except Exception as e:
                self.logger.error(t("tool.dep_install_error", package=package, error=str(e)))
    
    
    async def _create_tool_from_config(self, tool_config: Dict[str, Any]) -> Optional[ToolInterface]:
        """从配置创建工具实例"""
        try:
            module_name = tool_config.get("module")
            class_name = tool_config.get("class")
            
            if not module_name or not class_name:
                return None
            
            # 将同步的模块导入放到线程中执行，避免阻塞事件循环
            module = await asyncio.to_thread(importlib.import_module, module_name)
            tool_class = getattr(module, class_name)
            
            # 合并agent配置和工具配置
            tool_instance_config = tool_config.get("config", {})
            # 如果工具配置中没有timeout，从agent配置中获取
            if "timeout" not in tool_instance_config:
                agent_timeout = self.config.get("timeout") or self.config.get("scan_timeout")
                if agent_timeout:
                    tool_instance_config["timeout"] = agent_timeout
            
            return tool_class(tool_instance_config)
            
        except Exception as e:
            self.logger.error(t("tool.create_instance_failed", error=str(e)))
            return None
    
    async def _try_install_tool(self, tool_name: str) -> Dict[str, Any]:
        """尝试自动安装工具"""
        import platform
        
        # 检测操作系统
        system = platform.system().lower()
        is_windows = system == "windows"
        is_macos = system == "darwin"
        is_linux = system == "linux"
        
        # 工具名称到系统包名的映射（支持不同操作系统）
        tool_package_map = {
            "nmap": {
                "package": "nmap",
                "apt": {"package": "nmap", "manager": "apt"},
                "brew": {"package": "nmap", "manager": "brew"},
                "pip": {"package": "python-nmap", "manager": "pip"},
                "winget": {"package": "Nmap.Nmap", "manager": "winget"},
                "choco": {"package": "nmap", "manager": "choco"}
            },
            "dns_enum": {
                "apt": {"package": "dnsutils", "manager": "apt"},
                "brew": {"package": "bind", "manager": "brew"},  # macOS上bind包含dig等工具
                "pip": {"package": "dnspython", "manager": "pip"}
            },
            "subdomain_enum": {
                "apt": {"package": "dnsutils", "manager": "apt"},
                "brew": {"package": "bind", "manager": "brew"},
                "pip": {"package": "dnspython", "manager": "pip"}
            },
            "nslookup": {
                "apt": {"package": "dnsutils", "manager": "apt"},
                "brew": {"package": "bind", "manager": "brew"},
            },
            "dig": {
                "apt": {"package": "dnsutils", "manager": "apt"},
                "brew": {"package": "bind", "manager": "brew"},
            },
            "whois": {
                "apt": {"package": "whois", "manager": "apt"},
                "brew": {"package": "whois", "manager": "brew"},
            },
            "sqlmap": {
                "pip": {"package": "sqlmap", "manager": "pip"}
            },
            "nikto": {
                "apt": {"package": "nikto", "manager": "apt"},
                "brew": {"package": "nikto", "manager": "brew"},
            },
            "masscan": {
                "apt": {"package": "masscan", "manager": "apt"},
                "brew": {"package": "masscan", "manager": "brew"},
            },
        }
        
        # 检查工具是否在映射中
        if tool_name not in tool_package_map:
            return {
                "success": False,
                "error": f"工具 {tool_name} 不在自动安装列表中"
            }
        
        # 根据操作系统选择包管理器
        package_info = None
        if is_windows:
            # Windows优先使用winget，其次choco，最后pip
            if "winget" in tool_package_map[tool_name]:
                package_info = tool_package_map[tool_name]["winget"]
            elif "choco" in tool_package_map[tool_name]:
                package_info = tool_package_map[tool_name]["choco"]
            elif "pip" in tool_package_map[tool_name]:
                package_info = tool_package_map[tool_name]["pip"]
        elif is_macos:
            # macOS优先使用brew，其次pip
            if "brew" in tool_package_map[tool_name]:
                package_info = tool_package_map[tool_name]["brew"]
            elif "pip" in tool_package_map[tool_name]:
                package_info = tool_package_map[tool_name]["pip"]
        elif is_linux:
            # Linux优先使用apt，其次pip
            if "apt" in tool_package_map[tool_name]:
                package_info = tool_package_map[tool_name]["apt"]
            elif "pip" in tool_package_map[tool_name]:
                package_info = tool_package_map[tool_name]["pip"]
        else:
            # 其他系统尝试pip
            if "pip" in tool_package_map[tool_name]:
                package_info = tool_package_map[tool_name]["pip"]
        
        if not package_info:
            return {
                "success": False,
                "error": f"当前操作系统 ({system}) 不支持自动安装工具 {tool_name}"
            }
        
        package = package_info["package"]
        manager = package_info["manager"]
        
        try:
            self.logger.info(t("tool.try_install", name=tool_name, package=package, manager=manager, system=system))
            
            # 检查包管理器是否可用
            if is_windows:
                # Windows下使用 where 检查命令存在
                if manager == "pip":
                    check_cmd = ["python", "-m", "pip", "--version"]
                else:
                    check_cmd = ["where", manager]
            else:
                check_cmd = ["which", manager] if manager != "pip" else ["python", "-m", "pip", "--version"]
            check_process = await asyncio.create_subprocess_exec(
                *check_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await check_process.wait()
            
            if check_process.returncode != 0:
                return {
                    "success": False,
                    "error": f"包管理器 {manager} 不可用，请先安装 {manager}"
                }
            
            # 执行安装
            if manager == "apt":
                # 先更新包列表
                cmd = ["apt-get", "update", "-qq"]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.wait()
                
                # 安装包
                cmd = ["apt-get", "install", "-y", package]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    return {"success": True, "message": f"成功安装 {package}"}
                else:
                    error_msg = stderr.decode('utf-8', errors='ignore')
                    # 检查是否需要sudo权限
                    if "permission denied" in error_msg.lower() or "root" in error_msg.lower():
                        return {
                            "success": False,
                            "error": f"需要管理员权限安装 {package}，请手动运行: sudo apt-get install -y {package}"
                        }
                    return {
                        "success": False,
                        "error": f"安装失败: {error_msg}"
                    }
            elif manager == "brew":
                # macOS使用brew安装
                cmd = ["brew", "install", package]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    return {"success": True, "message": f"成功安装 {package}"}
                else:
                    error_msg = stderr.decode('utf-8', errors='ignore')
                    return {
                        "success": False,
                        "error": f"安装失败: {error_msg}"
                    }
            elif manager == "winget":
                # Windows 使用 winget 安装
                # 统一加上协议接受参数以减少交互
                cmd = [
                    "winget", "install", "--id", package, "-e",
                    "--accept-package-agreements", "--accept-source-agreements"
                ]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                if process.returncode == 0:
                    return {"success": True, "message": f"成功安装 {package}"}
                else:
                    return {
                        "success": False,
                        "error": f"安装失败: {stderr.decode('utf-8', errors='ignore')}"
                    }
            elif manager == "choco":
                # Windows 使用 Chocolatey 安装
                cmd = ["choco", "install", package, "-y"]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                if process.returncode == 0:
                    return {"success": True, "message": f"成功安装 {package}"}
                else:
                    return {
                        "success": False,
                        "error": f"安装失败: {stderr.decode('utf-8', errors='ignore')}"
                    }
            elif manager == "pip":
                cmd = ["python", "-m", "pip", "install", package]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    return {"success": True, "message": f"成功安装 {package}"}
                else:
                    return {
                        "success": False,
                        "error": f"安装失败: {stderr.decode('utf-8', errors='ignore')}"
                    }
            else:
                return {
                    "success": False,
                    "error": f"不支持的包管理器: {manager}"
                }
                
        except Exception as e:
            self.logger.error(t("tool.install_tool_failed", name=tool_name, error=str(e)))
            return {
                "success": False,
                "error": str(e)
            }
    
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
    
    def get_all_public_tools(self) -> Dict[str, ToolInterface]:
        """获取所有公有工具"""
        return self.public_tools
    
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
