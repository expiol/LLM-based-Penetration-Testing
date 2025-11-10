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
            await asyncio.sleep(0)  # 让出控制权
            
            # 加载Agent专有工具
            await self._load_private_tools()
            await asyncio.sleep(0)  # 让出控制权
            
            # 注册工具到分类（同步操作，但很快）
            self._categorize_tools()
            await asyncio.sleep(0)  # 让出控制权
            
            tool_count = len(self.get_available_tools())
            self.logger.info(f"Agent {self.agent_type.value} 工具管理器初始化完成")
            self.logger.info(f"可用工具: {tool_count} 个")
            
        except Exception as e:
            self.logger.error(f"工具管理器初始化失败: {e}")
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
                # 检查是否有替代工具
                available_tools = self.get_available_tools()
                self.logger.warning(f"工具 {tool_name} 不存在，可用工具: {available_tools}")
                
                # 尝试自动安装工具（如果是系统命令工具）
                install_result = await self._try_install_tool(tool_name)
                if install_result.get("success"):
                    # 重新获取工具
                    tool = self._get_tool(tool_name)
                    if tool:
                        self.logger.info(f"工具 {tool_name} 安装成功，已可用")
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
                    self.logger.debug(f"记录工具执行日志失败: {e}")
            
            # 执行工具
            start_time = datetime.now()
            result = await tool.execute(parameters, execution_context)
            end_time = datetime.now()
            
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
                    self.logger.debug(f"完成工具执行记录失败: {e}")
            
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
                    self.logger.info(f"从全局注册表加载公有工具: {tool_name}")
            
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
            self.logger.error(f"加载公有工具失败: {e}")
    
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
                        self.logger.info(f"自动发现并注册公有工具: {tool.name}")
                except Exception as e:
                    self.logger.warning(f"自动发现工具失败 {tool_config.get('class')}: {e}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"自动发现公有工具失败: {e}")
    
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
                        self.logger.info(f"✅ 成功加载私有工具: {name}")
                        await asyncio.sleep(0)  # 让出控制权
                    except Exception as e:
                        self.logger.error(f"加载工具 {name} 失败: {e}", exc_info=True)
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
                    self.logger.warning(f"导入 {self.agent_type.value} 的私有工具模块失败: {error_msg}")
                    await self._try_install_missing_dependencies(error_msg)
            except Exception as e:
                # 其他错误才显示为警告或错误
                self.logger.warning(f"加载 {self.agent_type.value} 的私有工具模块失败: {e}")
                await self._try_install_missing_dependencies(str(e))
                
        except Exception as e:
            self.logger.error(f"加载私有工具失败: {e}", exc_info=True)
    
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
        
        self.logger.info(f"检测到缺失的依赖包: {missing_packages}，尝试自动安装...")
        
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
                    self.logger.info(f"成功安装依赖包: {package}")
                    # 重新加载模块
                    try:
                        importlib.reload(importlib.import_module(f"src.tools.private.{self.agent_type.value.lower()}"))
                    except:
                        pass
                else:
                    self.logger.warning(f"安装依赖包 {package} 失败: {stderr.decode('utf-8', errors='ignore')}")
            except Exception as e:
                self.logger.error(f"安装依赖包 {package} 时出错: {e}")
    
    
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
            self.logger.error(f"创建工具实例失败: {e}")
            return None
    
    async def _try_install_tool(self, tool_name: str) -> Dict[str, Any]:
        """尝试自动安装工具"""
        import platform
        
        # 检测操作系统
        system = platform.system().lower()
        is_macos = system == "darwin"
        is_linux = system == "linux"
        
        # 工具名称到系统包名的映射（支持不同操作系统）
        tool_package_map = {
            "nmap": {
                "package": "nmap",
                "apt": {"package": "nmap", "manager": "apt"},
                "brew": {"package": "nmap", "manager": "brew"},
                "pip": {"package": "python-nmap", "manager": "pip"}
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
        if is_macos:
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
            self.logger.info(f"尝试安装工具 {tool_name} (包: {package}, 管理器: {manager}, 系统: {system})")
            
            # 检查包管理器是否可用
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
            self.logger.error(f"安装工具 {tool_name} 失败: {e}")
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
