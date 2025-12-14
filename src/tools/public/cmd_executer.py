"""
通用命令执行工具 - 公有工具
所有Agent都可以使用的安全命令执行工具，支持环境准备和各种通用命令
"""
import subprocess
import asyncio
import os
import tempfile
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from ...core.agent_tool_manager import ToolInterface

# 获取项目根目录
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_WORKSPACE = PROJECT_ROOT / "workspace"


class CommandExecutorTool(ToolInterface):
    """通用命令执行工具"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("command_executor", config)
        self.timeout = config.get("timeout", 300)  # 5分钟超时
        
        # Docker环境中不需要命令限制，支持所有命令
        self.allowed_commands = config.get("allowed_commands", None)  # None表示无限制
        self.enable_command_restrictions = config.get("enable_command_restrictions", False)
        
        # 环境配置
        self.environment_config = config.get("environment", {
            "package_manager": "apt",
            "temp_directory": "/tmp",
            "workspace_directory": str(DEFAULT_WORKSPACE), 
            "max_file_size": 100 * 1024 * 1024,  # 100MB
            "max_execution_time": 300
        })
        
        # 包管理器配置
        self.package_managers = {
            "apt": {"install_cmd": ["apt-get", "install", "-y"], "check_cmd": ["dpkg", "-l"]},
            "pip": {"install_cmd": ["pip", "install"], "check_cmd": ["pip", "show"]},
            "npm": {"install_cmd": ["npm", "install", "-g"], "check_cmd": ["npm", "list", "-g"]},
            "yum": {"install_cmd": ["yum", "install", "-y"], "check_cmd": ["rpm", "-q"]}
        }
        
        # 操作历史
        self.action_history: List[Dict[str, Any]] = []
        
    async def execute(self, parameters: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """执行命令或环境操作"""
        try:
            action_type = parameters.get("action_type", "execute_command")
            
            if action_type == "execute_command":
                return await self._execute_command(parameters)
            elif action_type == "install_package":
                return await self._install_package(parameters)
            elif action_type == "create_file":
                return await self._create_file(parameters)
            elif action_type == "create_directory":
                return await self._create_directory(parameters)
            elif action_type == "set_environment":
                return await self._set_environment(parameters)
            elif action_type == "prepare_environment":
                return await self._prepare_environment(parameters)
            else:
                return {"success": False, "error": f"不支持的操作类型: {action_type}"}
                
        except Exception as e:
            return {"success": False, "error": f"操作执行失败: {str(e)}"}
    
    async def _execute_command(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """执行命令"""
        try:
            command = parameters.get("command")
            working_directory = parameters.get("working_directory", self.environment_config.get("workspace_directory"))
            timeout = parameters.get("timeout", self.timeout)
            environment_vars = parameters.get("environment", {})
            
            # 立即更新执行状态，让UI可以看到
            if command:
                self._update_execution_status(
                    str(command),
                    "执行系统命令",
                    "AGENT"
                )
                self._add_output_line(f"准备执行: {str(command)[:80]}")
            
            if not command:
                return {"success": False, "error": "未指定命令"}
            
            # 检查命令是否被允许（如果启用了限制）
            if self.enable_command_restrictions and not self._is_command_allowed(command):
                return {"success": False, "error": f"命令不被允许: {command}"}
            
            # 准备环境变量
            env = os.environ.copy()
            env.update(environment_vars)
            
            # 执行命令
            result = await self._run_command(command, working_directory, timeout, env)
            
            # 记录操作历史
            self._record_action("execute_command", {
                "command": command,
                "working_directory": working_directory,
                "success": result.get("success", False)
            })
            
            return result
            
        except Exception as e:
            return {"success": False, "error": f"命令执行失败: {str(e)}"}
    
    async def _install_package(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """安装软件包"""
        try:
            package = parameters.get("package")
            package_manager = parameters.get("package_manager", self.environment_config.get("package_manager"))
            force_reinstall = parameters.get("force_reinstall", False)
            
            if not package:
                return {"success": False, "error": "未指定软件包名称"}
            
            if package_manager not in self.package_managers:
                return {"success": False, "error": f"不支持的包管理器: {package_manager}"}
            
            # 检查是否已安装
            if not force_reinstall and await self._is_package_installed(package, package_manager):
                return {"success": True, "message": f"软件包 {package} 已安装"}
            
            # 构建安装命令
            install_config = self.package_managers[package_manager]
            cmd = install_config["install_cmd"] + [package]
            
            # 执行安装
            result = await self._run_command(cmd)
            
            # 记录操作历史
            self._record_action("install_package", {
                "package": package,
                "package_manager": package_manager,
                "success": result.get("success", False)
            })
            
            return result
            
        except Exception as e:
            return {"success": False, "error": f"软件包安装失败: {str(e)}"}
    
    async def _create_file(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """创建文件"""
        try:
            file_path = parameters.get("path")
            content = parameters.get("content", "")
            file_type = parameters.get("type", "text")
            permissions = parameters.get("permissions", 0o644)
            
            if not file_path:
                return {"success": False, "error": "未指定文件路径"}
            
            # 检查文件大小
            if len(content) > self.environment_config.get("max_file_size", 100 * 1024 * 1024):
                return {"success": False, "error": "文件内容过大"}
            
            # 创建目录（如果不存在）
            directory = os.path.dirname(file_path)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            
            # 写入文件
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # 设置权限
            os.chmod(file_path, permissions)
            
            # 记录操作历史
            self._record_action("create_file", {
                "path": file_path,
                "type": file_type,
                "size": len(content)
            })
            
            return {"success": True, "message": f"文件创建成功: {file_path}"}
            
        except Exception as e:
            return {"success": False, "error": f"文件创建失败: {str(e)}"}
    
    async def _create_directory(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """创建目录"""
        try:
            directory_path = parameters.get("path")
            permissions = parameters.get("permissions", 0o755)
            
            if not directory_path:
                return {"success": False, "error": "未指定目录路径"}
            
            # 创建目录
            os.makedirs(directory_path, mode=permissions, exist_ok=True)
            
            # 记录操作历史
            self._record_action("create_directory", {
                "path": directory_path,
                "permissions": oct(permissions)
            })
            
            return {"success": True, "message": f"目录创建成功: {directory_path}"}
            
        except Exception as e:
            return {"success": False, "error": f"目录创建失败: {str(e)}"}
    
    async def _set_environment(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """设置环境变量"""
        try:
            variables = parameters.get("variables", {})
            
            for key, value in variables.items():
                os.environ[key] = str(value)
            
            # 记录操作历史
            self._record_action("set_environment", {
                "variables": list(variables.keys())
            })
            
            return {"success": True, "message": f"环境变量设置成功: {list(variables.keys())}"}
            
        except Exception as e:
            return {"success": False, "error": f"环境变量设置失败: {str(e)}"}
    
    async def _prepare_environment(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """准备完整环境（组合操作）"""
        try:
            stage_type = parameters.get("stage_type", "generic")
            requirements = parameters.get("requirements", [])
            
            results = []
            all_success = True
            
            for requirement in requirements:
                action_type = requirement.get("action")
                if action_type == "install_package":
                    result = await self._install_package(requirement)
                elif action_type == "create_file":
                    result = await self._create_file(requirement)
                elif action_type == "create_directory":
                    result = await self._create_directory(requirement)
                elif action_type == "set_environment":
                    result = await self._set_environment(requirement)
                elif action_type == "execute_command":
                    result = await self._execute_command(requirement)
                else:
                    result = {"success": False, "error": f"未知操作类型: {action_type}"}
                
                results.append(result)
                if not result.get("success", False):
                    all_success = False
                    break
            
            # 记录操作历史
            self._record_action("prepare_environment", {
                "stage_type": stage_type,
                "requirements_count": len(requirements),
                "success": all_success
            })
            
            return {
                "success": all_success,
                "stage_type": stage_type,
                "results": results,
                "message": f"环境准备{'成功' if all_success else '失败'}"
            }
            
        except Exception as e:
            return {"success": False, "error": f"环境准备失败: {str(e)}"}
    
    async def _run_command(self, command, working_directory: str = None, timeout: int = None, env: Dict[str, str] = None) -> Dict[str, Any]:
        """运行命令的核心方法 - 使用基类的通用流式执行方法"""
        try:
            # 如果是字符串命令，转换为列表
            if isinstance(command, str):
                import shlex
                try:
                    command_list = shlex.split(command)
                except ValueError:
                    command_list = command.split()
            else:
                command_list = list(command)
            
            # 设置默认值
            if working_directory is None:
                working_directory = self.environment_config.get("workspace_directory", str(DEFAULT_WORKSPACE))
            if timeout is None:
                timeout = self.timeout
            
            # 使用基类的通用流式命令执行方法
            result = await self.run_command_with_streaming(
                cmd=command_list,
                timeout=timeout,
                working_directory=working_directory,
                env=env,
                description="执行命令"
            )
            
            # 转换返回值格式以保持向后兼容
            return {
                "success": result.get("success", False),
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "return_code": result.get("returncode", -1),
                "command": result.get("command", ""),
                "error": result.get("error")
            }
                
        except Exception as e:
            return {"success": False, "error": f"命令执行失败: {str(e)}"}
    
    async def _is_package_installed(self, package: str, package_manager: str) -> bool:
        """检查软件包是否已安装"""
        try:
            if package_manager not in self.package_managers:
                return False
            
            check_config = self.package_managers[package_manager]
            cmd = check_config["check_cmd"] + [package]
            
            result = await self._run_command(cmd)
            return result.get("success", False)
            
        except Exception as e:
            self.logger.error(f"检查软件包安装状态失败: {e}")
            return False
    
    def _is_command_allowed(self, command: str) -> bool:
        """检查命令是否被允许"""
        # 如果没有启用命令限制，所有命令都允许
        if not self.enable_command_restrictions:
            return True
        
        # 如果没有设置允许的命令列表，默认允许所有命令
        if self.allowed_commands is None:
            return True
        
        if isinstance(command, list):
            command = command[0]
        elif isinstance(command, str):
            command = command.split()[0]
        
        # 检查命令是否在允许列表中
        for allowed_cmd in self.allowed_commands:
            if command.startswith(allowed_cmd) or command == allowed_cmd:
                return True
        
        return False
    
    def _record_action(self, action_type: str, details: Dict[str, Any]):
        """记录操作历史"""
        self.action_history.append({
            "action_type": action_type,
            "timestamp": asyncio.get_event_loop().time(),
            "details": details
        })
        
        # 限制历史记录数量
        if len(self.action_history) > 100:
            self.action_history = self.action_history[-50:]
    
    def get_description(self) -> str:
        """获取工具描述"""
        return "通用命令执行和环境管理工具，支持Docker环境中的完整命令执行、软件包安装、文件操作和环境准备"
    
    def get_parameters(self) -> Dict[str, Any]:
        """获取工具参数"""
        return {
            "required": ["action_type"],
            "optional": [
                "command", "package", "path", "content", "variables", 
                "requirements", "working_directory", "timeout", "environment"
            ],
            "action_type": {
                "type": "string",
                "description": "操作类型",
                "enum": [
                    "execute_command", "install_package", "create_file", 
                    "create_directory", "set_environment", "prepare_environment"
                ]
            },
            "command": {
                "type": "string",
                "description": "要执行的命令（用于execute_command）"
            },
            "package": {
                "type": "string", 
                "description": "软件包名称（用于install_package）"
            },
            "package_manager": {
                "type": "string",
                "description": "包管理器类型",
                "enum": ["apt", "pip", "npm", "yum"],
                "default": "apt"
            },
            "path": {
                "type": "string",
                "description": "文件或目录路径（用于create_file/create_directory）"
            },
            "content": {
                "type": "string",
                "description": "文件内容（用于create_file）"
            },
            "variables": {
                "type": "object",
                "description": "环境变量键值对（用于set_environment）"
            },
            "requirements": {
                "type": "array",
                "description": "环境要求列表（用于prepare_environment）",
                "items": {"type": "object"}
            },
            "working_directory": {
                "type": "string",
                "description": "工作目录"
            },
            "timeout": {
                "type": "integer",
                "description": "超时时间（秒）"
            },
            "environment": {
                "type": "object", 
                "description": "环境变量"
            }
        }
    
    def get_capabilities(self) -> List[str]:
        """获取工具能力"""
        return [
            "command_execution",
            "package_management",
            "file_operations",
            "directory_operations", 
            "environment_management",
            "environment_preparation",
            "timeout_control",
            "output_capture",
            "error_handling",
            "permission_control",
            "action_history"
        ]
    
    def get_tool_info(self) -> Dict[str, Any]:
        """获取工具信息"""
        return {
            "name": "command_executor",
            "description": self.get_description(),
            "parameters": self.get_parameters(),
            "capabilities": self.get_capabilities(),
            "returns": {
                "success": "bool - 是否成功",
                "return_code": "int - 返回码（命令执行）",
                "stdout": "str - 标准输出（命令执行）",
                "stderr": "str - 错误输出（命令执行）", 
                "command": "str - 执行的完整命令（命令执行）",
                "message": "str - 操作消息",
                "results": "array - 批量操作结果（环境准备）",
                "stage_type": "str - 阶段类型（环境准备）",
                "error": "str - 错误信息(如果失败)"
            },
            "examples": {
                "execute_command": {
                    "action_type": "execute_command",
                    "command": "nmap -sS -A -T4 192.168.1.0/24",
                    "working_directory": "/tmp",
                    "timeout": 300
                },
                "complex_command": {
                    "action_type": "execute_command",
                    "command": "bash -c 'for i in {1..254}; do ping -c 1 192.168.1.$i; done'",
                    "timeout": 600
                },
                "install_package": {
                    "action_type": "install_package", 
                    "package": "metasploit-framework",
                    "package_manager": "apt"
                },
                "create_script": {
                    "action_type": "create_file",
                    "path": "/tmp/exploit.py",
                    "content": "#!/usr/bin/env python3\nimport requests\nimport sys\n# Exploit code here",
                    "permissions": 755
                },
                "prepare_pentest_env": {
                    "action_type": "prepare_environment",
                    "stage_type": "exploitation",
                    "requirements": [
                        {"action": "install_package", "package": "metasploit-framework"},
                        {"action": "install_package", "package": "sqlmap"},
                        {"action": "install_package", "package": "gobuster"},
                        {"action": "create_directory", "path": "/tmp/exploits"},
                        {"action": "set_environment", "variables": {"MSF_DATABASE_CONFIG": "/tmp/database.yml"}}
                    ]
                }
            },
            "docker_features": {
                "unrestricted_execution": "支持执行任何系统命令",
                "root_privileges": "支持需要root权限的操作",
                "network_tools": "支持各种网络扫描和测试工具",
                "container_isolation": "在容器中安全运行危险命令"
            }
        }
    
    def get_action_history(self) -> List[Dict[str, Any]]:
        """获取操作历史"""
        return self.action_history.copy()


# 保留原有函数用于向后兼容
def java_exec(jar_path: str, params: List[str]) -> str:
    """
    向后兼容的Java执行函数
    建议使用CommandExecutorTool类
    """
    try:
        commands = ['java', '-jar', jar_path] + params
        process_rst = subprocess.run(commands, capture_output=True, text=True)
        stdout = process_rst.stdout
        return stdout or ''
    except:
        return ''