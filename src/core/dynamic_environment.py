"""
动态环境管理器
负责在Docker容器中动态安装软件包、创建文件、配置环境等
"""
import asyncio
import logging
import subprocess
import os
import tempfile
from typing import Dict, Any, List, Optional
from datetime import datetime
import json
import uuid
from pathlib import Path
from ..utils.unified_logger import get_logger

logger = get_logger("dynamic_environment")

# 获取项目根目录
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_WORKSPACE = PROJECT_ROOT / "workspace"


class EnvironmentAction:
    """环境操作类型"""
    INSTALL_PACKAGE = "install_package"
    CREATE_FILE = "create_file"
    EXECUTE_COMMAND = "execute_command"
    SET_ENVIRONMENT = "set_environment"
    CREATE_DIRECTORY = "create_directory"
    DOWNLOAD_FILE = "download_file"


class DynamicEnvironmentManager:
    """动态环境管理器"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.environment_state: Dict[str, Any] = {}
        self.installed_packages: List[str] = []
        self.created_files: List[str] = []
        self.environment_variables: Dict[str, str] = {}
        self.action_history: List[Dict[str, Any]] = []
        
        # 环境配置
        self.environment_config = config.get("environment", {
            "package_manager": "apt",  # apt, yum, pip, npm等
            "temp_directory": "/tmp",
            "workspace_directory": str(DEFAULT_WORKSPACE),
            "allowed_commands": ["apt", "pip", "npm", "git", "wget", "curl"],
            "max_file_size": 100 * 1024 * 1024,  # 100MB
            "max_execution_time": 300  # 5分钟
        })
    
    async def initialize(self):
        """初始化动态环境管理器"""
        try:
            # 创建工作目录
            logger.info(t("env.creating_workspace"))
            await self._create_workspace()
            workspace_dir = self.environment_config.get("workspace_directory", "unknown")
            logger.success(t("env.workspace_created", dir=workspace_dir))
            await asyncio.sleep(0)
            
            # 检查环境状态
            logger.info(t("env.checking_status"))
            await self._check_environment_status()
            available_managers = self.environment_state.get("available_package_managers", [])
            if available_managers:
                logger.success(t("env.check_complete", managers=", ".join(available_managers)))
            else:
                logger.warning(t("env.no_package_managers"))
            
            logger.info("动态环境管理器初始化完成")
            
        except Exception as e:
            logger.error(t("env.init_failed", error=str(e)))
            raise
    
    async def prepare_stage_environment(self, stage_type: str, stage_config: Dict[str, Any]) -> bool:
        """
        为特定阶段准备环境
        
        Args:
            stage_type: 阶段类型
            stage_config: 阶段配置
            
        Returns:
            bool: 是否准备成功
        """
        try:
            logger.info(f"为阶段 {stage_type} 准备环境")
            
            # 获取阶段所需的环境配置
            environment_requirements = self._get_stage_requirements(stage_type, stage_config)
            
            # 执行环境准备操作
            for requirement in environment_requirements:
                await self._execute_environment_action(requirement)
            
            # 更新环境状态
            self.environment_state[stage_type] = {
                "prepared_at": datetime.now().isoformat(),
                "requirements": environment_requirements,
                "status": "ready"
            }
            
            return True
            
        except Exception as e:
            logger.error(f"环境准备失败: {e}")
            return False
    
    def _get_stage_requirements(self, stage_type: str, stage_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """获取阶段所需的环境要求"""
        requirements = []
        
        # 根据阶段类型添加默认要求
        if stage_type == "reconnaissance":
            requirements.extend([
                {
                    "action": EnvironmentAction.INSTALL_PACKAGE,
                    "package": "nmap",
                    "package_manager": "apt"
                },
                {
                    "action": EnvironmentAction.INSTALL_PACKAGE,
                    "package": "dnsutils",
                    "package_manager": "apt"
                }
            ])
        elif stage_type == "exploitation":
            requirements.extend([
                {
                    "action": EnvironmentAction.INSTALL_PACKAGE,
                    "package": "python3-pip",
                    "package_manager": "apt"
                },
                {
                    "action": EnvironmentAction.INSTALL_PACKAGE,
                    "package": "sqlmap",
                    "package_manager": "pip"
                }
            ])
        
        # 从配置中获取自定义要求
        custom_requirements = stage_config.get("environment_requirements", [])
        requirements.extend(custom_requirements)
        
        return requirements
    
    async def _execute_environment_action(self, action: Dict[str, Any]) -> bool:
        """执行环境操作"""
        try:
            action_type = action.get("action")
            action_id = str(uuid.uuid4())
            
            logger.info(f"执行环境操作: {action_type}")
            
            # 记录操作历史
            action_record = {
                "id": action_id,
                "action": action,
                "timestamp": datetime.now().isoformat(),
                "status": "executing"
            }
            self.action_history.append(action_record)
            
            # 执行具体操作
            if action_type == EnvironmentAction.INSTALL_PACKAGE:
                result = await self._install_package(action)
            elif action_type == EnvironmentAction.CREATE_FILE:
                result = await self._create_file(action)
            elif action_type == EnvironmentAction.EXECUTE_COMMAND:
                result = await self._execute_command(action)
            elif action_type == EnvironmentAction.SET_ENVIRONMENT:
                result = await self._set_environment(action)
            elif action_type == EnvironmentAction.CREATE_DIRECTORY:
                result = await self._create_directory(action)
            elif action_type == EnvironmentAction.DOWNLOAD_FILE:
                result = await self._download_file(action)
            else:
                result = {"success": False, "error": f"未知的操作类型: {action_type}"}
            
            # 更新操作记录
            action_record["status"] = "completed" if result.get("success", False) else "failed"
            action_record["result"] = result
            
            return result.get("success", False)
            
        except Exception as e:
            logger.error(f"环境操作执行失败: {e}")
            return False
    
    async def _install_package(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """安装软件包"""
        try:
            package = action.get("package")
            package_manager = action.get("package_manager", "apt")
            
            if not package:
                return {"success": False, "error": "未指定软件包名称"}
            
            # 检查是否已安装
            if await self._is_package_installed(package, package_manager):
                logger.info(f"软件包 {package} 已安装")
                return {"success": True, "message": f"软件包 {package} 已安装"}
            
            # 构建安装命令
            if package_manager == "apt":
                cmd = ["apt-get", "update", "&&", "apt-get", "install", "-y", package]
            elif package_manager == "pip":
                cmd = ["pip", "install", package]
            elif package_manager == "npm":
                cmd = ["npm", "install", "-g", package]
            else:
                return {"success": False, "error": f"不支持的包管理器: {package_manager}"}
            
            # 执行安装
            result = await self._run_command(cmd)
            
            if result.get("success", False):
                self.installed_packages.append(package)
                logger.info(f"软件包 {package} 安装成功")
            
            return result
            
        except Exception as e:
            logger.error(f"软件包安装失败: {e}")
            return {"success": False, "error": str(e)}
    
    async def _create_file(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """创建文件"""
        try:
            file_path = action.get("path")
            content = action.get("content", "")
            file_type = action.get("type", "text")
            
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
            if file_type == "python":
                # 创建Python文件
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                # 设置执行权限
                os.chmod(file_path, 0o755)
            else:
                # 创建普通文件
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            self.created_files.append(file_path)
            logger.info(f"文件创建成功: {file_path}")
            
            return {"success": True, "message": f"文件创建成功: {file_path}"}
            
        except Exception as e:
            logger.error(f"文件创建失败: {e}")
            return {"success": False, "error": str(e)}
    
    async def _execute_command(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """执行命令"""
        try:
            command = action.get("command")
            working_directory = action.get("working_directory", self.environment_config.get("workspace_directory"))
            timeout = action.get("timeout", self.environment_config.get("max_execution_time", 300))
            
            if not command:
                return {"success": False, "error": "未指定命令"}
            
            # 检查命令是否被允许
            if not self._is_command_allowed(command):
                return {"success": False, "error": f"命令不被允许: {command}"}
            
            # 执行命令
            result = await self._run_command(command, working_directory, timeout)
            
            return result
            
        except Exception as e:
            logger.error(f"命令执行失败: {e}")
            return {"success": False, "error": str(e)}
    
    async def _set_environment(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """设置环境变量"""
        try:
            variables = action.get("variables", {})
            
            for key, value in variables.items():
                os.environ[key] = str(value)
                self.environment_variables[key] = str(value)
            
            logger.info(f"环境变量设置成功: {list(variables.keys())}")
            
            return {"success": True, "message": f"环境变量设置成功: {list(variables.keys())}"}
            
        except Exception as e:
            logger.error(f"环境变量设置失败: {e}")
            return {"success": False, "error": str(e)}
    
    async def _create_directory(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """创建目录"""
        try:
            directory_path = action.get("path")
            permissions = action.get("permissions", 0o755)
            
            if not directory_path:
                return {"success": False, "error": "未指定目录路径"}
            
            os.makedirs(directory_path, mode=permissions, exist_ok=True)
            
            logger.info(f"目录创建成功: {directory_path}")
            
            return {"success": True, "message": f"目录创建成功: {directory_path}"}
            
        except Exception as e:
            logger.error(f"目录创建失败: {e}")
            return {"success": False, "error": str(e)}
    
    async def _download_file(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """下载文件"""
        try:
            url = action.get("url")
            destination = action.get("destination")
            
            if not url or not destination:
                return {"success": False, "error": "未指定URL或目标路径"}
            
            # 使用wget下载文件
            cmd = ["wget", "-O", destination, url]
            result = await self._run_command(cmd)
            
            if result.get("success", False):
                self.created_files.append(destination)
                logger.info(f"文件下载成功: {destination}")
            
            return result
            
        except Exception as e:
            logger.error(f"文件下载失败: {e}")
            return {"success": False, "error": str(e)}
    
    async def _run_command(self, command: List[str], working_directory: str = None, timeout: int = 300) -> Dict[str, Any]:
        """运行命令"""
        try:
            # 如果是字符串命令，转换为列表
            if isinstance(command, str):
                command = command.split()
            
            # 执行命令
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_directory
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                
                return {
                    "success": process.returncode == 0,
                    "stdout": stdout.decode('utf-8') if stdout else "",
                    "stderr": stderr.decode('utf-8') if stderr else "",
                    "return_code": process.returncode
                }
                
            except asyncio.TimeoutError:
                process.kill()
                return {"success": False, "error": "命令执行超时"}
                
        except Exception as e:
            logger.error(f"命令执行失败: {e}")
            return {"success": False, "error": str(e)}
    
    async def _is_package_installed(self, package: str, package_manager: str) -> bool:
        """检查软件包是否已安装"""
        try:
            if package_manager == "apt":
                cmd = ["dpkg", "-l", package]
            elif package_manager == "pip":
                cmd = ["pip", "show", package]
            elif package_manager == "npm":
                cmd = ["npm", "list", "-g", package]
            else:
                return False
            
            result = await self._run_command(cmd)
            return result.get("success", False)
            
        except Exception as e:
            logger.error(f"检查软件包安装状态失败: {e}")
            return False
    
    def _is_command_allowed(self, command: str) -> bool:
        """检查命令是否被允许"""
        allowed_commands = self.environment_config.get("allowed_commands", [])
        
        # 检查命令是否在允许列表中
        for allowed_cmd in allowed_commands:
            if command.startswith(allowed_cmd):
                return True
        
        return False
    
    async def _create_workspace(self):
        """创建工作空间，若配置路径不可写则回退到临时目录"""
        default_path = str(DEFAULT_WORKSPACE)
        configured_path = Path(self.environment_config.get("workspace_directory", default_path))

        try:
            configured_path.mkdir(parents=True, exist_ok=True)
            workspace_dir = configured_path
            logger.info("工作空间路径: %s", workspace_dir)
        except OSError as exc:
            fallback = Path(tempfile.gettempdir()) / "llm_pentest_workspace"
            fallback.mkdir(parents=True, exist_ok=True)
            workspace_dir = fallback
            self.environment_config["workspace_directory"] = str(fallback)
            logger.warning(
                "无法在 %s 创建工作空间(%s)，已回退到 %s",
                configured_path,
                exc,
                fallback,
            )
        
    
    async def _check_environment_status(self):
        """检查环境状态"""
        # 检查包管理器（带超时保护，避免阻塞）
        package_managers = ["apt", "pip", "npm"]
        available_managers = []
        
        for manager in package_managers:
            try:
                # 每个命令检查最多2秒超时
                if await asyncio.wait_for(self._is_command_available(manager), timeout=2.0):
                    available_managers.append(manager)
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug(f"检查包管理器 {manager} 超时或失败: {e}")
                continue
        
        self.environment_state["available_package_managers"] = available_managers
        self.environment_state["workspace_directory"] = self.environment_config.get("workspace_directory")
        self.environment_state["initialized_at"] = datetime.now().isoformat()
    
    async def _is_command_available(self, command: str) -> bool:
        """检查命令是否可用"""
        try:
            # 使用较短的超时时间（2秒）
            result = await asyncio.wait_for(
                self._run_command(["which", command], timeout=2),
                timeout=2.0
            )
            return result.get("success", False)
        except (asyncio.TimeoutError, Exception):
            return False
    
    def get_environment_state(self) -> Dict[str, Any]:
        """获取环境状态"""
        return {
            "environment_state": self.environment_state,
            "installed_packages": self.installed_packages,
            "created_files": self.created_files,
            "environment_variables": self.environment_variables,
            "action_history_count": len(self.action_history)
        }
    
    def get_action_history(self) -> List[Dict[str, Any]]:
        """获取操作历史"""
        return self.action_history.copy()
    
    def get_status(self) -> Dict[str, Any]:
        """获取状态"""
        return {
            "environment_ready": True,
            "installed_packages_count": len(self.installed_packages),
            "created_files_count": len(self.created_files),
            "environment_variables_count": len(self.environment_variables),
            "action_history_count": len(self.action_history)
        }
