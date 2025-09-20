"""
目标行为Agent - 负责执行最终的渗透目标和数据获取
按照Cyber Kill Chain的目标行为阶段设计
"""
import asyncio
import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime

from .base_agent import BaseAgent
from ..database.logging_service import pentest_logger
from ..orchestrator.states import AgentType


class ObjectivesAgent(BaseAgent):
    """目标行为Agent - 负责数据获取、横向移动和目标完成"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("ObjectivesAgent", config.get("safe_mode", True) if config else True)
        
        self.config = config or {}
        
        # 目标配置
        self.data_collection_enabled = config.get("data_collection_enabled", True)
        self.lateral_movement_enabled = config.get("lateral_movement_enabled", False)
        self.privilege_maintenance = config.get("privilege_maintenance", True)
        self.evidence_collection = config.get("evidence_collection", True)
        self.cleanup_after_completion = config.get("cleanup_after_completion", True)
        
        self.logger.info(f"目标行为Agent初始化完成 - Safe Mode: {self.safe_mode}")
    
    async def execute(self, target_info: Dict[str, Any], context: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        执行目标行为任务
        
        Args:
            target_info: 目标信息
            context: 执行上下文（包含C2结果）
            
        Returns:
            Dict[str, Any]: 目标行为结果
        """
        try:
            if not self.validate_input(target_info):
                return self.create_result(success=False, error="输入验证失败")
            
            target = target_info["target"]
            session_context = context[0] if context else {}
            session_id = session_context.get("session_id")
            
            # 获取C2结果
            global_context = session_context.get("global_context", {})
            active_sessions = global_context.get("active_sessions", [])
            communication_channels = global_context.get("communication_channels", [])
            
            self.logger.info(f"开始目标行为 - 目标: {target}, 活跃会话: {len(active_sessions)}")
            
            # 记录开始目标行为
            if session_id:
                pentest_logger.log_agent_action(
                    session_id=session_id,
                    agent_name=self.name,
                    agent_type=AgentType.OBJECTIVES_AGENT,
                    log_level="INFO",
                    log_type="EXECUTION",
                    message=f"开始执行目标行为 - 目标: {target}",
                    details={
                        "target": target,
                        "active_sessions": len(active_sessions),
                        "communication_channels": len(communication_channels)
                    }
                )
            
            # 执行目标行为
            objectives_results = await self._execute_objectives(
                target, active_sessions, communication_channels, session_id
            )
            
            completed_objectives = len([o for o in objectives_results.get("objectives_executed", []) 
                                      if o.get("success")])
            
            self.logger.info(f"目标行为完成 - 完成目标: {completed_objectives}")
            
            return self.create_result(
                success=True,
                data=objectives_results
            )
            
        except Exception as e:
            self.logger.error(f"目标行为任务失败: {e}")
            return self.create_result(success=False, error=str(e))
    
    async def _execute_objectives(self, target: str, active_sessions: List[Dict[str, Any]], 
                                communication_channels: List[Dict[str, Any]], session_id: str) -> Dict[str, Any]:
        """
        执行目标行为
        
        Args:
            target: 目标地址
            active_sessions: 活跃会话
            communication_channels: 通信通道
            session_id: 会话ID
            
        Returns:
            Dict[str, Any]: 目标行为结果
        """
        results = {
            "target": target,
            "objectives_executed": [],
            "data_collected": [],
            "lateral_movement": [],
            "privilege_escalation": [],
            "evidence_gathered": [],
            "cleanup_actions": [],
            "mission_status": "in_progress"
        }
        
        # 1. 数据收集
        if self.data_collection_enabled and active_sessions:
            data_collection = await self._collect_sensitive_data(target, active_sessions, session_id)
            results["objectives_executed"].append({
                "objective": "data_collection",
                "success": data_collection.get("success", False),
                "details": data_collection
            })
            results["data_collected"] = data_collection.get("collected_data", [])
        
        # 2. 横向移动
        if self.lateral_movement_enabled and active_sessions and not self.safe_mode:
            lateral_movement = await self._perform_lateral_movement(target, active_sessions, session_id)
            results["objectives_executed"].append({
                "objective": "lateral_movement",
                "success": lateral_movement.get("success", False),
                "details": lateral_movement
            })
            results["lateral_movement"] = lateral_movement.get("movement_results", [])
        
        # 3. 权限维持
        if self.privilege_maintenance and active_sessions:
            privilege_maintenance = await self._maintain_privileges(target, active_sessions, session_id)
            results["objectives_executed"].append({
                "objective": "privilege_maintenance",
                "success": privilege_maintenance.get("success", False),
                "details": privilege_maintenance
            })
        
        # 4. 证据收集
        if self.evidence_collection:
            evidence_collection = await self._collect_evidence(target, active_sessions, session_id)
            results["objectives_executed"].append({
                "objective": "evidence_collection",
                "success": evidence_collection.get("success", False),
                "details": evidence_collection
            })
            results["evidence_gathered"] = evidence_collection.get("evidence", [])
        
        # 5. 清理工作
        if self.cleanup_after_completion:
            cleanup = await self._perform_cleanup(target, active_sessions, session_id)
            results["objectives_executed"].append({
                "objective": "cleanup",
                "success": cleanup.get("success", False),
                "details": cleanup
            })
            results["cleanup_actions"] = cleanup.get("cleanup_actions", [])
        
        # 6. 确定任务状态
        successful_objectives = [o for o in results["objectives_executed"] if o.get("success")]
        if len(successful_objectives) >= len(results["objectives_executed"]) * 0.7:
            results["mission_status"] = "completed"
        elif len(successful_objectives) > 0:
            results["mission_status"] = "partially_completed"
        else:
            results["mission_status"] = "failed"
        
        return results
    
    async def _collect_sensitive_data(self, target: str, active_sessions: List[Dict[str, Any]], 
                                    session_id: str) -> Dict[str, Any]:
        """收集敏感数据"""
        collection_result = {
            "success": True,
            "collected_data": [],
            "collection_methods": [],
            "total_files": 0,
            "total_size_mb": 0
        }
        
        # 定义要收集的敏感数据类型
        sensitive_targets = [
            {
                "type": "credentials",
                "paths": ["/etc/passwd", "/etc/shadow", "~/.ssh/id_rsa", "~/.bashrc"],
                "description": "System credentials and SSH keys"
            },
            {
                "type": "configuration",
                "paths": ["/etc/apache2/apache2.conf", "/etc/mysql/my.cnf", "/etc/ssh/sshd_config"],
                "description": "Application and service configurations"
            },
            {
                "type": "application_data",
                "paths": ["/var/www/html/config.php", "/var/lib/mysql/", "/opt/app/data/"],
                "description": "Application databases and data files"
            },
            {
                "type": "logs",
                "paths": ["/var/log/auth.log", "/var/log/apache2/access.log", "/var/log/syslog"],
                "description": "System and application logs"
            },
            {
                "type": "user_data",
                "paths": ["/home/*/Documents/", "/home/*/.ssh/", "/home/*/Desktop/"],
                "description": "User personal data and configurations"
            }
        ]
        
        for session in active_sessions:
            if session.get("status") == "active":
                for target_info in sensitive_targets:
                    collection_attempt = await self._collect_data_type(
                        target, session, target_info, session_id
                    )
                    
                    if collection_attempt.get("success"):
                        collection_result["collected_data"].extend(collection_attempt.get("files", []))
                        collection_result["collection_methods"].append(collection_attempt.get("method"))
                        collection_result["total_files"] += collection_attempt.get("file_count", 0)
                        collection_result["total_size_mb"] += collection_attempt.get("size_mb", 0)
        
        # 记录数据收集活动
        if session_id:
            pentest_logger.log_agent_action(
                session_id=session_id,
                agent_name=self.name,
                agent_type=AgentType.OBJECTIVES_AGENT,
                log_level="INFO",
                log_type="DATA_COLLECTION",
                message="执行敏感数据收集",
                details={
                    "total_files": collection_result["total_files"],
                    "total_size_mb": collection_result["total_size_mb"],
                    "data_types": [t["type"] for t in sensitive_targets]
                }
            )
        
        return collection_result
    
    async def _collect_data_type(self, target: str, session: Dict[str, Any], 
                               target_info: Dict[str, Any], session_id: str) -> Dict[str, Any]:
        """收集特定类型的数据"""
        data_type = target_info["type"]
        paths = target_info["paths"]
        
        if self.safe_mode:
            # 模拟数据收集
            return {
                "success": True,
                "data_type": data_type,
                "method": "file_enumeration",
                "files": [
                    {
                        "path": path,
                        "size_kb": 10 + (hash(path) % 100),
                        "permissions": "644",
                        "owner": "www-data",
                        "modified": "2024-01-15T10:30:00Z",
                        "content_preview": "# Configuration file..." if "config" in path else "sensitive_data_preview"
                    }
                    for path in paths[:2]  # 限制模拟文件数量
                ],
                "file_count": len(paths[:2]),
                "size_mb": round(sum([10 + (hash(p) % 100) for p in paths[:2]]) / 1024, 2),
                "simulation": True
            }
        else:
            # 实际数据收集应该在这里实现
            self.logger.warning("实际数据收集功能未实现")
            return {"success": False, "error": "实际数据收集未实现"}
    
    async def _perform_lateral_movement(self, target: str, active_sessions: List[Dict[str, Any]], 
                                      session_id: str) -> Dict[str, Any]:
        """执行横向移动"""
        if self.safe_mode:
            self.logger.info("安全模式下跳过横向移动")
            return {
                "success": False,
                "reason": "Safe mode enabled",
                "simulation": True
            }
        
        movement_result = {
            "success": True,
            "movement_results": [],
            "discovered_hosts": [],
            "compromised_hosts": [],
            "movement_methods": []
        }
        
        # 实际横向移动应该在这里实现
        self.logger.warning("横向移动功能未实现")
        return {"success": False, "error": "横向移动功能未实现"}
    
    async def _maintain_privileges(self, target: str, active_sessions: List[Dict[str, Any]], 
                                 session_id: str) -> Dict[str, Any]:
        """维持权限"""
        maintenance_result = {
            "success": True,
            "maintenance_actions": [],
            "backup_access_methods": [],
            "privilege_verification": {}
        }
        
        # 权限验证
        privilege_check = await self._verify_current_privileges(target, active_sessions, session_id)
        maintenance_result["privilege_verification"] = privilege_check
        
        # 创建备份访问方法
        if self.safe_mode:
            backup_methods = [
                {
                    "method": "additional_ssh_key",
                    "location": "/home/admin/.ssh/authorized_keys2",
                    "status": "installed",
                    "simulation": True
                },
                {
                    "method": "secondary_web_shell",
                    "location": "/var/www/html/assets/config.php",
                    "status": "installed",
                    "simulation": True
                },
                {
                    "method": "cron_persistence_backup",
                    "location": "/etc/cron.hourly/system-update",
                    "status": "installed",
                    "simulation": True
                }
            ]
            maintenance_result["backup_access_methods"] = backup_methods
        
        # 记录权限维持活动
        if session_id:
            pentest_logger.log_agent_action(
                session_id=session_id,
                agent_name=self.name,
                agent_type=AgentType.OBJECTIVES_AGENT,
                log_level="INFO",
                log_type="PRIVILEGE_MAINTENANCE",
                message="执行权限维持",
                details=maintenance_result
            )
        
        return maintenance_result
    
    async def _verify_current_privileges(self, target: str, active_sessions: List[Dict[str, Any]], 
                                       session_id: str) -> Dict[str, Any]:
        """验证当前权限"""
        if self.safe_mode:
            return {
                "user": "www-data",
                "groups": ["www-data"],
                "sudo_access": False,
                "root_access": False,
                "database_access": True,
                "file_permissions": "limited",
                "network_access": True,
                "simulation": True
            }
        else:
            return {"error": "实际权限验证未实现"}
    
    async def _collect_evidence(self, target: str, active_sessions: List[Dict[str, Any]], 
                              session_id: str) -> Dict[str, Any]:
        """收集证据"""
        evidence_result = {
            "success": True,
            "evidence": [],
            "evidence_types": [],
            "total_evidence_items": 0
        }
        
        # 定义要收集的证据类型
        evidence_types = [
            {
                "type": "vulnerability_proof",
                "description": "Proof of successful exploitation",
                "commands": ["id", "whoami", "uname -a"]
            },
            {
                "type": "access_demonstration",
                "description": "Demonstration of gained access",
                "commands": ["ls -la /etc/", "cat /etc/passwd", "ps aux"]
            },
            {
                "type": "network_information",
                "description": "Network topology and services",
                "commands": ["ifconfig", "netstat -tlnp", "arp -a"]
            },
            {
                "type": "system_information",
                "description": "System configuration and users",
                "commands": ["cat /proc/version", "w", "last"]
            }
        ]
        
        for session in active_sessions:
            if session.get("status") == "active":
                for evidence_type in evidence_types:
                    evidence_collection = await self._collect_evidence_type(
                        target, session, evidence_type, session_id
                    )
                    
                    if evidence_collection.get("success"):
                        evidence_result["evidence"].extend(evidence_collection.get("evidence_items", []))
                        evidence_result["evidence_types"].append(evidence_type["type"])
        
        evidence_result["total_evidence_items"] = len(evidence_result["evidence"])
        
        # 记录证据收集
        if session_id:
            pentest_logger.log_agent_action(
                session_id=session_id,
                agent_name=self.name,
                agent_type=AgentType.OBJECTIVES_AGENT,
                log_level="INFO",
                log_type="EVIDENCE_COLLECTION",
                message="收集渗透证据",
                details={
                    "total_evidence_items": evidence_result["total_evidence_items"],
                    "evidence_types": evidence_result["evidence_types"]
                }
            )
        
        return evidence_result
    
    async def _collect_evidence_type(self, target: str, session: Dict[str, Any], 
                                   evidence_type: Dict[str, Any], session_id: str) -> Dict[str, Any]:
        """收集特定类型的证据"""
        if self.safe_mode:
            # 模拟证据收集
            evidence_items = []
            for cmd in evidence_type["commands"]:
                # 模拟命令输出
                mock_outputs = {
                    "id": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
                    "whoami": "www-data",
                    "uname -a": "Linux target-server 5.4.0-74-generic #83-Ubuntu",
                    "ls -la /etc/": "drwxr-xr-x  2 root root 4096 Jan 15 10:30 .",
                    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash",
                    "ps aux": "root      1  0.0  0.1 225340  8944 ?",
                    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>",
                    "netstat -tlnp": "tcp        0      0 0.0.0.0:22",
                    "arp -a": "gateway (192.168.1.1) at 00:50:56:c0:00:08",
                    "cat /proc/version": "Linux version 5.4.0-74-generic",
                    "w": "10:30:45 up 15 days,  2:15,  1 user",
                    "last": "admin    pts/0        192.168.1.10"
                }
                
                evidence_items.append({
                    "command": cmd,
                    "output": mock_outputs.get(cmd, f"Output of {cmd}"),
                    "timestamp": datetime.now().isoformat(),
                    "session_id": session.get("session_id"),
                    "evidence_type": evidence_type["type"]
                })
            
            return {
                "success": True,
                "evidence_type": evidence_type["type"],
                "evidence_items": evidence_items,
                "simulation": True
            }
        else:
            return {"success": False, "error": "实际证据收集未实现"}
    
    async def _perform_cleanup(self, target: str, active_sessions: List[Dict[str, Any]], 
                             session_id: str) -> Dict[str, Any]:
        """执行清理工作"""
        cleanup_result = {
            "success": True,
            "cleanup_actions": [],
            "files_removed": [],
            "logs_cleaned": [],
            "traces_removed": []
        }
        
        if self.safe_mode:
            # 模拟清理动作
            cleanup_actions = [
                {
                    "action": "remove_temporary_files",
                    "description": "Remove temporary exploit files",
                    "files": ["/tmp/.exploit", "/tmp/.payload"],
                    "success": True,
                    "simulation": True
                },
                {
                    "action": "clean_command_history",
                    "description": "Clear bash history",
                    "files": ["/home/admin/.bash_history", "/root/.bash_history"],
                    "success": True,
                    "simulation": True
                },
                {
                    "action": "remove_log_entries",
                    "description": "Clean relevant log entries",
                    "logs": ["/var/log/auth.log", "/var/log/apache2/access.log"],
                    "success": True,
                    "simulation": True
                },
                {
                    "action": "restore_file_timestamps",
                    "description": "Restore original file timestamps",
                    "files": ["/etc/passwd", "/etc/shadow"],
                    "success": True,
                    "simulation": True
                }
            ]
            
            cleanup_result["cleanup_actions"] = cleanup_actions
            cleanup_result["files_removed"] = [
                action.get("files", []) for action in cleanup_actions 
                if action.get("action") == "remove_temporary_files"
            ]
            cleanup_result["logs_cleaned"] = [
                action.get("logs", []) for action in cleanup_actions 
                if action.get("action") == "remove_log_entries"
            ]
        
        # 记录清理活动
        if session_id:
            pentest_logger.log_agent_action(
                session_id=session_id,
                agent_name=self.name,
                agent_type=AgentType.OBJECTIVES_AGENT,
                log_level="INFO",
                log_type="CLEANUP",
                message="执行渗透痕迹清理",
                details={
                    "cleanup_actions": len(cleanup_result["cleanup_actions"]),
                    "files_cleaned": len(cleanup_result.get("files_removed", [])),
                    "logs_cleaned": len(cleanup_result.get("logs_cleaned", []))
                }
            )
        
        return cleanup_result
    
    def get_capabilities(self) -> List[str]:
        """获取目标行为Agent的能力列表"""
        return [
            "sensitive_data_collection",
            "lateral_movement",
            "privilege_maintenance",
            "evidence_collection",
            "credential_harvesting",
            "network_enumeration",
            "data_exfiltration",
            "trace_cleanup",
            "persistence_verification",
            "mission_completion"
        ]
