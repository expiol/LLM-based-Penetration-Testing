"""
命令控制Agent - 负责建立和维护与被攻陷系统的通信
按照Cyber Kill Chain的命令控制阶段设计
"""
import asyncio
import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime

from .base_agent import BaseAgent
from ..database.logging_service import pentest_logger
from ..orchestrator.states import AgentType


class C2Agent(BaseAgent):
    """命令控制Agent - 负责C2通信和远程控制"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("C2Agent", config.get("safe_mode", True) if config else True)
        
        self.config = config or {}
        
        # C2配置
        self.c2_server_host = config.get("c2_server_host", "127.0.0.1")
        self.c2_server_port = config.get("c2_server_port", 8443)
        self.communication_protocol = config.get("communication_protocol", "https")
        self.beacon_interval = config.get("beacon_interval", 60)  # 秒
        self.encryption_enabled = config.get("encryption_enabled", True)
        
        self.logger.info(f"C2Agent初始化完成 - Safe Mode: {self.safe_mode}")
    
    async def execute(self, target_info: Dict[str, Any], context: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        执行命令控制任务
        
        Args:
            target_info: 目标信息
            context: 执行上下文（包含安装结果）
            
        Returns:
            Dict[str, Any]: C2执行结果
        """
        try:
            if not self.validate_input(target_info):
                return self.create_result(success=False, error="输入验证失败")
            
            target = target_info["target"]
            session_context = context[0] if context else {}
            session_id = session_context.get("session_id")
            
            # 获取安装结果
            global_context = session_context.get("global_context", {})
            successful_installations = global_context.get("successful_installations", [])
            backdoors_installed = global_context.get("backdoors_installed", [])
            
            self.logger.info(f"开始C2通信 - 目标: {target}, 后门数量: {len(backdoors_installed)}")
            
            # 记录开始C2
            if session_id:
                pentest_logger.log_agent_action(
                    session_id=session_id,
                    agent_name=self.name,
                    agent_type=AgentType.C2_AGENT,
                    log_level="INFO",
                    log_type="EXECUTION",
                    message=f"开始建立C2通信 - 目标: {target}",
                    details={
                        "target": target,
                        "backdoors_count": len(backdoors_installed),
                        "installations_count": len(successful_installations)
                    }
                )
            
            # 执行C2通信
            c2_results = await self._establish_c2_communication(
                target, successful_installations, backdoors_installed, session_id
            )
            
            active_channels = len([c for c in c2_results.get("communication_channels", []) 
                                 if c.get("status") == "active"])
            
            self.logger.info(f"C2通信完成 - 活跃通道: {active_channels}")
            
            return self.create_result(
                success=True,
                data=c2_results
            )
            
        except Exception as e:
            self.logger.error(f"C2通信任务失败: {e}")
            return self.create_result(success=False, error=str(e))
    
    async def _establish_c2_communication(self, target: str, successful_installations: List[Dict[str, Any]], 
                                        backdoors_installed: List[Dict[str, Any]], session_id: str) -> Dict[str, Any]:
        """
        建立C2通信
        
        Args:
            target: 目标地址
            successful_installations: 成功的安装
            backdoors_installed: 安装的后门
            session_id: 会话ID
            
        Returns:
            Dict[str, Any]: C2结果
        """
        results = {
            "target": target,
            "c2_server": {
                "host": self.c2_server_host,
                "port": self.c2_server_port,
                "protocol": self.communication_protocol
            },
            "communication_channels": [],
            "active_sessions": [],
            "command_executions": [],
            "data_exfiltration": [],
            "beacon_status": {}
        }
        
        # 1. 启动C2服务器
        c2_server_status = await self._start_c2_server(session_id)
        results["c2_server_status"] = c2_server_status
        
        # 2. 建立通信通道
        for backdoor in backdoors_installed:
            if backdoor.get("success"):
                channel = await self._establish_communication_channel(target, backdoor, session_id)
                results["communication_channels"].append(channel)
        
        # 3. 验证通信
        active_channels = [c for c in results["communication_channels"] if c.get("status") == "active"]
        if active_channels:
            communication_test = await self._test_communication(target, active_channels, session_id)
            results["communication_test"] = communication_test
        
        # 4. 建立持久会话
        for channel in active_channels:
            session_result = await self._establish_persistent_session(target, channel, session_id)
            results["active_sessions"].append(session_result)
        
        # 5. 执行初始命令
        if results["active_sessions"]:
            initial_commands = await self._execute_initial_commands(target, results["active_sessions"], session_id)
            results["command_executions"].extend(initial_commands)
        
        # 6. 配置信标
        beacon_config = await self._configure_beacon(target, active_channels, session_id)
        results["beacon_status"] = beacon_config
        
        return results
    
    async def _start_c2_server(self, session_id: str) -> Dict[str, Any]:
        """启动C2服务器"""
        # 记录工具执行
        tool_exec_id = pentest_logger.log_tool_execution(
            session_id=session_id,
            tool_name="c2_server",
            command=f"Start C2 server on {self.c2_server_host}:{self.c2_server_port}",
            parameters={
                "host": self.c2_server_host,
                "port": self.c2_server_port,
                "protocol": self.communication_protocol
            },
            safe_mode=self.safe_mode,
            risk_level="HIGH"
        )
        
        if self.safe_mode:
            # 模拟C2服务器启动
            result = {
                "status": "running",
                "host": self.c2_server_host,
                "port": self.c2_server_port,
                "protocol": self.communication_protocol,
                "encryption": self.encryption_enabled,
                "start_time": datetime.now().isoformat(),
                "simulation": True
            }
        else:
            # 实际C2服务器应该在这里启动
            self.logger.warning("实际C2服务器启动功能未实现")
            result = {"status": "failed", "error": "实际C2服务器启动未实现"}
        
        # 完成工具执行记录
        pentest_logger.complete_tool_execution(
            tool_exec_id=tool_exec_id,
            success=result.get("status") == "running",
            return_code=0 if result.get("status") == "running" else 1,
            stdout=json.dumps(result, indent=2)
        )
        
        return result
    
    async def _establish_communication_channel(self, target: str, backdoor: Dict[str, Any], 
                                             session_id: str) -> Dict[str, Any]:
        """建立通信通道"""
        backdoor_type = backdoor.get("backdoor_type", "unknown")
        
        if backdoor_type == "reverse_shell":
            return await self._establish_reverse_shell_channel(target, backdoor, session_id)
        elif backdoor_type == "bind_shell":
            return await self._establish_bind_shell_channel(target, backdoor, session_id)
        elif backdoor_type == "web_shell":
            return await self._establish_web_shell_channel(target, backdoor, session_id)
        elif backdoor_type == "database_backdoor":
            return await self._establish_database_channel(target, backdoor, session_id)
        else:
            return await self._establish_generic_channel(target, backdoor, session_id)
    
    async def _establish_reverse_shell_channel(self, target: str, backdoor: Dict[str, Any], 
                                             session_id: str) -> Dict[str, Any]:
        """建立反向Shell通道"""
        if self.safe_mode:
            return {
                "channel_type": "reverse_shell",
                "status": "active",
                "target": target,
                "callback_host": backdoor.get("callback_host"),
                "callback_port": backdoor.get("callback_port"),
                "protocol": backdoor.get("protocol", "tcp"),
                "encryption": self.encryption_enabled,
                "established_at": datetime.now().isoformat(),
                "simulation": True
            }
        else:
            self.logger.warning("实际反向Shell通道建立功能未实现")
            return {"channel_type": "reverse_shell", "status": "failed", "error": "未实现"}
    
    async def _establish_bind_shell_channel(self, target: str, backdoor: Dict[str, Any], 
                                          session_id: str) -> Dict[str, Any]:
        """建立绑定Shell通道"""
        if self.safe_mode:
            return {
                "channel_type": "bind_shell",
                "status": "active",
                "target": target,
                "listen_port": backdoor.get("listen_port"),
                "protocol": backdoor.get("protocol", "tcp"),
                "encryption": self.encryption_enabled,
                "established_at": datetime.now().isoformat(),
                "simulation": True
            }
        else:
            self.logger.warning("实际绑定Shell通道建立功能未实现")
            return {"channel_type": "bind_shell", "status": "failed", "error": "未实现"}
    
    async def _establish_web_shell_channel(self, target: str, backdoor: Dict[str, Any], 
                                         session_id: str) -> Dict[str, Any]:
        """建立Web Shell通道"""
        if self.safe_mode:
            return {
                "channel_type": "web_shell",
                "status": "active",
                "target": target,
                "shell_url": f"http://{target}/includes/config.php",
                "access_parameter": "cmd",
                "protocol": "http",
                "established_at": datetime.now().isoformat(),
                "simulation": True
            }
        else:
            self.logger.warning("实际Web Shell通道建立功能未实现")
            return {"channel_type": "web_shell", "status": "failed", "error": "未实现"}
    
    async def _establish_database_channel(self, target: str, backdoor: Dict[str, Any], 
                                        session_id: str) -> Dict[str, Any]:
        """建立数据库通道"""
        if self.safe_mode:
            return {
                "channel_type": "database_backdoor",
                "status": "active",
                "target": target,
                "function_name": backdoor.get("function_name"),
                "access_method": backdoor.get("access_method"),
                "protocol": "sql",
                "established_at": datetime.now().isoformat(),
                "simulation": True
            }
        else:
            self.logger.warning("实际数据库通道建立功能未实现")
            return {"channel_type": "database_backdoor", "status": "failed", "error": "未实现"}
    
    async def _establish_generic_channel(self, target: str, backdoor: Dict[str, Any], 
                                       session_id: str) -> Dict[str, Any]:
        """建立通用通道"""
        return {
            "channel_type": "generic",
            "status": "failed",
            "target": target,
            "error": "不支持的后门类型",
            "simulation": self.safe_mode
        }
    
    async def _test_communication(self, target: str, active_channels: List[Dict[str, Any]], 
                                session_id: str) -> Dict[str, Any]:
        """测试通信"""
        test_results = {
            "total_channels": len(active_channels),
            "successful_tests": 0,
            "failed_tests": 0,
            "test_details": []
        }
        
        for channel in active_channels:
            test_result = await self._test_single_channel(target, channel, session_id)
            test_results["test_details"].append(test_result)
            
            if test_result.get("success"):
                test_results["successful_tests"] += 1
            else:
                test_results["failed_tests"] += 1
        
        return test_results
    
    async def _test_single_channel(self, target: str, channel: Dict[str, Any], 
                                 session_id: str) -> Dict[str, Any]:
        """测试单个通道"""
        channel_type = channel.get("channel_type")
        
        if self.safe_mode:
            # 模拟通信测试
            return {
                "channel_type": channel_type,
                "success": True,
                "test_command": "whoami",
                "response": "www-data",
                "latency_ms": 150,
                "simulation": True
            }
        else:
            # 实际通信测试应该在这里实现
            return {
                "channel_type": channel_type,
                "success": False,
                "error": "实际通信测试未实现"
            }
    
    async def _establish_persistent_session(self, target: str, channel: Dict[str, Any], 
                                          session_id: str) -> Dict[str, Any]:
        """建立持久会话"""
        if self.safe_mode:
            return {
                "session_id": f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "channel_type": channel.get("channel_type"),
                "target": target,
                "status": "active",
                "established_at": datetime.now().isoformat(),
                "last_activity": datetime.now().isoformat(),
                "capabilities": ["command_execution", "file_transfer", "port_forwarding"],
                "simulation": True
            }
        else:
            return {
                "status": "failed",
                "error": "实际持久会话建立未实现"
            }
    
    async def _execute_initial_commands(self, target: str, active_sessions: List[Dict[str, Any]], 
                                      session_id: str) -> List[Dict[str, Any]]:
        """执行初始命令"""
        command_executions = []
        
        # 基础系统信息收集命令
        initial_commands = [
            "whoami",
            "id",
            "uname -a",
            "cat /etc/passwd",
            "ps aux",
            "netstat -tlnp",
            "ifconfig"
        ]
        
        for session in active_sessions:
            if session.get("status") == "active":
                for cmd in initial_commands:
                    execution_result = await self._execute_command(target, session, cmd, session_id)
                    command_executions.append(execution_result)
                    
                    # 添加延迟以避免检测
                    await asyncio.sleep(1)
        
        return command_executions
    
    async def _execute_command(self, target: str, session: Dict[str, Any], 
                             command: str, session_id: str) -> Dict[str, Any]:
        """执行单个命令"""
        # 记录工具执行
        tool_exec_id = pentest_logger.log_tool_execution(
            session_id=session_id,
            tool_name="c2_command",
            command=command,
            parameters={
                "target": target,
                "session_id": session.get("session_id"),
                "channel_type": session.get("channel_type")
            },
            safe_mode=self.safe_mode,
            risk_level="MEDIUM"
        )
        
        if self.safe_mode:
            # 模拟命令执行结果
            mock_responses = {
                "whoami": "www-data",
                "id": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
                "uname -a": "Linux target-server 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux",
                "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
                "ps aux": "root      1  0.0  0.1 225340  8944 ?        Ss   10:00   0:02 /sbin/init",
                "netstat -tlnp": "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -",
                "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100"
            }
            
            result = {
                "command": command,
                "success": True,
                "output": mock_responses.get(command, f"Command '{command}' executed"),
                "exit_code": 0,
                "execution_time": 0.5,
                "session_id": session.get("session_id"),
                "timestamp": datetime.now().isoformat(),
                "simulation": True
            }
        else:
            # 实际命令执行应该在这里实现
            result = {
                "command": command,
                "success": False,
                "error": "实际命令执行未实现"
            }
        
        # 完成工具执行记录
        pentest_logger.complete_tool_execution(
            tool_exec_id=tool_exec_id,
            success=result.get("success", False),
            return_code=result.get("exit_code", 1),
            stdout=result.get("output", ""),
            stderr=result.get("error", "")
        )
        
        return result
    
    async def _configure_beacon(self, target: str, active_channels: List[Dict[str, Any]], 
                              session_id: str) -> Dict[str, Any]:
        """配置信标"""
        beacon_config = {
            "enabled": True,
            "interval": self.beacon_interval,
            "channels": len(active_channels),
            "protocol": self.communication_protocol,
            "encryption": self.encryption_enabled,
            "last_beacon": datetime.now().isoformat(),
            "beacon_data": {}
        }
        
        if self.safe_mode:
            # 模拟信标配置
            beacon_config.update({
                "simulation": True,
                "beacon_data": {
                    "hostname": "target-server",
                    "ip_address": target,
                    "user": "www-data",
                    "os": "Linux Ubuntu 20.04",
                    "uptime": "15 days"
                }
            })
        
        # 记录信标配置
        if session_id:
            pentest_logger.log_agent_action(
                session_id=session_id,
                agent_name=self.name,
                agent_type=AgentType.C2_AGENT,
                log_level="INFO",
                log_type="CONFIGURATION",
                message="配置C2信标",
                details=beacon_config
            )
        
        return beacon_config
    
    def get_capabilities(self) -> List[str]:
        """获取C2Agent的能力列表"""
        return [
            "c2_server_management",
            "communication_channel_establishment",
            "reverse_shell_handling",
            "bind_shell_handling",
            "web_shell_communication",
            "database_backdoor_communication",
            "command_execution",
            "file_transfer",
            "beacon_management",
            "session_persistence",
            "traffic_encryption"
        ]
