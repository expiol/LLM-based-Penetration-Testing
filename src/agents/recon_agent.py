"""
侦察Agent - 专门负责信息收集和目标侦察
按照Cyber Kill Chain的侦察阶段设计
参考PentestGPT的侦察策略
"""
import asyncio
import logging
import subprocess
import json
import socket
from typing import Dict, Any, List, Optional
from datetime import datetime

from .base_agent import BaseAgent
from ..database.logging_service import pentest_logger
from ..orchestrator.states import AgentType


class ReconAgent(BaseAgent):
    """侦察Agent - 负责信息收集、端口扫描、服务识别等"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            "ReconAgent", 
            config.get("safe_mode", True) if config else True,
            AgentType.RECON_AGENT
        )
        
        self.config = config or {}
        
        # 侦察配置
        self.scan_timeout = self.config.get("scan_timeout", 300)  # 5分钟超时
        self.max_ports = self.config.get("max_ports", 1000)
        self.stealth_mode = self.config.get("stealth_mode", True)
        
        self.logger.info(f"侦察Agent初始化完成")
    
    async def execute(self, target_info: Dict[str, Any], context: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        执行侦察任务
        
        Args:
            target_info: 目标信息
            context: 执行上下文（包含session_id, stage_id等）
            
        Returns:
            Dict[str, Any]: 侦察结果
        """
        try:
            if not self.validate_input(target_info):
                return self.create_result(success=False, error="输入验证失败")
            
            target = target_info["target"]
            session_context = context[0] if context else {}
            session_id = session_context.get("session_id")
            
            self.logger.info(f"开始侦察目标: {target}")
            
            # 记录开始侦察
            if session_id:
                pentest_logger.log_agent_action(
                    session_id=session_id,
                    agent_name=self.name,
                    agent_type=AgentType.RECON_AGENT,
                    log_level="INFO",
                    log_type="EXECUTION",
                    message=f"开始侦察目标: {target}",
                    details={"target": target, "available_tools": self.get_available_tools()}
                )
            
            # 初始化工具（如果还未初始化）
            await self.initialize_tools()
            
            # 执行分阶段侦察（使用新工具架构）
            recon_results = await self._perform_comprehensive_reconnaissance_with_tools(target, session_id)
            
            # 分析和整理结果
            analyzed_results = await self._analyze_reconnaissance_results(recon_results)
            
            self.logger.info(f"侦察完成 - 发现 {len(analyzed_results.get('services', []))} 个服务")
            
            return self.create_result(
                success=True,
                data=analyzed_results
            )
            
        except Exception as e:
            self.logger.error(f"侦察任务失败: {e}")
            return self.create_result(success=False, error=str(e))
    
    async def _perform_comprehensive_reconnaissance(self, target: str, session_id: str) -> Dict[str, Any]:
        """
        执行全面侦察
        
        Args:
            target: 目标地址
            session_id: 会话ID
            
        Returns:
            Dict[str, Any]: 侦察结果
        """
        results = {
            "target": target,
            "dns_info": {},
            "port_scan": {},
            "service_detection": {},
            "os_detection": {},
            "vulnerability_scan": {},
            "raw_outputs": {}
        }
        
        # 1. DNS信息收集
        self.logger.info("执行DNS信息收集")
        dns_info = await self._collect_dns_information(target, session_id)
        results["dns_info"] = dns_info
        
        # 2. 端口扫描
        self.logger.info("执行端口扫描")
        port_scan = await self._perform_port_scan(target, session_id)
        results["port_scan"] = port_scan
        
        # 3. 服务识别
        if port_scan.get("open_ports"):
            self.logger.info("执行服务识别")
            service_detection = await self._perform_service_detection(target, port_scan["open_ports"], session_id)
            results["service_detection"] = service_detection
        
        # 4. 操作系统识别（在安全模式下跳过）
        if not self.safe_mode and port_scan.get("open_ports"):
            self.logger.info("执行操作系统识别")
            os_detection = await self._perform_os_detection(target, session_id)
            results["os_detection"] = os_detection
        
        # 5. 基础漏洞扫描
        if not self.safe_mode and port_scan.get("open_ports"):
            self.logger.info("执行基础漏洞扫描")
            vuln_scan = await self._perform_vulnerability_scan(target, session_id)
            results["vulnerability_scan"] = vuln_scan
        
        return results
    
    async def _collect_dns_information(self, target: str, session_id: str) -> Dict[str, Any]:
        """收集DNS信息"""
        dns_info = {}
        
        try:
            # 记录工具执行
            tool_exec_id = pentest_logger.log_tool_execution(
                session_id=session_id,
                tool_name="nslookup",
                command=f"nslookup {target}",
                safe_mode=self.safe_mode,
                risk_level="LOW"
            )
            
            if self.tools_available.get("nslookup"):
                cmd = ["nslookup", target]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=30
                )
                
                dns_info = {
                    "command": " ".join(cmd),
                    "success": process.returncode == 0,
                    "stdout": stdout.decode() if stdout else "",
                    "stderr": stderr.decode() if stderr else ""
                }
                
                # 完成工具执行记录
                pentest_logger.complete_tool_execution(
                    tool_exec_id=tool_exec_id,
                    success=process.returncode == 0,
                    return_code=process.returncode,
                    stdout=dns_info["stdout"],
                    stderr=dns_info["stderr"]
                )
            
            else:
                # 使用Python socket进行基础DNS查询
                try:
                    ip = socket.gethostbyname(target)
                    dns_info = {
                        "command": f"Python socket.gethostbyname({target})",
                        "success": True,
                        "ip_address": ip,
                        "method": "python_socket"
                    }
                except socket.gaierror as e:
                    dns_info = {
                        "command": f"Python socket.gethostbyname({target})",
                        "success": False,
                        "error": str(e)
                    }
        
        except asyncio.TimeoutError:
            dns_info = {"success": False, "error": "DNS查询超时"}
        except Exception as e:
            dns_info = {"success": False, "error": str(e)}
        
        return dns_info
    
    async def _perform_port_scan(self, target: str, session_id: str) -> Dict[str, Any]:
        """执行端口扫描"""
        port_scan_result = {}
        
        try:
            if self.tools_available.get("nmap") and not self.safe_mode:
                # 使用nmap进行端口扫描
                port_scan_result = await self._nmap_port_scan(target, session_id)
            else:
                # 使用Python socket进行基础端口扫描
                port_scan_result = await self._socket_port_scan(target, session_id)
        
        except Exception as e:
            self.logger.error(f"端口扫描失败: {e}")
            port_scan_result = {"success": False, "error": str(e)}
        
        return port_scan_result
    
    async def _nmap_port_scan(self, target: str, session_id: str) -> Dict[str, Any]:
        """使用nmap进行端口扫描"""
        # 构建nmap命令
        if self.stealth_mode:
            cmd = ["nmap", "-sS", "-T4", "-p", "1-1000", target]
        else:
            cmd = ["nmap", "-sT", "-T4", "-p", "1-1000", target]
        
        # 记录工具执行
        tool_exec_id = pentest_logger.log_tool_execution(
            session_id=session_id,
            tool_name="nmap",
            command=" ".join(cmd),
            parameters={"stealth_mode": self.stealth_mode, "port_range": "1-1000"},
            safe_mode=self.safe_mode,
            risk_level="MEDIUM" if not self.safe_mode else "LOW"
        )
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.scan_timeout
            )
            
            output = stdout.decode() if stdout else ""
            error = stderr.decode() if stderr else ""
            
            # 解析nmap输出
            open_ports = self._parse_nmap_output(output)
            
            result = {
                "command": " ".join(cmd),
                "success": process.returncode == 0,
                "open_ports": open_ports,
                "raw_output": output,
                "error": error if error else None
            }
            
            # 完成工具执行记录
            pentest_logger.complete_tool_execution(
                tool_exec_id=tool_exec_id,
                success=process.returncode == 0,
                return_code=process.returncode,
                stdout=output,
                stderr=error
            )
            
            return result
            
        except asyncio.TimeoutError:
            return {"success": False, "error": "端口扫描超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _socket_port_scan(self, target: str, session_id: str) -> Dict[str, Any]:
        """使用Python socket进行基础端口扫描"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3389, 5432, 8080]
        open_ports = []
        
        # 记录工具执行
        tool_exec_id = pentest_logger.log_tool_execution(
            session_id=session_id,
            tool_name="python_socket",
            command=f"socket scan on {target}",
            parameters={"ports": common_ports},
            safe_mode=True,  # socket扫描总是安全的
            risk_level="LOW"
        )
        
        try:
            # 并发扫描端口
            tasks = []
            for port in common_ports:
                task = self._check_port(target, port)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if isinstance(result, bool) and result:
                    open_ports.append({
                        "port": common_ports[i],
                        "state": "open",
                        "service": self._guess_service(common_ports[i])
                    })
            
            scan_result = {
                "command": f"Python socket scan on {target}",
                "success": True,
                "open_ports": open_ports,
                "method": "python_socket",
                "ports_scanned": common_ports
            }
            
            # 完成工具执行记录
            pentest_logger.complete_tool_execution(
                tool_exec_id=tool_exec_id,
                success=True,
                return_code=0,
                stdout=json.dumps(scan_result, indent=2)
            )
            
            return scan_result
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _check_port(self, target: str, port: int) -> bool:
        """检查单个端口是否开放"""
        try:
            future = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(future, timeout=3)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    def _guess_service(self, port: int) -> str:
        """根据端口号猜测服务"""
        port_service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https",
            993: "imaps", 995: "pop3s", 1433: "mssql", 3389: "rdp",
            5432: "postgresql", 8080: "http-alt"
        }
        return port_service_map.get(port, "unknown")
    
    async def _perform_service_detection(self, target: str, open_ports: List[Dict[str, Any]], session_id: str) -> Dict[str, Any]:
        """执行服务识别"""
        # 在安全模式下，只进行基础的服务识别
        services = []
        
        for port_info in open_ports:
            port = port_info.get("port")
            service_info = {
                "port": port,
                "service": port_info.get("service", "unknown"),
                "state": "open",
                "detection_method": "port_based_guess"
            }
            
            # 尝试获取banner信息（仅在非安全模式下）
            if not self.safe_mode:
                banner = await self._get_service_banner(target, port)
                if banner:
                    service_info["banner"] = banner
                    service_info["detection_method"] = "banner_grab"
            
            services.append(service_info)
        
        return {
            "success": True,
            "services": services,
            "target": target
        }
    
    async def _get_service_banner(self, target: str, port: int) -> Optional[str]:
        """获取服务banner"""
        try:
            future = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(future, timeout=5)
            
            # 读取banner
            banner = await asyncio.wait_for(reader.read(1024), timeout=3)
            
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore').strip()
        except:
            return None
    
    def _parse_nmap_output(self, output: str) -> List[Dict[str, Any]]:
        """解析nmap输出"""
        open_ports = []
        lines = output.split('\n')
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    
                    port = int(port_proto.split('/')[0])
                    
                    open_ports.append({
                        "port": port,
                        "protocol": "tcp",
                        "state": state,
                        "service": service
                    })
        
        return open_ports
    
    async def _perform_os_detection(self, target: str, session_id: str) -> Dict[str, Any]:
        """执行操作系统识别（仅在非安全模式下）"""
        if self.safe_mode:
            return {"skipped": True, "reason": "Safe mode enabled"}
        
        # TODO: 实现OS检测逻辑
        return {"success": False, "error": "OS detection not implemented"}
    
    async def _perform_vulnerability_scan(self, target: str, session_id: str) -> Dict[str, Any]:
        """执行基础漏洞扫描（仅在非安全模式下）"""
        if self.safe_mode:
            return {"skipped": True, "reason": "Safe mode enabled"}
        
        # TODO: 实现漏洞扫描逻辑
        return {"success": False, "error": "Vulnerability scan not implemented"}
    
    async def _analyze_reconnaissance_results(self, recon_results: Dict[str, Any]) -> Dict[str, Any]:
        """分析和整理侦察结果"""
        analyzed = {
            "target": recon_results["target"],
            "services": [],
            "vulnerabilities": [],
            "intelligence": {},
            "summary": {}
        }
        
        # 整理服务信息
        if recon_results.get("service_detection", {}).get("services"):
            analyzed["services"] = recon_results["service_detection"]["services"]
        elif recon_results.get("port_scan", {}).get("open_ports"):
            analyzed["services"] = recon_results["port_scan"]["open_ports"]
        
        # 生成摘要
        analyzed["summary"] = {
            "total_services": len(analyzed["services"]),
            "open_ports": [s.get("port") for s in analyzed["services"]],
            "identified_services": [s.get("service") for s in analyzed["services"] if s.get("service") != "unknown"],
            "dns_resolved": recon_results.get("dns_info", {}).get("success", False),
            "scan_successful": recon_results.get("port_scan", {}).get("success", False)
        }
        
        # 生成情报信息
        analyzed["intelligence"] = {
            "attack_surface": self._assess_attack_surface(analyzed["services"]),
            "priority_targets": self._identify_priority_targets(analyzed["services"]),
            "next_steps": self._suggest_next_steps(analyzed["services"])
        }
        
        return analyzed
    
    def _assess_attack_surface(self, services: List[Dict[str, Any]]) -> Dict[str, Any]:
        """评估攻击面"""
        web_services = [s for s in services if s.get("service") in ["http", "https", "http-alt"]]
        ssh_services = [s for s in services if s.get("service") == "ssh"]
        database_services = [s for s in services if s.get("service") in ["mysql", "postgresql", "mssql"]]
        
        return {
            "web_services": len(web_services),
            "remote_access": len(ssh_services),
            "databases": len(database_services),
            "total_services": len(services),
            "risk_level": "HIGH" if len(services) > 10 else "MEDIUM" if len(services) > 5 else "LOW"
        }
    
    def _identify_priority_targets(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """识别优先目标"""
        priority_services = ["http", "https", "ssh", "ftp", "telnet", "rdp"]
        priorities = []
        
        for service in services:
            if service.get("service") in priority_services:
                priority = {
                    "port": service.get("port"),
                    "service": service.get("service"),
                    "priority": "HIGH" if service.get("service") in ["http", "https", "ssh"] else "MEDIUM",
                    "reason": f"{service.get('service')} service commonly targeted"
                }
                priorities.append(priority)
        
        return sorted(priorities, key=lambda x: x["priority"], reverse=True)
    
    def _suggest_next_steps(self, services: List[Dict[str, Any]]) -> List[str]:
        """建议下一步行动"""
        suggestions = []
        
        web_services = [s for s in services if s.get("service") in ["http", "https", "http-alt"]]
        if web_services:
            suggestions.append("对Web服务进行目录枚举和漏洞扫描")
        
        ssh_services = [s for s in services if s.get("service") == "ssh"]
        if ssh_services:
            suggestions.append("尝试SSH暴力破解或密钥认证")
        
        ftp_services = [s for s in services if s.get("service") == "ftp"]
        if ftp_services:
            suggestions.append("检查FTP匿名访问和暴力破解")
        
        if not suggestions:
            suggestions.append("进行更深入的服务指纹识别")
        
        return suggestions
    
    def _check_nmap_available(self) -> bool:
        """检查nmap是否可用"""
        try:
            result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def _check_nslookup_available(self) -> bool:
        """检查nslookup是否可用"""
        try:
            result = subprocess.run(["nslookup", "--help"], capture_output=True, text=True)
            return result.returncode == 0 or result.returncode == 1  # nslookup可能返回1但仍然可用
        except:
            return False
    
    def _check_ping_available(self) -> bool:
        """检查ping是否可用"""
        try:
            result = subprocess.run(["ping", "-c", "1", "127.0.0.1"], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def get_capabilities(self) -> List[str]:
        """获取侦察Agent的能力列表"""
        return [
            "dns_information_gathering",
            "port_scanning",
            "service_detection", 
            "os_fingerprinting",
            "vulnerability_discovery",
            "attack_surface_analysis",
            "intelligence_analysis",
            "banner_grabbing",
            "subdomain_enumeration"
        ]
    
    def get_agent_type(self) -> AgentType:
        """获取Agent类型"""
        return AgentType.RECON_AGENT
    
    async def _perform_comprehensive_reconnaissance_with_tools(self, target: str, session_id: str) -> Dict[str, Any]:
        """
        使用新工具架构执行全面侦察
        
        Args:
            target: 目标地址
            session_id: 会话ID
            
        Returns:
            Dict[str, Any]: 侦察结果
        """
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "port_scan": {},
            "service_detection": {},
            "dns_enumeration": {},
            "subdomain_enumeration": {},
            "errors": []
        }
        
        try:
            # 1. 端口扫描
            self.logger.info("开始端口扫描")
            port_scan_result = await self.execute_tool(
                "nmap",
                {
                    "target": target,
                    "ports": f"1-{self.max_ports}",
                    "scan_type": "tcp_syn" if self.stealth_mode else "tcp_connect",
                    "service_detection": True,
                    "os_detection": not self.stealth_mode
                }
            )
            
            if port_scan_result.get("success"):
                results["port_scan"] = port_scan_result.get("result", {})
                self.logger.info("端口扫描完成")
            else:
                error_msg = f"端口扫描失败: {port_scan_result.get('error')}"
                self.logger.error(error_msg)
                results["errors"].append(error_msg)
            
            # 2. DNS枚举
            self.logger.info("开始DNS枚举")
            dns_result = await self.execute_tool(
                "dns_enum",
                {"domain": target}
            )
            
            if dns_result.get("success"):
                results["dns_enumeration"] = dns_result.get("dns_records", {})
                self.logger.info("DNS枚举完成")
            else:
                error_msg = f"DNS枚举失败: {dns_result.get('error')}"
                self.logger.error(error_msg)
                results["errors"].append(error_msg)
            
            # 3. 子域名枚举
            self.logger.info("开始子域名枚举")
            subdomain_result = await self.execute_tool(
                "subdomain_enum",
                {
                    "domain": target,
                    "methods": ["dns_brute", "certificate_transparency"],
                    "timeout": self.scan_timeout
                }
            )
            
            if subdomain_result.get("success"):
                results["subdomain_enumeration"] = subdomain_result.get("result", {})
                self.logger.info("子域名枚举完成")
            else:
                error_msg = f"子域名枚举失败: {subdomain_result.get('error')}"
                self.logger.error(error_msg)
                results["errors"].append(error_msg)
            
            # 记录工具使用统计
            tool_stats = self.get_tool_usage_statistics()
            results["tool_statistics"] = tool_stats
            
        except Exception as e:
            error_msg = f"侦察过程异常: {str(e)}"
            self.logger.error(error_msg)
            results["errors"].append(error_msg)
        
        return results