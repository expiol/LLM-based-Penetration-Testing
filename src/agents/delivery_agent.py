"""
投递Agent - 负责将攻击载荷投递到目标系统
按照Cyber Kill Chain的投递阶段设计
"""
import asyncio
import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime

from .base_agent import BaseAgent
from ..database.logging_service import pentest_logger
from ..orchestrator.states import AgentType


class DeliveryAgent(BaseAgent):
    """投递Agent - 负责载荷投递和攻击向量执行"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("DeliveryAgent", config.get("safe_mode", True) if config else True)
        
        self.config = config or {}
        
        # 投递配置
        self.delivery_timeout = config.get("delivery_timeout", 60)
        self.max_retry_attempts = config.get("max_retry_attempts", 3)
        self.stealth_mode = config.get("stealth_mode", True)
        
        self.logger.info(f"投递Agent初始化完成 - Safe Mode: {self.safe_mode}")
    
    async def execute(self, target_info: Dict[str, Any], context: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        执行投递任务
        
        Args:
            target_info: 目标信息
            context: 执行上下文（包含武器化结果）
            
        Returns:
            Dict[str, Any]: 投递结果
        """
        try:
            if not self.validate_input(target_info):
                return self.create_result(success=False, error="输入验证失败")
            
            target = target_info["target"]
            session_context = context[0] if context else {}
            session_id = session_context.get("session_id")
            
            # 获取武器化结果
            global_context = session_context.get("global_context", {})
            payloads = global_context.get("payloads", [])
            attack_vectors = global_context.get("attack_vectors", [])
            
            self.logger.info(f"开始投递 - 目标: {target}, 载荷数量: {len(payloads)}")
            
            # 记录开始投递
            if session_id:
                pentest_logger.log_agent_action(
                    session_id=session_id,
                    agent_name=self.name,
                    agent_type=AgentType.DELIVERY_AGENT,
                    log_level="INFO",
                    log_type="EXECUTION",
                    message=f"开始投递 - 目标: {target}",
                    details={
                        "target": target,
                        "payloads_count": len(payloads),
                        "attack_vectors_count": len(attack_vectors)
                    }
                )
            
            # 执行投递
            delivery_results = await self._perform_delivery(
                target, payloads, attack_vectors, session_id
            )
            
            self.logger.info(f"投递完成 - 成功投递: {delivery_results.get('successful_deliveries', 0)}")
            
            return self.create_result(
                success=True,
                data=delivery_results
            )
            
        except Exception as e:
            self.logger.error(f"投递任务失败: {e}")
            return self.create_result(success=False, error=str(e))
    
    async def _perform_delivery(self, target: str, payloads: List[Dict[str, Any]], 
                              attack_vectors: List[Dict[str, Any]], session_id: str) -> Dict[str, Any]:
        """
        执行投递过程
        
        Args:
            target: 目标地址
            payloads: 攻击载荷
            attack_vectors: 攻击向量
            session_id: 会话ID
            
        Returns:
            Dict[str, Any]: 投递结果
        """
        results = {
            "target": target,
            "delivery_attempts": [],
            "successful_deliveries": 0,
            "failed_deliveries": 0,
            "delivery_methods_used": [],
            "compromised_services": []
        }
        
        # 1. 分析投递策略
        delivery_strategy = await self._analyze_delivery_strategy(payloads, attack_vectors)
        results["delivery_strategy"] = delivery_strategy
        
        # 2. 执行Web应用投递
        web_results = await self._deliver_web_payloads(target, payloads, session_id)
        results["delivery_attempts"].extend(web_results)
        
        # 3. 执行网络服务投递
        network_results = await self._deliver_network_payloads(target, payloads, session_id)
        results["delivery_attempts"].extend(network_results)
        
        # 4. 执行社会工程投递（仅模拟）
        if not self.safe_mode:
            social_results = await self._simulate_social_engineering_delivery(target, payloads, session_id)
            results["delivery_attempts"].extend(social_results)
        
        # 5. 统计结果
        successful = [attempt for attempt in results["delivery_attempts"] if attempt.get("success")]
        results["successful_deliveries"] = len(successful)
        results["failed_deliveries"] = len(results["delivery_attempts"]) - len(successful)
        
        # 6. 记录成功的投递方法
        results["delivery_methods_used"] = list(set([
            attempt.get("method") for attempt in successful
        ]))
        
        # 7. 识别被攻陷的服务
        results["compromised_services"] = [
            attempt.get("target_service") for attempt in successful
        ]
        
        return results
    
    async def _analyze_delivery_strategy(self, payloads: List[Dict[str, Any]], 
                                       attack_vectors: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析投递策略"""
        strategy = {
            "primary_method": "web_application",
            "fallback_methods": [],
            "payload_prioritization": [],
            "timing_strategy": "immediate"
        }
        
        # 确定主要投递方法
        web_payloads = [p for p in payloads if p.get("type", "").startswith("web")]
        network_payloads = [p for p in payloads if p.get("type", "").endswith("injection")]
        
        if web_payloads:
            strategy["primary_method"] = "web_application"
            strategy["fallback_methods"].append("network_service")
        elif network_payloads:
            strategy["primary_method"] = "network_service"
            strategy["fallback_methods"].append("protocol_exploitation")
        
        # 载荷优先级
        priority_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        sorted_payloads = sorted(
            payloads,
            key=lambda x: priority_order.get(x.get("risk_level", "LOW"), 1),
            reverse=True
        )
        strategy["payload_prioritization"] = [p.get("type") for p in sorted_payloads[:5]]
        
        # 时间策略
        if self.stealth_mode:
            strategy["timing_strategy"] = "delayed_random"
        else:
            strategy["timing_strategy"] = "immediate"
        
        return strategy
    
    async def _deliver_web_payloads(self, target: str, payloads: List[Dict[str, Any]], 
                                  session_id: str) -> List[Dict[str, Any]]:
        """投递Web应用载荷"""
        delivery_attempts = []
        
        web_payloads = [p for p in payloads if "http" in p.get("target_service", "")]
        
        for payload in web_payloads:
            attempt = await self._attempt_web_delivery(target, payload, session_id)
            delivery_attempts.append(attempt)
            
            # 在隐蔽模式下添加延迟
            if self.stealth_mode:
                await asyncio.sleep(2)
        
        return delivery_attempts
    
    async def _attempt_web_delivery(self, target: str, payload: Dict[str, Any], 
                                  session_id: str) -> Dict[str, Any]:
        """尝试Web载荷投递"""
        payload_type = payload.get("type")
        payload_content = payload.get("payload")
        target_service = payload.get("target_service", "")
        
        # 记录工具执行
        tool_exec_id = pentest_logger.log_tool_execution(
            session_id=session_id,
            tool_name="web_delivery",
            command=f"Deliver {payload_type} to {target}",
            parameters={
                "payload_type": payload_type,
                "target_service": target_service,
                "safe_mode": self.safe_mode
            },
            safe_mode=self.safe_mode,
            risk_level=payload.get("risk_level", "MEDIUM")
        )
        
        try:
            if self.safe_mode:
                # 安全模式下只模拟投递
                result = await self._simulate_web_delivery(target, payload)
            else:
                # 实际投递（需要谨慎）
                result = await self._execute_web_delivery(target, payload)
            
            # 完成工具执行记录
            pentest_logger.complete_tool_execution(
                tool_exec_id=tool_exec_id,
                success=result.get("success", False),
                return_code=0 if result.get("success") else 1,
                stdout=json.dumps(result, indent=2)
            )
            
            return {
                "method": "web_application",
                "payload_type": payload_type,
                "target_service": target_service,
                "success": result.get("success", False),
                "response": result.get("response", ""),
                "status_code": result.get("status_code"),
                "delivery_time": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Web投递失败: {e}")
            return {
                "method": "web_application",
                "payload_type": payload_type,
                "target_service": target_service,
                "success": False,
                "error": str(e),
                "delivery_time": datetime.now().isoformat()
            }
    
    async def _simulate_web_delivery(self, target: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """模拟Web投递（安全模式）"""
        payload_type = payload.get("type")
        
        # 模拟不同类型载荷的投递结果
        if payload_type == "sql_injection":
            return {
                "success": True,
                "response": "Database error: syntax error",
                "status_code": 500,
                "vulnerability_confirmed": True,
                "simulation": True
            }
        elif payload_type == "xss":
            return {
                "success": True,
                "response": "Script executed in context",
                "status_code": 200,
                "vulnerability_confirmed": True,
                "simulation": True
            }
        elif payload_type == "directory_traversal":
            return {
                "success": True,
                "response": "root:x:0:0:root:/root:/bin/bash",
                "status_code": 200,
                "vulnerability_confirmed": True,
                "simulation": True
            }
        else:
            return {
                "success": False,
                "response": "Payload type not supported in simulation",
                "status_code": 400,
                "simulation": True
            }
    
    async def _execute_web_delivery(self, target: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """执行实际Web投递（非安全模式）"""
        # 这里应该实现实际的HTTP请求投递
        # 出于安全考虑，当前只返回模拟结果
        self.logger.warning("实际Web投递功能未实现，使用模拟结果")
        return await self._simulate_web_delivery(target, payload)
    
    async def _deliver_network_payloads(self, target: str, payloads: List[Dict[str, Any]], 
                                      session_id: str) -> List[Dict[str, Any]]:
        """投递网络服务载荷"""
        delivery_attempts = []
        
        network_payloads = [p for p in payloads if "ssh" in p.get("target_service", "") or 
                          "mysql" in p.get("target_service", "") or
                          "postgresql" in p.get("target_service", "")]
        
        for payload in network_payloads:
            attempt = await self._attempt_network_delivery(target, payload, session_id)
            delivery_attempts.append(attempt)
            
            # 在隐蔽模式下添加延迟
            if self.stealth_mode:
                await asyncio.sleep(3)
        
        return delivery_attempts
    
    async def _attempt_network_delivery(self, target: str, payload: Dict[str, Any], 
                                      session_id: str) -> Dict[str, Any]:
        """尝试网络服务载荷投递"""
        payload_type = payload.get("type")
        target_service = payload.get("target_service", "")
        
        # 记录工具执行
        tool_exec_id = pentest_logger.log_tool_execution(
            session_id=session_id,
            tool_name="network_delivery",
            command=f"Deliver {payload_type} to {target_service}",
            parameters={
                "payload_type": payload_type,
                "target_service": target_service,
                "safe_mode": self.safe_mode
            },
            safe_mode=self.safe_mode,
            risk_level=payload.get("risk_level", "MEDIUM")
        )
        
        try:
            if "ssh" in target_service:
                result = await self._deliver_ssh_payload(target, payload)
            elif "mysql" in target_service or "postgresql" in target_service:
                result = await self._deliver_database_payload(target, payload)
            else:
                result = await self._deliver_generic_network_payload(target, payload)
            
            # 完成工具执行记录
            pentest_logger.complete_tool_execution(
                tool_exec_id=tool_exec_id,
                success=result.get("success", False),
                return_code=0 if result.get("success") else 1,
                stdout=json.dumps(result, indent=2)
            )
            
            return {
                "method": "network_service",
                "payload_type": payload_type,
                "target_service": target_service,
                "success": result.get("success", False),
                "response": result.get("response", ""),
                "delivery_time": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"网络投递失败: {e}")
            return {
                "method": "network_service",
                "payload_type": payload_type,
                "target_service": target_service,
                "success": False,
                "error": str(e),
                "delivery_time": datetime.now().isoformat()
            }
    
    async def _deliver_ssh_payload(self, target: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """投递SSH载荷"""
        if self.safe_mode:
            # 模拟SSH连接尝试
            username = payload.get("username", "admin")
            password = payload.get("password", "admin")
            
            # 模拟弱密码成功的情况
            if username == "admin" and password == "admin":
                return {
                    "success": True,
                    "response": f"SSH login successful for {username}",
                    "authentication_method": "password",
                    "simulation": True
                }
            else:
                return {
                    "success": False,
                    "response": "Authentication failed",
                    "simulation": True
                }
        else:
            # 实际SSH连接应该在这里实现
            self.logger.warning("实际SSH投递功能未实现")
            return {"success": False, "error": "实际SSH投递未实现"}
    
    async def _deliver_database_payload(self, target: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """投递数据库载荷"""
        if self.safe_mode:
            # 模拟数据库注入
            sql_payload = payload.get("payload", "")
            
            if "SELECT" in sql_payload.upper():
                return {
                    "success": True,
                    "response": "Query executed successfully",
                    "result_rows": 5,
                    "simulation": True
                }
            else:
                return {
                    "success": False,
                    "response": "SQL syntax error",
                    "simulation": True
                }
        else:
            # 实际数据库连接应该在这里实现
            self.logger.warning("实际数据库投递功能未实现")
            return {"success": False, "error": "实际数据库投递未实现"}
    
    async def _deliver_generic_network_payload(self, target: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """投递通用网络载荷"""
        if self.safe_mode:
            # 模拟通用网络攻击
            return {
                "success": True,
                "response": "Payload delivered to network service",
                "simulation": True
            }
        else:
            self.logger.warning("实际网络投递功能未实现")
            return {"success": False, "error": "实际网络投递未实现"}
    
    async def _simulate_social_engineering_delivery(self, target: str, payloads: List[Dict[str, Any]], 
                                                  session_id: str) -> List[Dict[str, Any]]:
        """模拟社会工程投递"""
        delivery_attempts = []
        
        # 仅模拟社会工程攻击
        social_attack = {
            "method": "social_engineering",
            "payload_type": "phishing_email",
            "target_service": "email",
            "success": True,  # 模拟成功
            "response": "User clicked malicious link (simulated)",
            "delivery_time": datetime.now().isoformat(),
            "simulation": True
        }
        
        delivery_attempts.append(social_attack)
        
        # 记录社会工程模拟
        if session_id:
            pentest_logger.log_agent_action(
                session_id=session_id,
                agent_name=self.name,
                agent_type=AgentType.DELIVERY_AGENT,
                log_level="INFO",
                log_type="SIMULATION",
                message="模拟社会工程攻击",
                details=social_attack
            )
        
        return delivery_attempts
    
    def get_capabilities(self) -> List[str]:
        """获取投递Agent的能力列表"""
        return [
            "web_payload_delivery",
            "network_service_exploitation",
            "database_injection_delivery",
            "ssh_credential_testing",
            "social_engineering_simulation",
            "multi_vector_delivery",
            "stealth_delivery",
            "payload_timing_control"
        ]
