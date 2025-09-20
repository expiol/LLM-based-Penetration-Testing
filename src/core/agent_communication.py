"""
Agent间通信和信息整合系统
实现Agent之间的消息传递、状态同步和信息整合
"""
import asyncio
import logging
import json
import uuid
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import threading
from collections import defaultdict

from ..database.logging_service import pentest_logger
from ..orchestrator.states import AgentType


class MessageType(Enum):
    """消息类型"""
    INFORMATION = "information"
    REQUEST = "request"
    RESPONSE = "response"
    COMMAND = "command"
    STATUS_UPDATE = "status_update"
    ERROR = "error"
    COORDINATION = "coordination"


class MessagePriority(Enum):
    """消息优先级"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class AgentMessage:
    """Agent消息"""
    message_id: str
    source_agent: str
    target_agent: str  # "ALL" 表示广播
    message_type: MessageType
    priority: MessagePriority
    content: Dict[str, Any]
    timestamp: str
    session_id: str
    correlation_id: Optional[str] = None  # 用于关联请求和响应
    ttl: int = 300  # 消息生存时间（秒）
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentMessage':
        """从字典创建消息"""
        return cls(
            message_id=data["message_id"],
            source_agent=data["source_agent"],
            target_agent=data["target_agent"],
            message_type=MessageType(data["message_type"]),
            priority=MessagePriority(data["priority"]),
            content=data["content"],
            timestamp=data["timestamp"],
            session_id=data["session_id"],
            correlation_id=data.get("correlation_id"),
            ttl=data.get("ttl", 300)
        )


@dataclass
class AgentStatus:
    """Agent状态"""
    agent_name: str
    agent_type: AgentType
    status: str  # online, offline, busy, error
    last_seen: str
    current_task: Optional[str] = None
    progress: int = 0  # 0-100
    capabilities: List[str] = None
    health_score: int = 100  # 0-100
    
    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []


class AgentCommunicationHub:
    """Agent通信中心"""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.logger = logging.getLogger(f"AgentComm.{session_id[:8]}")
        
        # 消息管理
        self.message_queue: Dict[str, List[AgentMessage]] = defaultdict(list)  # agent_name -> messages
        self.message_history: List[AgentMessage] = []
        self.pending_requests: Dict[str, AgentMessage] = {}  # correlation_id -> request
        
        # Agent管理
        self.registered_agents: Dict[str, AgentStatus] = {}
        self.agent_subscribers: Dict[MessageType, List[str]] = defaultdict(list)
        
        # 回调和处理器
        self.message_handlers: Dict[str, List[Callable]] = defaultdict(list)  # agent_name -> handlers
        self.global_handlers: List[Callable] = []
        
        # 同步和状态
        self.lock = threading.RLock()
        self.running = False
        self.message_processor_task: Optional[asyncio.Task] = None
        
        # 统计信息
        self.stats = {
            "messages_sent": 0,
            "messages_received": 0,
            "messages_processed": 0,
            "errors": 0,
            "start_time": datetime.now().isoformat()
        }
        
        self.logger.info(f"Agent通信中心初始化完成 - Session: {session_id}")
    
    async def start(self):
        """启动通信中心"""
        self.running = True
        self.message_processor_task = asyncio.create_task(self._message_processor())
        self.logger.info("Agent通信中心已启动")
    
    async def stop(self):
        """停止通信中心"""
        self.running = False
        if self.message_processor_task:
            self.message_processor_task.cancel()
            try:
                await self.message_processor_task
            except asyncio.CancelledError:
                pass
        self.logger.info("Agent通信中心已停止")
    
    def register_agent(self, agent_name: str, agent_type: AgentType, capabilities: List[str] = None) -> bool:
        """注册Agent"""
        try:
            with self.lock:
                status = AgentStatus(
                    agent_name=agent_name,
                    agent_type=agent_type,
                    status="online",
                    last_seen=datetime.now().isoformat(),
                    capabilities=capabilities or []
                )
                self.registered_agents[agent_name] = status
                
                # 初始化消息队列
                if agent_name not in self.message_queue:
                    self.message_queue[agent_name] = []
            
            self.logger.info(f"Agent注册成功: {agent_name} ({agent_type.value})")
            
            # 广播Agent上线消息
            asyncio.create_task(self._broadcast_agent_status(agent_name, "online"))
            
            return True
            
        except Exception as e:
            self.logger.error(f"Agent注册失败: {agent_name} - {e}")
            return False
    
    def unregister_agent(self, agent_name: str) -> bool:
        """注销Agent"""
        try:
            with self.lock:
                if agent_name in self.registered_agents:
                    del self.registered_agents[agent_name]
                    # 清理消息队列
                    if agent_name in self.message_queue:
                        del self.message_queue[agent_name]
            
            self.logger.info(f"Agent注销成功: {agent_name}")
            
            # 广播Agent下线消息
            asyncio.create_task(self._broadcast_agent_status(agent_name, "offline"))
            
            return True
            
        except Exception as e:
            self.logger.error(f"Agent注销失败: {agent_name} - {e}")
            return False
    
    async def send_message(self, source_agent: str, target_agent: str, message_type: MessageType,
                          content: Dict[str, Any], priority: MessagePriority = MessagePriority.MEDIUM,
                          correlation_id: Optional[str] = None) -> str:
        """发送消息"""
        try:
            message_id = str(uuid.uuid4())
            message = AgentMessage(
                message_id=message_id,
                source_agent=source_agent,
                target_agent=target_agent,
                message_type=message_type,
                priority=priority,
                content=content,
                timestamp=datetime.now().isoformat(),
                session_id=self.session_id,
                correlation_id=correlation_id
            )
            
            # 记录消息到历史
            self.message_history.append(message)
            
            # 如果是请求消息，记录到待处理请求
            if message_type == MessageType.REQUEST and correlation_id:
                self.pending_requests[correlation_id] = message
            
            # 分发消息
            await self._distribute_message(message)
            
            # 更新统计
            self.stats["messages_sent"] += 1
            
            # 记录到数据库
            pentest_logger.log_agent_action(
                session_id=self.session_id,
                agent_name="CommunicationHub",
                agent_type=AgentType.RECON_AGENT,  # 使用占位符类型
                log_level="DEBUG",
                log_type="MESSAGE_SENT",
                message=f"消息发送: {source_agent} -> {target_agent}",
                details={
                    "message_id": message_id,
                    "message_type": message_type.value,
                    "priority": priority.value
                }
            )
            
            return message_id
            
        except Exception as e:
            self.logger.error(f"消息发送失败: {e}")
            self.stats["errors"] += 1
            raise
    
    async def send_request(self, source_agent: str, target_agent: str, content: Dict[str, Any],
                          timeout: int = 30) -> Optional[AgentMessage]:
        """发送请求并等待响应"""
        correlation_id = str(uuid.uuid4())
        
        # 发送请求
        await self.send_message(
            source_agent=source_agent,
            target_agent=target_agent,
            message_type=MessageType.REQUEST,
            content=content,
            priority=MessagePriority.HIGH,
            correlation_id=correlation_id
        )
        
        # 等待响应
        try:
            response = await self._wait_for_response(correlation_id, timeout)
            return response
        except asyncio.TimeoutError:
            self.logger.warning(f"请求超时: {correlation_id}")
            return None
    
    async def send_response(self, source_agent: str, target_agent: str, content: Dict[str, Any],
                           correlation_id: str):
        """发送响应"""
        await self.send_message(
            source_agent=source_agent,
            target_agent=target_agent,
            message_type=MessageType.RESPONSE,
            content=content,
            priority=MessagePriority.HIGH,
            correlation_id=correlation_id
        )
        
        # 清理待处理请求
        if correlation_id in self.pending_requests:
            del self.pending_requests[correlation_id]
    
    async def broadcast_message(self, source_agent: str, message_type: MessageType,
                               content: Dict[str, Any], priority: MessagePriority = MessagePriority.MEDIUM):
        """广播消息"""
        await self.send_message(
            source_agent=source_agent,
            target_agent="ALL",
            message_type=message_type,
            content=content,
            priority=priority
        )
    
    async def get_messages(self, agent_name: str, message_type: Optional[MessageType] = None) -> List[AgentMessage]:
        """获取Agent的消息"""
        with self.lock:
            messages = self.message_queue.get(agent_name, []).copy()
            
            if message_type:
                messages = [msg for msg in messages if msg.message_type == message_type]
            
            return messages
    
    async def consume_messages(self, agent_name: str, message_type: Optional[MessageType] = None) -> List[AgentMessage]:
        """获取并消费Agent的消息"""
        with self.lock:
            messages = self.message_queue.get(agent_name, [])
            
            if message_type:
                consumed = [msg for msg in messages if msg.message_type == message_type]
                remaining = [msg for msg in messages if msg.message_type != message_type]
                self.message_queue[agent_name] = remaining
            else:
                consumed = messages.copy()
                self.message_queue[agent_name] = []
            
            self.stats["messages_processed"] += len(consumed)
            return consumed
    
    def update_agent_status(self, agent_name: str, status: str, current_task: Optional[str] = None,
                           progress: int = None, health_score: int = None):
        """更新Agent状态"""
        with self.lock:
            if agent_name in self.registered_agents:
                agent_status = self.registered_agents[agent_name]
                agent_status.status = status
                agent_status.last_seen = datetime.now().isoformat()
                
                if current_task is not None:
                    agent_status.current_task = current_task
                if progress is not None:
                    agent_status.progress = progress
                if health_score is not None:
                    agent_status.health_score = health_score
        
        # 广播状态更新
        asyncio.create_task(self._broadcast_agent_status(agent_name, status))
    
    def get_agent_status(self, agent_name: str) -> Optional[AgentStatus]:
        """获取Agent状态"""
        with self.lock:
            return self.registered_agents.get(agent_name)
    
    def get_all_agents(self) -> Dict[str, AgentStatus]:
        """获取所有Agent状态"""
        with self.lock:
            return self.registered_agents.copy()
    
    def subscribe_to_messages(self, agent_name: str, message_type: MessageType):
        """订阅特定类型的消息"""
        if agent_name not in self.agent_subscribers[message_type]:
            self.agent_subscribers[message_type].append(agent_name)
    
    def register_message_handler(self, agent_name: str, handler: Callable):
        """注册消息处理器"""
        self.message_handlers[agent_name].append(handler)
    
    def register_global_handler(self, handler: Callable):
        """注册全局消息处理器"""
        self.global_handlers.append(handler)
    
    async def _distribute_message(self, message: AgentMessage):
        """分发消息"""
        if message.target_agent == "ALL":
            # 广播消息
            with self.lock:
                for agent_name in self.registered_agents:
                    if agent_name != message.source_agent:
                        self.message_queue[agent_name].append(message)
        else:
            # 单播消息
            with self.lock:
                if message.target_agent in self.registered_agents:
                    self.message_queue[message.target_agent].append(message)
                else:
                    self.logger.warning(f"目标Agent不存在: {message.target_agent}")
        
        # 调用消息处理器
        await self._call_message_handlers(message)
    
    async def _call_message_handlers(self, message: AgentMessage):
        """调用消息处理器"""
        # 调用目标Agent的处理器
        handlers = self.message_handlers.get(message.target_agent, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(message)
                else:
                    handler(message)
            except Exception as e:
                self.logger.error(f"消息处理器异常: {e}")
        
        # 调用全局处理器
        for handler in self.global_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(message)
                else:
                    handler(message)
            except Exception as e:
                self.logger.error(f"全局消息处理器异常: {e}")
    
    async def _message_processor(self):
        """消息处理器后台任务"""
        while self.running:
            try:
                # 清理过期消息
                await self._cleanup_expired_messages()
                
                # 检查Agent健康状态
                await self._check_agent_health()
                
                await asyncio.sleep(5)  # 每5秒检查一次
                
            except Exception as e:
                self.logger.error(f"消息处理器异常: {e}")
                await asyncio.sleep(1)
    
    async def _cleanup_expired_messages(self):
        """清理过期消息"""
        current_time = datetime.now()
        
        with self.lock:
            for agent_name, messages in self.message_queue.items():
                valid_messages = []
                for message in messages:
                    message_time = datetime.fromisoformat(message.timestamp)
                    age = (current_time - message_time).total_seconds()
                    
                    if age < message.ttl:
                        valid_messages.append(message)
                
                self.message_queue[agent_name] = valid_messages
    
    async def _check_agent_health(self):
        """检查Agent健康状态"""
        current_time = datetime.now()
        
        with self.lock:
            for agent_name, status in self.registered_agents.items():
                last_seen = datetime.fromisoformat(status.last_seen)
                age = (current_time - last_seen).total_seconds()
                
                # 如果超过60秒没有活动，标记为不健康
                if age > 60 and status.status != "offline":
                    status.health_score = max(0, status.health_score - 10)
                    if status.health_score <= 20:
                        status.status = "error"
                        self.logger.warning(f"Agent健康状态异常: {agent_name}")
    
    async def _wait_for_response(self, correlation_id: str, timeout: int) -> AgentMessage:
        """等待响应"""
        start_time = datetime.now()
        
        while (datetime.now() - start_time).total_seconds() < timeout:
            # 检查是否有响应
            for message in self.message_history[-100:]:  # 只检查最近100条消息
                if (message.message_type == MessageType.RESPONSE and 
                    message.correlation_id == correlation_id):
                    return message
            
            await asyncio.sleep(0.1)  # 100ms检查间隔
        
        raise asyncio.TimeoutError(f"等待响应超时: {correlation_id}")
    
    async def _broadcast_agent_status(self, agent_name: str, status: str):
        """广播Agent状态更新"""
        await self.broadcast_message(
            source_agent="CommunicationHub",
            message_type=MessageType.STATUS_UPDATE,
            content={
                "agent_name": agent_name,
                "status": status,
                "timestamp": datetime.now().isoformat()
            },
            priority=MessagePriority.LOW
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self.lock:
            current_stats = self.stats.copy()
            current_stats.update({
                "registered_agents": len(self.registered_agents),
                "pending_messages": sum(len(msgs) for msgs in self.message_queue.values()),
                "pending_requests": len(self.pending_requests),
                "message_history_size": len(self.message_history),
                "uptime_seconds": (datetime.now() - datetime.fromisoformat(self.stats["start_time"])).total_seconds()
            })
            return current_stats


class InformationIntegrator:
    """信息整合器"""
    
    def __init__(self, communication_hub: AgentCommunicationHub):
        self.comm_hub = communication_hub
        self.logger = logging.getLogger("InformationIntegrator")
        
        # 信息存储
        self.integrated_intelligence: Dict[str, Any] = {
            "reconnaissance": {},
            "vulnerabilities": [],
            "exploitation_results": [],
            "access_gained": [],
            "persistence_mechanisms": [],
            "data_collected": [],
            "network_topology": {},
            "timeline": []
        }
        
        # 注册消息处理器
        self.comm_hub.register_global_handler(self._process_information_message)
    
    async def _process_information_message(self, message: AgentMessage):
        """处理信息消息"""
        if message.message_type == MessageType.INFORMATION:
            await self._integrate_information(message)
    
    async def _integrate_information(self, message: AgentMessage):
        """整合信息"""
        source_agent = message.source_agent
        content = message.content
        
        try:
            # 根据来源Agent类型整合信息
            if "ReconAgent" in source_agent:
                await self._integrate_reconnaissance_info(content)
            elif "WeaponizeAgent" in source_agent:
                await self._integrate_weaponization_info(content)
            elif "ExploitAgent" in source_agent:
                await self._integrate_exploitation_info(content)
            elif "InstallAgent" in source_agent:
                await self._integrate_installation_info(content)
            elif "C2Agent" in source_agent:
                await self._integrate_c2_info(content)
            elif "ObjectivesAgent" in source_agent:
                await self._integrate_objectives_info(content)
            
            # 添加到时间线
            self.integrated_intelligence["timeline"].append({
                "timestamp": message.timestamp,
                "source_agent": source_agent,
                "event_type": "information_update",
                "summary": self._generate_event_summary(content)
            })
            
        except Exception as e:
            self.logger.error(f"信息整合失败: {e}")
    
    async def _integrate_reconnaissance_info(self, content: Dict[str, Any]):
        """整合侦察信息"""
        recon_data = self.integrated_intelligence["reconnaissance"]
        
        if "services" in content:
            if "discovered_services" not in recon_data:
                recon_data["discovered_services"] = []
            recon_data["discovered_services"].extend(content["services"])
        
        if "vulnerabilities" in content:
            self.integrated_intelligence["vulnerabilities"].extend(content["vulnerabilities"])
        
        if "network_info" in content:
            self.integrated_intelligence["network_topology"].update(content["network_info"])
    
    async def _integrate_weaponization_info(self, content: Dict[str, Any]):
        """整合武器化信息"""
        if "payloads" in content:
            if "payloads" not in self.integrated_intelligence:
                self.integrated_intelligence["payloads"] = []
            self.integrated_intelligence["payloads"].extend(content["payloads"])
        
        if "exploits" in content:
            if "available_exploits" not in self.integrated_intelligence:
                self.integrated_intelligence["available_exploits"] = []
            self.integrated_intelligence["available_exploits"].extend(content["exploits"])
    
    async def _integrate_exploitation_info(self, content: Dict[str, Any]):
        """整合利用信息"""
        if "exploitation_results" in content:
            self.integrated_intelligence["exploitation_results"].extend(content["exploitation_results"])
        
        if "access_gained" in content:
            self.integrated_intelligence["access_gained"].extend(content["access_gained"])
    
    async def _integrate_installation_info(self, content: Dict[str, Any]):
        """整合安装信息"""
        if "persistence_mechanisms" in content:
            self.integrated_intelligence["persistence_mechanisms"].extend(content["persistence_mechanisms"])
        
        if "backdoors" in content:
            if "backdoors" not in self.integrated_intelligence:
                self.integrated_intelligence["backdoors"] = []
            self.integrated_intelligence["backdoors"].extend(content["backdoors"])
    
    async def _integrate_c2_info(self, content: Dict[str, Any]):
        """整合C2信息"""
        if "communication_channels" in content:
            if "c2_channels" not in self.integrated_intelligence:
                self.integrated_intelligence["c2_channels"] = []
            self.integrated_intelligence["c2_channels"].extend(content["communication_channels"])
        
        if "command_results" in content:
            if "c2_commands" not in self.integrated_intelligence:
                self.integrated_intelligence["c2_commands"] = []
            self.integrated_intelligence["c2_commands"].extend(content["command_results"])
    
    async def _integrate_objectives_info(self, content: Dict[str, Any]):
        """整合目标信息"""
        if "data_collected" in content:
            self.integrated_intelligence["data_collected"].extend(content["data_collected"])
        
        if "evidence" in content:
            if "evidence_collected" not in self.integrated_intelligence:
                self.integrated_intelligence["evidence_collected"] = []
            self.integrated_intelligence["evidence_collected"].extend(content["evidence"])
    
    def _generate_event_summary(self, content: Dict[str, Any]) -> str:
        """生成事件摘要"""
        if "services" in content:
            return f"发现 {len(content['services'])} 个服务"
        elif "vulnerabilities" in content:
            return f"识别 {len(content['vulnerabilities'])} 个漏洞"
        elif "payloads" in content:
            return f"生成 {len(content['payloads'])} 个载荷"
        elif "exploitation_results" in content:
            return f"完成 {len(content['exploitation_results'])} 次利用尝试"
        elif "persistence_mechanisms" in content:
            return f"安装 {len(content['persistence_mechanisms'])} 个持久化机制"
        elif "communication_channels" in content:
            return f"建立 {len(content['communication_channels'])} 个通信通道"
        elif "data_collected" in content:
            return f"收集 {len(content['data_collected'])} 项数据"
        else:
            return "信息更新"
    
    def get_integrated_intelligence(self) -> Dict[str, Any]:
        """获取整合的情报信息"""
        return self.integrated_intelligence.copy()
    
    def get_intelligence_summary(self) -> Dict[str, Any]:
        """获取情报摘要"""
        intelligence = self.integrated_intelligence
        
        return {
            "total_services": len(intelligence.get("reconnaissance", {}).get("discovered_services", [])),
            "total_vulnerabilities": len(intelligence.get("vulnerabilities", [])),
            "total_exploits": len(intelligence.get("exploitation_results", [])),
            "access_levels": len(intelligence.get("access_gained", [])),
            "persistence_count": len(intelligence.get("persistence_mechanisms", [])),
            "c2_channels": len(intelligence.get("c2_channels", [])),
            "data_items": len(intelligence.get("data_collected", [])),
            "timeline_events": len(intelligence.get("timeline", []))
        }
