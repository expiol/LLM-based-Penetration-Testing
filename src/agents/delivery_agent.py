"""
基于LangChain的投递Agent
"""
from typing import Dict, Any, List
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from .base_agent import LangChainBaseAgent
from ..orchestrator.states import AgentType
from ..prompts.agent_prompts import AgentPrompts


class LangChainDeliveryAgent(LangChainBaseAgent):
    """
    基于LangChain的投递Agent
    负责将武器化载荷投递到目标系统
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            name="LangChainDeliveryAgent",
            agent_type=AgentType.DELIVERY_AGENT,
            safe_mode=config.get("safe_mode", True) if config else True,
            config=config
        )
    
    def get_system_prompt(self) -> str:
        """
        获取投递Agent的系统提示词
        使用 AgentPrompts 中的统一 prompt
        """
        # 尝试从当前上下文获取信息（如果已设置）
        payloads: List[Dict[str, Any]] = []
        target_info: Dict[str, Any] = {}
        
        if hasattr(self, '_current_global_context') and self._current_global_context:
            # 从全局上下文中获取已准备的载荷
            payloads = self._current_global_context.get("payloads", [])
        
        if hasattr(self, '_current_target_info') and self._current_target_info:
            target_info = self._current_target_info
            target_info["target"] = target_info.get("target", "目标待指定")
        else:
            target_info = {"target": "目标待指定"}
        
        # 使用 AgentPrompts 中的方法
        # 注意：get_delivery_agent_prompt 接受 payloads 和 target_info
        return AgentPrompts.get_delivery_agent_prompt(payloads, target_info)
    
    def _create_prompt(self) -> ChatPromptTemplate:
        """创建投递Agent的Prompt模板"""
        return ChatPromptTemplate.from_messages([
            ("system", self.get_system_prompt()),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

