"""
基于LangChain的安装Agent
"""
from typing import Dict, Any
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from .base_agent import LangChainBaseAgent
from ..orchestrator.states import AgentType
from ..prompts.agent_prompts import AgentPrompts


class LangChainInstallAgent(LangChainBaseAgent):
    """
    基于LangChain的安装Agent
    负责在目标系统建立持久化机制
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            name="LangChainInstallAgent",
            agent_type=AgentType.INSTALL_AGENT,
            safe_mode=config.get("safe_mode", True) if config else True,
            config=config
        )
    
    def get_system_prompt(self) -> str:
        """
        获取安装Agent的系统提示词
        使用 AgentPrompts 中的统一 prompt
        """
        # 尝试从当前上下文获取信息（如果已设置）
        exploit_results: Dict[str, Any] = {}
        target_info: Dict[str, Any] = {}
        
        if hasattr(self, '_current_global_context') and self._current_global_context:
            # 从全局上下文中获取利用结果
            exploit_results = self._current_global_context.get("exploitation_results", {})
            if isinstance(exploit_results, list) and exploit_results:
                exploit_results = exploit_results[0]  # 取第一个结果
        
        if hasattr(self, '_current_target_info') and self._current_target_info:
            target_info = self._current_target_info
            target_info["target"] = target_info.get("target", "目标待指定")
        else:
            target_info = {"target": "目标待指定"}
        
        # 使用 AgentPrompts 中的方法
        return AgentPrompts.get_install_agent_prompt(exploit_results, target_info)
    
    def _create_prompt(self) -> ChatPromptTemplate:
        """创建安装Agent的Prompt模板"""
        return ChatPromptTemplate.from_messages([
            ("system", self.get_system_prompt()),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

