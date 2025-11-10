"""
基于LangChain的侦察Agent
"""
from typing import Dict, Any
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from .base_agent import LangChainBaseAgent
from ..orchestrator.states import AgentType
from ..prompts.agent_prompts import AgentPrompts


class LangChainReconAgent(LangChainBaseAgent):
    """
    基于LangChain的侦察Agent
    负责信息收集、端口扫描、服务识别等
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            name="LangChainReconAgent",
            agent_type=AgentType.RECON_AGENT,
            safe_mode=config.get("safe_mode", True) if config else True,
            config=config
        )
    
    def get_system_prompt(self) -> str:
        """
        获取侦察Agent的系统提示词
        使用 AgentPrompts 中的统一 prompt
        """
        # 尝试从当前上下文获取信息（如果已设置）
        target = ""
        context = {}
        
        if hasattr(self, '_current_target_info') and self._current_target_info:
            target = self._current_target_info.get("target", "")
        
        if hasattr(self, '_current_global_context') and self._current_global_context:
            context = self._current_global_context
        
        # 如果有完整信息，使用完整版 prompt；否则使用基础版本
        if target:
            return AgentPrompts.get_recon_agent_prompt(target, context)
        else:
            # 返回基础版本（初始化时使用）
            return AgentPrompts.get_recon_agent_prompt("目标待指定", {
                "recon_depth": "standard",
                "time_limit": 1800
            })
    
    def _create_prompt(self) -> ChatPromptTemplate:
        """创建侦察Agent的Prompt模板"""
        return ChatPromptTemplate.from_messages([
            ("system", self.get_system_prompt()),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

