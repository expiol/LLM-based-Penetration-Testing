"""
基于LangChain的命令控制Agent
"""
from typing import Dict, Any
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from .base_agent import LangChainBaseAgent
from ..orchestrator.states import AgentType
from ..prompts.agent_prompts import AgentPrompts


class LangChainC2Agent(LangChainBaseAgent):
    """
    基于LangChain的命令控制Agent
    负责建立和维护与目标系统的稳定通信
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            name="LangChainC2Agent",
            agent_type=AgentType.C2_AGENT,
            safe_mode=config.get("safe_mode", True) if config else True,
            config=config
        )
    
    def get_system_prompt(self) -> str:
        """
        获取C2 Agent的系统提示词
        使用 AgentPrompts 中的统一 prompt
        """
        # 尝试从当前上下文获取信息（如果已设置）
        install_results: Dict[str, Any] = {}
        target_info: Dict[str, Any] = {}
        
        if hasattr(self, '_current_global_context') and self._current_global_context:
            # 从全局上下文中获取安装结果
            install_results = self._current_global_context.get("installation_results", {})
        
        if hasattr(self, '_current_target_info') and self._current_target_info:
            target_info = self._current_target_info
            target_info["target"] = target_info.get("target", "目标待指定")
        else:
            target_info = {"target": "目标待指定"}
        
        # 使用 AgentPrompts 中的方法
        return AgentPrompts.get_c2_agent_prompt(install_results, target_info)
    
    def _create_prompt(self) -> ChatPromptTemplate:
        """创建C2 Agent的Prompt模板"""
        return ChatPromptTemplate.from_messages([
            ("system", self.get_system_prompt()),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

