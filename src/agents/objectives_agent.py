"""
基于LangChain的目标行为Agent
"""
from typing import Dict, Any, List
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from .base_agent import LangChainBaseAgent
from ..orchestrator.states import AgentType
from ..prompts.agent_prompts import AgentPrompts


class LangChainObjectivesAgent(LangChainBaseAgent):
    """
    基于LangChain的目标行为Agent
    负责执行最终的攻击目标和数据收集任务
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            name="LangChainObjectivesAgent",
            agent_type=AgentType.OBJECTIVES_AGENT,
            safe_mode=config.get("safe_mode", True) if config else True,
            config=config
        )
    
    def get_system_prompt(self) -> str:
        """
        获取目标行为Agent的系统提示词
        使用 AgentPrompts 中的统一 prompt
        """
        # 尝试从当前上下文获取信息（如果已设置）
        c2_results: Dict[str, Any] = {}
        targets: List[str] = []
        
        if hasattr(self, '_current_global_context') and self._current_global_context:
            # 从全局上下文中获取C2结果
            c2_results = self._current_global_context.get("c2_results", {})
        
        if hasattr(self, '_current_target_info') and self._current_target_info:
            target = self._current_target_info.get("target", "")
            if target:
                targets = [target]
        
        # 使用 AgentPrompts 中的方法
        return AgentPrompts.get_objectives_agent_prompt(c2_results, targets)
    
    def _create_prompt(self) -> ChatPromptTemplate:
        """创建目标行为Agent的Prompt模板"""
        return ChatPromptTemplate.from_messages([
            ("system", self.get_system_prompt()),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

