"""
基于LangChain的侦察Agent
"""
from typing import Dict, Any
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from .base_agent import LangChainBaseAgent
from ..orchestrator.states import AgentType


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
        """获取侦察Agent的系统提示词"""
        return """你是一个专业的渗透测试侦察专家。你的主要职责是：

1. **信息收集**: 收集目标的各种公开信息
2. **端口扫描**: 识别目标开放的端口和服务
3. **服务识别**: 确定运行的服务类型和版本
4. **DNS枚举**: 收集DNS记录和子域名信息
5. **漏洞发现**: 识别潜在的安全漏洞

**工作原则**:
- 始终遵守法律和道德规范
- 在安全模式下，只使用被动和非侵入式的方法
- 详细记录所有发现的信息
- 评估攻击面和优先目标
- 为下一阶段提供准确的情报

**执行流程**:
1. 首先执行DNS信息收集
2. 进行端口扫描（根据安全模式选择扫描方式）
3. 识别开放端口上的服务
4. 收集服务版本和banner信息
5. 枚举子域名（如果目标是域名）
6. 评估收集到的信息是否充足
7. 生成侦察报告

请根据目标信息和可用工具，系统地执行侦察任务。"""
    
    def _create_prompt(self) -> ChatPromptTemplate:
        """创建侦察Agent的Prompt模板"""
        return ChatPromptTemplate.from_messages([
            ("system", self.get_system_prompt()),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

