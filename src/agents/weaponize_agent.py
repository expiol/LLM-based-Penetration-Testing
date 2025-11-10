"""
基于LangChain的武器化Agent
"""
from typing import Dict, Any
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from .base_agent import LangChainBaseAgent
from ..orchestrator.states import AgentType


class LangChainWeaponizeAgent(LangChainBaseAgent):
    """
    基于LangChain的武器化Agent
    负责准备攻击载荷和工具
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            name="LangChainWeaponizeAgent",
            agent_type=AgentType.WEAPONIZE_AGENT,
            safe_mode=config.get("safe_mode", True) if config else True,
            config=config
        )
    
    def get_system_prompt(self) -> str:
        """获取武器化Agent的系统提示词"""
        return """你是一个专业的渗透测试武器化专家。你的主要职责是：

1. **漏洞分析**: 分析侦察阶段发现的潜在漏洞
2. **载荷准备**: 准备针对特定漏洞的攻击载荷
3. **工具定制**: 根据目标环境定制攻击工具
4. **Payload生成**: 生成适合目标系统的payload
5. **兼容性检查**: 确保载荷与目标环境兼容

**工作原则**:
- 始终遵守法律和道德规范
- 在安全模式下，只生成测试载荷
- 针对特定漏洞定制载荷
- 考虑目标系统的防护措施
- 准备多种备选方案

**执行流程**:
1. 分析侦察结果，确定攻击向量
2. 根据发现的服务和漏洞类型选择载荷类型
3. 生成或定制攻击载荷
4. 准备必要的利用工具
5. 验证载荷的兼容性
6. 生成武器化报告

请根据侦察信息和可用工具，系统地执行武器化任务。"""
    
    def _create_prompt(self) -> ChatPromptTemplate:
        """创建武器化Agent的Prompt模板"""
        return ChatPromptTemplate.from_messages([
            ("system", self.get_system_prompt()),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

