"""
Cyber Kill Chain 状态枚举
定义渗透测试的各个阶段状态
"""
from enum import Enum, auto


class KillChainState(Enum):
    """Cyber Kill Chain 状态枚举"""
    
    # 初始状态
    INITIALIZED = auto()
    
    # 1. 侦察阶段
    RECONNAISSANCE = auto()
    
    # 2. 武器化阶段
    WEAPONIZATION = auto()
    
    # 3. 投递阶段
    DELIVERY = auto()
    
    # 4. 利用阶段
    EXPLOITATION = auto()
    
    # 5. 安装阶段
    INSTALLATION = auto()
    
    # 6. 命令与控制阶段
    COMMAND_CONTROL = auto()
    
    # 7. 目标行为阶段
    ACTIONS_ON_OBJECTIVES = auto()
    
    # 完成状态
    COMPLETED = auto()
    
    # 错误状态
    ERROR = auto()
    
    # 暂停状态
    PAUSED = auto()


class TaskStatus(Enum):
    """任务状态枚举"""
    
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentType(Enum):
    """Agent类型枚举"""
    
    RECON_AGENT = "recon_agent"
    WEAPONIZE_AGENT = "weaponize_agent"
    DELIVERY_AGENT = "delivery_agent"
    EXPLOIT_AGENT = "exploit_agent"
    INSTALL_AGENT = "install_agent"
    C2_AGENT = "c2_agent"
    OBJECTIVES_AGENT = "objectives_agent"
