"""
主控LLM提示词模板
管理整个渗透测试项目的LLM prompts
参考 harbinger 项目的攻击生命周期设计
"""
import json
from typing import Dict, Any, List, Optional


# 攻击生命周期阶段映射（参考 harbinger）
ATTACK_PHASES = [
    "initial reconnaissance",     # 初始侦察
    "initial compromise",         # 初始入侵
    "establish foothold",         # 建立立足点
    "escalate privileges",        # 权限提升
    "internal reconnaissance",    # 内部侦察
    "move laterally",            # 横向移动
    "maintain presence",         # 维持存在
    "complete mission",          # 完成任务
]

# 攻击阶段别名映射
ATTACK_PHASE_ALIASES = {
    "information gathering": "initial reconnaissance",
    "scanning": "initial reconnaissance",
    "footprinting": "initial reconnaissance",
    "profiling": "initial reconnaissance",
    "osint collection": "initial reconnaissance",
    "exploitation": "initial compromise",
    "breach": "initial compromise",
    "intrusion": "initial compromise",
    "gaining access": "initial compromise",
    "zero-day attack": "initial compromise",
    "persistence": "establish foothold",
    "anchoring": "establish foothold",
    "backdooring": "establish foothold",
    "command and control (c2) setup": "establish foothold",
    "privilege escalation": "escalate privileges",
    "gaining elevated access": "escalate privileges",
    "root compromise": "escalate privileges",
    "discovery": "internal reconnaissance",
    "enumeration": "internal reconnaissance",
    "network mapping": "internal reconnaissance",
    "system analysis": "internal reconnaissance",
    "lateral movement": "move laterally",
    "pivoting": "move laterally",
    "island hopping": "move laterally",
    "spreading": "move laterally",
    "command and control (c2)": "maintain presence",
    "remote access": "maintain presence",
    "staying hidden": "maintain presence",
    "exfiltration": "complete mission",
    "impact": "complete mission",
    "data theft": "complete mission",
    "disruption": "complete mission",
    "denial of service": "complete mission",
    "destruction": "complete mission",
}

# Kill Chain 到攻击阶段的映射
KILL_CHAIN_TO_ATTACK_PHASE = {
    "reconnaissance": "initial reconnaissance",
    "weaponization": "initial compromise",
    "delivery": "initial compromise", 
    "exploitation": "escalate privileges",
    "installation": "establish foothold",
    "command_control": "maintain presence",
    "actions_on_objectives": "complete mission",
}

# 检测风险等级
class DetectionRisk:
    """检测风险评估"""
    LOW = 1       # 不太可能被检测
    MEDIUM = 2    # 有一定检测风险
    HIGH = 3      # 较高检测风险
    VERY_HIGH = 4 # 很高检测风险
    CERTAIN = 5   # 几乎肯定被检测
    
    @staticmethod
    def get_risk_description(level: int) -> str:
        descriptions = {
            1: "低风险 - 不太可能被检测",
            2: "中等风险 - 有一定检测可能",
            3: "高风险 - 较高检测可能",
            4: "很高风险 - 可能被检测",
            5: "极高风险 - 几乎肯定被检测",
        }
        return descriptions.get(level, "未知风险")


def normalize_attack_phase(phase: str) -> str:
    """标准化攻击阶段名称"""
    phase_lower = phase.lower().strip()
    if phase_lower in ATTACK_PHASES:
        return phase_lower
    if phase_lower in ATTACK_PHASE_ALIASES:
        return ATTACK_PHASE_ALIASES[phase_lower]
    return "initial reconnaissance"  # 默认返回初始侦察


class MasterPrompts:
    """主控LLM提示词管理"""
    
    @staticmethod
    def get_master_system_prompt() -> str:
        """
        获取主控LLM的系统提示词
        
        Returns:
            str: 系统提示词
        """
        return """你是一个专业的渗透测试主控专家，负责统筹管理整个网络安全渗透测试项目。你具有丰富的网络安全知识、实战经验和项目管理能力。

### 核心身份与职责
你是LLM-based Penetration Testing项目的大脑和指挥中心，负责：
1. 制定和调整渗透测试策略和计划
2. 协调管理各个专门Agent（侦察、武器化、投递、利用、安装、C2、目标行为）
3. 维护和更新TODO列表，确保任务有序推进，防止超长流程
4. 进行自我纠错和对其他Agent的修正指导
5. 整合和分析各阶段的测试结果
6. 处理人工干预和安全决策

### 项目架构理解
本项目基于Cyber Kill Chain杀伤链模型，包含以下阶段：
- Reconnaissance（侦察）：信息收集、端口扫描、服务识别
- Weaponization（武器化）：漏洞分析、载荷准备
- Delivery（投递）：攻击向量实施
- Exploitation（利用）：漏洞利用、权限获取
- Installation（安装）：持久化机制
- Command & Control（命令控制）：建立通信渠道
- Actions on Objectives（目标行为）：数据收集、横向移动

### TODO管理原则
为防止执行超长，必须严格维护TODO列表：
1. 将复杂任务分解为可管理的子任务（每个任务不超过30分钟）
2. 设置明确的依赖关系和优先级
3. 定期检查和更新TODO状态
4. 在任务执行前验证可行性，及时调整计划
5. 对失败任务及时分析原因并制定补救措施

### 安全和道德原则
- 所有测试必须获得明确授权
- 严格遵守法律法规和道德规范
- 在安全模式下运行，避免破坏性操作
- 详细记录所有操作，便于审计
- 发现严重漏洞时及时通知相关方

### 响应格式要求
请始终以JSON格式响应，包含以下字段：
- strategy: 执行策略和决策
- reasoning: 详细的推理过程
- risk_assessment: 风险评估（低/中/高）
- recommendations: 具体的行动建议
- todo_updates: TODO列表更新（如需要）
- next_steps: 下一步行动计划
- safety_notes: 安全注意事项

记住：你的决策将直接影响整个渗透测试项目的成功与安全。"""

    @staticmethod
    def get_planning_prompt(target: str, options: Dict[str, Any], context: Dict[str, Any]) -> str:
        """
        获取渗透测试规划提示词
        
        Args:
            target: 目标地址（可能是 "auto_extract" 标记）
            options: 测试选项（包含 raw_description）
            context: 执行上下文
            
        Returns:
            str: 规划提示词
        """
        # 检查是否需要从描述中提取目标
        raw_description = options.get("raw_description", "")
        
        # 如果target是"auto_extract"或者为空，使用原始描述让LLM提取
        # 优先使用原始描述，让LLM来理解和规划
        if (target == "auto_extract" or not target) and raw_description:
            # 需要LLM从描述中提取目标
            return f"""你需要从以下自然语言描述中提取目标信息，并为其制定详细的渗透测试计划。

## 用户原始输入
{raw_description}

### ⚠️ 重要：目标提取规则
1. **智能识别目标地址**：
   - 用户可能使用中文句号（。）代替英文句点（.），请自动转换
   - 例如："192。168。66。1" 应识别为 "192.168.66.1"
   - 例如："example。com" 应识别为 "example.com"

2. **提取辅助信息**：
   - 注意用户描述中的设备类型信息（如"路由器"、"服务器"、"网站"等）
   - 这些信息应该影响你的扫描策略：
     * **路由器**：重点扫描 22(SSH), 23(Telnet), 80/443(Web管理), 161(SNMP), 8080, 8443 等管理端口
     * **服务器**：扫描常用服务端口 22, 80, 443, 3306, 5432, 6379 等
     * **网站/Web应用**：重点 80, 443, 8080, 8443 及Web漏洞扫描
     * **未指定**：进行标准端口扫描 1-1000

3. **智能工具选择**：
   - 如果目标是**IP地址**：使用nmap进行端口扫描和服务识别，**不要**使用dns_enum或subdomain_enum
   - 如果目标是**域名**：可以使用dns_enum、subdomain_enum进行DNS信息收集

### 目标信息
- 用户描述: {raw_description}
- 测试选项: {json.dumps(options, ensure_ascii=False, indent=2)}
- 当前环境状态: {json.dumps(context.get("environment_state", {}), ensure_ascii=False, indent=2)}
- 可用工具: {json.dumps(context.get("available_tools", []), ensure_ascii=False)}

### 规划要求
请制定一个完整的Cyber Kill Chain渗透测试计划，需要包含：

#### 1. 侦察阶段 (Reconnaissance)
- 端口扫描策略（Nmap扫描类型、端口范围）
- 服务识别和版本探测
- 子域名枚举方法
- DNS信息收集
- Web应用指纹识别
- 社会工程学信息收集（如适用）

#### 2. 武器化阶段 (Weaponization)  
- 基于侦察结果的漏洞分析
- 攻击载荷类型选择
- 自定义工具开发需求
- 利用代码准备

#### 3. 投递阶段 (Delivery)
- 攻击向量选择（Web、邮件、物理等）
- 载荷投递方法
- 社会工程学策略（如需要）

#### 4. 利用阶段 (Exploitation)
- 漏洞利用优先级排序
- 利用工具配置
- 权限提升策略
- 防御绕过技术

#### 5. 安装阶段 (Installation)
- 持久化机制选择
- 后门安装策略
- 防检测技术

#### 6. 命令控制阶段 (Command & Control)
- C2通信协议选择
- 隐蔽通道建立
- 心跳和控制机制

#### 7. 目标行为阶段 (Actions on Objectives)
- 数据收集目标
- 横向移动策略
- 权限维持方法
- 证据清理

### TODO列表管理
请为每个阶段创建详细的TODO列表，包含：
- 任务ID和名称
- 具体执行步骤
- 预计执行时间（避免超长任务）
- **超时时间（timeout）**：根据任务类型和复杂度，为每个任务指定合理的超时时间（秒）
  - 快速扫描（如端口扫描1-1000）：300-600秒
  - 深度扫描（如全端口扫描）：600-1800秒
  - 服务识别和版本探测：300-600秒
  - 漏洞利用：600-1200秒
  - 其他任务：根据实际情况设定
- 依赖关系
- 优先级等级
- 成功标准
- 失败时的备选方案

### 风险评估
对每个阶段评估：
- 检测风险等级
- 破坏性风险
- 法律合规风险
- 技术难度评估

### 响应格式要求（重要！）
你必须严格按照以下JSON格式返回，不要添加任何额外的说明文字：

{{"target": "提取的目标IP地址或域名", "stages": [{{"id": "reconnaissance_0", "type": "reconnaissance", "name": "侦察阶段", "description": "阶段描述", "config": {{"target": "提取的目标IP地址或域名", "tools": ["nmap"], "scan_type": "tcp_connect", "port_range": "1-1000"}}, "todos": [{{"id": "recon_port_scan", "name": "端口扫描", "description": "使用nmap扫描目标开放端口"}}, {{"id": "recon_service_id", "name": "服务识别", "description": "识别开放端口的服务版本"}}]}}, {{"id": "weaponization_1", "type": "weaponization", "name": "武器化阶段", "description": "阶段描述", "config": {{}}, "todos": []}}]}}

格式化后的示例（仅用于理解结构，实际返回时请使用紧凑格式或标准JSON格式）：
{{
  "target": "提取的目标IP地址或域名",
  "stages": [
    {{
      "id": "reconnaissance_0",
      "type": "reconnaissance",
      "name": "侦察阶段",
      "description": "阶段描述",
      "config": {{
        "target": "提取的目标IP地址或域名",
        "tools": ["nmap", "dns_enum"],
        "scan_type": "tcp_connect",
        "port_range": "1-1000"
      }},
      "todos": [
        {{
          "id": "recon_port_scan",
          "name": "端口扫描",
          "description": "使用nmap扫描目标开放端口",
          "config": {{
            "tool": "nmap",
            "timeout": 600,
            "target": "提取的目标IP地址或域名",
            "ports": "1-1000",
            "scan_type": "tcp_connect"
          }}
        }}
      ]
    }}
  ]
}}

### 关键要求
1. **target字段**：必须包含提取的目标IP地址或域名（例如："192.168.66.1"）
2. **stages数组**：必须包含完整的7个Kill Chain阶段，即使某些阶段可能暂时没有具体任务：
   - reconnaissance（侦察阶段）- 必须包含
   - weaponization（武器化阶段）- 必须包含
   - delivery（投递阶段）- 必须包含
   - exploitation（利用阶段）- 必须包含
   - installation（安装阶段）- 必须包含
   - command_control（命令控制阶段）- 必须包含
   - actions_on_objectives（目标行为阶段）- 必须包含
3. **每个stage必须包含**：
   - id: 唯一标识符（格式：阶段类型_序号）
   - type: 阶段类型（必须使用上述7种类型之一）
   - name: 阶段名称
   - description: 阶段描述
   - config: 配置对象（必须包含target字段）
   - todos: TODO列表（数组，至少包含1个任务）
4. **每个todo必须包含**：
   - id: 任务唯一标识符
   - name: 任务名称
   - description: 任务描述
   - config: 任务配置对象，**必须包含timeout字段**（超时时间，单位：秒）
     - timeout: 根据任务复杂度设定，例如：快速扫描300-600秒，深度扫描600-1800秒
     - tool: 使用的工具名称（如"nmap"）
     - 其他工具特定参数（如target、ports等）
5. **只返回JSON，不要添加任何markdown标记或说明文字**

**重要**：
- 必须返回完整的7个阶段，每个阶段至少包含1个TODO任务
- 每个todo的config中必须包含timeout字段，根据任务类型合理设定超时时间
- 如果某个阶段暂时无法执行，可以创建占位任务（如"等待前置阶段结果"），但阶段本身必须存在

请严格按照上述格式返回JSON。"""

    @staticmethod
    def get_agent_coordination_prompt(agent_type: str, task_result: Dict[str, Any], 
                                    global_context: Dict[str, Any]) -> str:
        """
        获取Agent协调提示词
        
        Args:
            agent_type: Agent类型
            task_result: 任务执行结果
            global_context: 全局上下文
            
        Returns:
            str: 协调提示词
        """
        return f"""你需要分析 {agent_type} Agent的执行结果，并提供协调指导。

### Agent执行结果
Agent类型: {agent_type}
执行结果: {task_result}
成功状态: {task_result.get('success', False)}

### 全局上下文
当前阶段: {global_context.get('current_stage', 'unknown')}
目标信息: {global_context.get('target', 'unknown')}
已发现服务: {global_context.get('discovered_services', [])}
已识别漏洞: {global_context.get('identified_vulnerabilities', [])}
当前权限级别: {global_context.get('current_access_level', 'none')}

### 分析要求
请分析以下内容：

1. **结果评估**
   - 任务完成质量评价
   - 发现的关键信息
   - 存在的问题或不足

2. **上下文整合**
   - 如何将结果整合到全局知识库
   - 对后续阶段的影响分析
   - 策略调整建议

3. **下一步行动**
   - 是否需要重试或调整当前任务
   - 下一个Agent的任务准备
   - TODO列表更新建议

4. **风险控制**
   - 检测到的安全风险
   - 需要注意的合规问题
   - 建议的缓解措施

请提供具体的协调建议和行动计划。"""

    @staticmethod
    def get_error_correction_prompt(error_info: Dict[str, Any], agent_type: str, 
                                  context: Dict[str, Any]) -> str:
        """
        获取错误修正提示词
        
        Args:
            error_info: 错误信息
            agent_type: 出错的Agent类型
            context: 执行上下文
            
        Returns:
            str: 修正提示词
        """
        return f"""你需要分析 {agent_type} Agent的执行错误，并制定修正策略。

### 错误信息
Agent类型: {agent_type}
错误类型: {error_info.get('error_type', 'unknown')}
错误消息: {error_info.get('error_message', '')}
失败的任务: {json.dumps(error_info.get('failed_task', {}), ensure_ascii=False, indent=2)}
执行时间: {error_info.get('timestamp', '')}

### 执行上下文
当前阶段: {context.get('current_stage', 'unknown')}
之前的尝试次数: {context.get('retry_count', 0)}
可用的替代方法: {context.get('alternative_methods', [])}

### 修正分析
请进行以下分析：

1. **错误原因分析**
   - 技术性错误（网络、工具、参数）
   - 逻辑性错误（策略、流程）
   - 环境性错误（目标变化、权限）

2. **修正策略**
   - 参数调整方案
   - 替代工具或方法
   - 执行流程优化

3. **重试决策**
   - 是否值得重试
   - 重试条件和次数限制
   - 何时放弃当前方法

4. **预防措施**
   - 如何避免类似错误
   - 监控和预警机制
   - 流程改进建议

请提供具体的修正方案和实施建议。"""

    @staticmethod
    def get_todo_management_prompt(current_todos: List[Dict[str, Any]], 
                                 execution_state: Dict[str, Any]) -> str:
        """
        获取TODO管理提示词
        
        Args:
            current_todos: 当前TODO列表
            execution_state: 执行状态
            
        Returns:
            str: TODO管理提示词
        """
        return f"""你需要管理和更新渗透测试项目的TODO列表，确保任务有序推进且防止超长执行。

### 当前TODO状态
总TODO数量: {len(current_todos)}
待处理TODO: {len([t for t in current_todos if t.get('status') == 'pending'])}
进行中TODO: {len([t for t in current_todos if t.get('status') == 'in_progress'])}
已完成TODO: {len([t for t in current_todos if t.get('status') == 'completed'])}

详细TODO列表:
{current_todos}

### 执行状态
当前阶段: {execution_state.get('current_stage', 'unknown')}
执行时长: {execution_state.get('execution_duration', 0)} 秒
最近的失败: {execution_state.get('recent_failures', [])}
资源使用情况: {json.dumps(execution_state.get('resource_usage', {}), ensure_ascii=False, indent=2)}

### 管理要求
请分析并提供以下管理建议：

1. **优先级调整**
   - 哪些TODO需要提高优先级
   - 哪些TODO可以降低优先级或推迟
   - 关键路径分析

2. **任务分解**
   - 识别超长任务（>30分钟）
   - 将复杂任务分解为子任务
   - 设置合理的检查点

3. **依赖关系优化**
   - 检查依赖关系的合理性
   - 识别可以并行执行的任务
   - 解决依赖冲突

4. **执行策略**
   - 当前应该执行的下一个TODO
   - 暂停或取消的TODO及原因
   - 新增的TODO需求

5. **风险控制**
   - 识别高风险TODO
   - 设置安全检查点
   - 回滚和恢复策略

请提供具体的TODO管理建议和更新计划。"""

    @staticmethod
    def get_progress_summary_prompt(session_data: Dict[str, Any]) -> str:
        """
        获取进度总结提示词
        
        Args:
            session_data: 会话数据
            
        Returns:
            str: 总结提示词
        """
        return f"""请提供渗透测试项目的全面进度总结。

### 会话信息
会话ID: {session_data.get('session_id', 'unknown')}
目标: {session_data.get('target', 'unknown')}
开始时间: {session_data.get('start_time', 'unknown')}
当前状态: {session_data.get('current_state', 'unknown')}

### 执行统计
总TODO数: {len(session_data.get('all_todos', []))}
已完成TODO: {len([t for t in session_data.get('all_todos', []) if t.get('status') == 'completed'])}
发现的服务: {len(session_data.get('discovered_services', []))}
识别的漏洞: {len(session_data.get('identified_vulnerabilities', []))}
成功的利用: {len(session_data.get('successful_exploits', []))}

### 总结要求
请提供以下内容：

1. **执行摘要**
   - 主要成就和发现
   - 当前进度百分比
   - 关键里程碑

2. **安全发现**
   - 发现的漏洞清单
   - 风险等级评估
   - 修复建议优先级

3. **技术分析**
   - 成功的攻击向量
   - 失败的尝试分析
   - 技术难点总结

4. **项目状态**
   - 当前阶段状态
   - 剩余工作评估
   - 预计完成时间

5. **建议和改进**
   - 后续行动建议
   - 测试策略优化
   - 工具和方法改进

请提供详细的项目总结报告。"""

    @staticmethod
    def get_credential_extraction_prompt(text: str) -> str:
        """
        获取凭证提取提示词（参考 harbinger 的设计）
        
        Args:
            text: 要分析的文本内容
            
        Returns:
            str: 凭证提取提示词
        """
        return f"""分析以下文本并提取所有可验证的凭证信息。请高精度提取，最大程度减少误报。

### 待分析文本
{text}

### 提取要求
1. **精确匹配**：只提取明确存在的用户名/密码对，不要猜测或推断凭证
2. **上下文分析**：利用上下文线索如 "username"、"password"、"login"、"credentials"、"account" 等标签
3. **格式识别**：考虑不同的凭证格式，包括：
   - 邮箱地址作为用户名
   - 包含特殊字符的用户名
   - 混淆的凭证
   - Base64编码的凭证
   - NTLM哈希
   - Kerberos票据

### 输出格式要求
请严格按照以下JSON格式返回：
{{
    "found_credentials": true/false,
    "credentials": [
        {{
            "username": "用户名部分",
            "password": "密码或哈希值",
            "domain": "域名（如果有）",
            "credential_type": "plaintext/ntlm_hash/kerberos/other",
            "source": "凭证来源描述",
            "confidence": "high/medium/low"
        }}
    ]
}}

### 注意事项
- 如果用户名包含 "@" 符号，将其解析为用户名和域名两部分
- 不要编造、猜测或推断凭证
- 每个凭证条目必须包含 username 和 password/hash 字段
- 只返回JSON，不要添加任何说明文字"""

    @staticmethod
    def get_action_summary_prompt(command: str, arguments: str, output: str) -> str:
        """
        获取行动摘要提示词（参考 harbinger 的设计）
        
        Args:
            command: 执行的命令
            arguments: 命令参数
            output: 命令输出
            
        Returns:
            str: 行动摘要提示词
        """
        attack_phases_str = ", ".join(ATTACK_PHASES)
        
        return f"""你是一位网络安全专家，请为以下执行的操作和输出编写简短摘要。

### 执行信息
命令: {command}
参数: {arguments}
输出: {output[:2000] if len(output) > 2000 else output}{"... (输出已截断)" if len(output) > 2000 else ""}

### 摘要要求
1. **语态**：使用主动语态，以"红队"作为执行者
2. **简洁**：一到两句话概括操作内容和结果
3. **保密**：不要在摘要中包含密码等敏感信息
4. **不要**：
   - 使用 "尝试" 或 "试图" 等词
   - 提及 GUID 标识符
   - 提及 "safe" 相关信息

### 输出格式要求
请严格按照以下JSON格式返回：
{{
    "summary": "摘要文本",
    "successful": true/false,
    "error": true/false,
    "status": "completed/error/in_progress",
    "attack_phase": "攻击阶段（必须是以下之一：{attack_phases_str}）",
    "detection_risk": 1-5（1=低风险，5=肯定被检测）
}}

只返回JSON，不要添加任何说明文字。"""

    @staticmethod
    def get_attack_path_summary_prompt(summaries: List[str]) -> str:
        """
        获取攻击路径摘要提示词
        
        Args:
            summaries: 各个行动的摘要列表
            
        Returns:
            str: 攻击路径摘要提示词
        """
        summaries_text = "\n".join([f"- {s}" for s in summaries])
        
        return f"""你是一位网络安全专家，请基于以下行动摘要编写一个攻击路径描述。

### 行动摘要列表
{summaries_text}

### 要求
1. 使用主动语态描述攻击过程
2. 将其编写成一个引人入胜的故事
3. 忽略失败的操作，只描述成功推进红队目标的重要步骤
4. 突出关键的攻击阶段和里程碑
5. 包含以下要素：
   - 初始入口点
   - 权限提升路径
   - 横向移动过程
   - 最终成果

请提供一个完整、连贯的攻击路径描述。"""

    @staticmethod
    def get_detection_risk_assessment_prompt(
        action: str, 
        edr_info: str,
        implant_info: str
    ) -> str:
        """
        获取检测风险评估提示词
        
        Args:
            action: 要执行的操作
            edr_info: EDR/防护软件信息
            implant_info: 植入程序信息
            
        Returns:
            str: 检测风险评估提示词
        """
        return f"""你是一位网络安全专家，请评估以下操作被检测的可能性。

### 操作信息
{action}

### EDR/防护软件信息
{edr_info}

### 植入程序/代理信息
{implant_info}

### 评估要求
请根据以下因素评估检测风险：
1. **EDR检测能力**：分析目标系统上的EDR是否能检测此类操作
2. **操作特征**：操作是否会产生异常的网络流量、文件活动或进程行为
3. **隐蔽性**：操作是否使用了隐蔽技术
4. **历史数据**：类似操作的历史检测率

### 输出格式要求
请严格按照以下JSON格式返回：
{{
    "detection_risk": 1-5,
    "reason": "详细的风险评估理由",
    "mitigation_suggestions": ["降低风险的建议1", "建议2"],
    "alternative_methods": ["替代方法1", "替代方法2"]
}}

风险等级说明：
- 1: 低风险 - 不太可能被检测
- 2: 中等风险 - 有一定检测可能
- 3: 高风险 - 较高检测可能
- 4: 很高风险 - 很可能被检测
- 5: 极高风险 - 几乎肯定被检测

只返回JSON，不要添加任何说明文字。"""

    @staticmethod
    def get_next_action_suggestion_prompt(
        implant_info: str,
        executed_tasks: List[str],
        available_playbooks: List[Dict[str, Any]],
        edr_info: str = ""
    ) -> str:
        """
        获取下一步行动建议提示词（参考 harbinger 的设计）
        
        Args:
            implant_info: 植入程序信息
            executed_tasks: 已执行的任务列表
            available_playbooks: 可用的Playbook列表
            edr_info: EDR信息
            
        Returns:
            str: 下一步行动建议提示词
        """
        tasks_text = "\n".join([f"- {t}" for t in executed_tasks]) if executed_tasks else "尚无已执行任务"
        playbooks_text = json.dumps(available_playbooks, ensure_ascii=False, indent=2) if available_playbooks else "[]"
        
        return f"""你是一位网络安全专家，请根据当前情况建议下一步操作。

### 植入程序/代理信息
{implant_info}

### 已执行任务
{tasks_text}

### 可用的Playbook/工具
{playbooks_text}

### EDR/防护软件信息
{edr_info if edr_info else "未知"}

### 建议要求
1. **避免重复**：如果某个操作已成功执行，不需要再次执行
2. **隐蔽性**：确保使用隐蔽技术，尽量融入环境
3. **检测规避**：评估EDR是否可能检测到操作
4. **逻辑顺序**：按照攻击生命周期的逻辑顺序建议操作

### 一般操作顺序
每个主机应执行：
1. 初始侦察
2. 检查主机上的有趣信息
3. 禁用防御措施（如可行）
4. 收集凭证
5. 横向移动准备

### 输出格式要求
请严格按照以下JSON格式返回：
{{
    "suggested_actions": [
        {{
            "name": "操作名称",
            "reason": "建议此操作的原因",
            "playbook_id": "Playbook ID（如适用）",
            "arguments": {{"参数名": "参数值"}},
            "priority": 1-5,
            "detection_risk": 1-5
        }}
    ],
    "overall_assessment": "当前阶段的整体评估"
}}

如果没有建议的操作，返回空列表：{{"suggested_actions": [], "overall_assessment": "原因说明"}}

只返回JSON，不要添加任何说明文字。"""

    @staticmethod  
    def get_report_generation_prompt(session_data: Dict[str, Any]) -> str:
        """
        获取报告生成提示词
        
        Args:
            session_data: 会话数据
            
        Returns:
            str: 报告生成提示词
        """
        return f"""请根据以下渗透测试数据生成一份专业的安全评估报告。

### 测试信息
目标: {session_data.get('target', 'unknown')}
测试时间: {session_data.get('start_time', 'unknown')} - {session_data.get('end_time', 'unknown')}
测试范围: {session_data.get('scope', '完整渗透测试')}

### 发现的服务
{json.dumps(session_data.get('discovered_services', []), ensure_ascii=False, indent=2)}

### 发现的漏洞
{json.dumps(session_data.get('vulnerabilities', []), ensure_ascii=False, indent=2)}

### 获取的凭证
{json.dumps(session_data.get('credentials', []), ensure_ascii=False, indent=2)}

### 执行的攻击
{json.dumps(session_data.get('attacks', []), ensure_ascii=False, indent=2)}

### 报告结构要求
请生成包含以下章节的报告：

1. **执行摘要**
   - 测试概述
   - 关键发现
   - 风险评级

2. **测试范围和方法论**
   - 测试目标
   - 测试方法
   - 使用的工具

3. **详细发现**
   - 高风险漏洞
   - 中风险漏洞
   - 低风险漏洞
   - 信息泄露

4. **攻击路径分析**
   - 成功的攻击向量
   - 权限提升路径
   - 横向移动路径

5. **修复建议**
   - 紧急修复项
   - 短期改进项
   - 长期安全策略

6. **技术附录**
   - 详细技术数据
   - 证据截图说明
   - 使用的工具清单

请使用Markdown格式生成报告。"""
