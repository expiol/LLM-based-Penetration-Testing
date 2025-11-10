"""
主控LLM提示词模板
管理整个渗透测试项目的LLM prompts
"""
import json
from typing import Dict, Any, List


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

用户描述：{raw_description}

### 任务要求
1. **目标提取**：从用户描述中准确提取目标地址（IP地址或域名）
2. **计划制定**：基于提取的目标制定完整的渗透测试计划

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

{{"target": "提取的目标IP地址或域名", "stages": [{{"id": "reconnaissance_0", "type": "reconnaissance", "name": "侦察阶段", "description": "阶段描述", "config": {{"target": "提取的目标IP地址或域名", "tools": ["nmap", "dns_enum"], "scan_type": "tcp_connect", "port_range": "1-1000"}}, "todos": [{{"id": "recon_port_scan", "name": "端口扫描", "description": "使用nmap扫描目标开放端口"}}]}}, {{"id": "weaponization_1", "type": "weaponization", "name": "武器化阶段", "description": "阶段描述", "config": {{}}, "todos": []}}]}}

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
          "description": "使用nmap扫描目标开放端口"
        }}
      ]
    }}
  ]
}}

### 关键要求
1. **target字段**：必须包含提取的目标IP地址或域名（例如："192.168.66.1"）
2. **stages数组**：必须包含至少一个阶段对象
3. **每个stage必须包含**：
   - id: 唯一标识符（格式：阶段类型_序号）
   - type: 阶段类型（reconnaissance/weaponization/delivery/exploitation/installation/command_control/actions_on_objectives）
   - name: 阶段名称
   - description: 阶段描述
   - config: 配置对象（必须包含target字段）
   - todos: TODO列表（数组）
4. **只返回JSON，不要添加任何markdown标记或说明文字**

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
