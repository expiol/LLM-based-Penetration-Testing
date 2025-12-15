# 用户中断与智能重新规划功能

## 功能概述

在渗透测试执行过程中，用户可以随时输入补充信息，系统会使用主控LLM智能分析并调整执行计划，**保留已完成的工作**，而非简单地从头开始。

## 核心设计

### 1. 三种调整策略

主控LLM会根据用户补充信息智能选择以下策略之一：

#### ✅ 策略A：继续当前阶段 (continue_current)
**适用场景**：用户补充的是当前阶段的额外信息

**示例**：
- 用户输入："发现新端口8080开放"
- 系统行为：在当前侦察阶段添加针对8080端口的详细扫描任务
- 优点：保留所有已完成工作，最小化中断

#### 🔧 策略B：调整计划 (adjust_plan)
**适用场景**：用户信息改变了测试方向或优先级

**示例**：
- 用户输入："这是一台Nginx服务器"
- 系统行为：
  - 调整当前阶段：重点扫描Nginx相关漏洞
  - 调整后续阶段：添加Nginx特定的利用任务
  - 删除不相关任务（如IIS相关测试）
- 优点：保留已完成阶段的结果，智能调整未来计划

#### 🔄 策略C：从头重新开始 (restart_from_beginning)
**适用场景**：仅在极端情况下使用

**示例**：
- 用户输入："目标地址应该是192.168.1.100，不是192.168.1.1"
- 系统行为：清空所有结果，重新生成完整计划
- 缺点：丢失所有已完成工作

### 2. 智能决策流程

```
用户输入补充信息
    ↓
暂停当前执行的子Agent
    ↓
主控LLM分析：
  - 用户提供了什么新信息？
  - 对当前阶段有何影响？
  - 是否需要调整后续阶段？
    ↓
选择策略 (A/B/C)
    ↓
应用计划调整：
  - 添加新任务
  - 移除不相关任务
  - 修改任务优先级
    ↓
恢复执行（从调整后的计划继续）
```

## 使用方法

### CLI 交互

在测试执行过程中，直接输入补充信息即可：

```bash
# 启动测试
pentest> start 192.168.1.1

# 执行过程中随时输入
发现8080端口开放

# 系统会：
# 1. 暂停当前任务
# 2. 显示分析结果
# 3. 询问是否继续
继续执行? (y/n): y
```

### 编程接口

```python
# 使用智能中断方法（推荐）
result = await master_controller.handle_interrupt(
    session_id="session_123",
    user_message="发现新端口8080开放"
)

# 返回结果
{
    "success": True,
    "action": "continue_current",  # 或 adjust_plan / restart_from_beginning
    "reason": "用户发现了新端口，已添加到当前侦察阶段",
    "message": "重新规划完成"
}
```

## 实现细节

### 关键文件

1. **src/prompts/master_prompts.py**
   - `get_replan_with_interrupt_prompt()`: 生成重新规划的prompt
   - 包含详细的场景分析和决策指导

2. **src/core/master_controller.py**
   - `handle_interrupt()`: 主入口方法
   - `_replan_with_new_info()`: 调用主控LLM分析
   - `_handle_restart_from_beginning()`: 处理完全重启
   - `_handle_adjust_plan()`: 处理计划调整
   - `_handle_continue_current()`: 处理继续当前阶段

3. **Pentest.py**
   - `_handle_replan()`: CLI处理中断的入口
   - 显示友好的用户反馈

### Prompt 设计要点

重新规划的prompt包含以下信息：

```python
MasterPrompts.get_replan_with_interrupt_prompt(
    current_plan={...},           # 当前执行计划
    current_stage="reconnaissance", # 当前正在执行的阶段
    user_message="发现8080端口",    # 用户补充信息
    global_context={...},          # 已收集的全局信息
    stage_results={...}            # 各阶段已完成的结果摘要
)
```

prompt 会指导LLM：
- 分析用户信息的类型和影响
- 明确说明三种策略的适用场景
- 优先选择最小化中断的策略
- 返回结构化的JSON响应

### JSON 响应格式

```json
{
  "replan_action": "continue_current",
  "action_reason": "选择此操作的详细原因",
  "user_info_analysis": "对用户补充信息的分析",
  
  "current_stage_updates": {
    "stage_type": "reconnaissance",
    "action": "continue",
    "new_todos": [
      {
        "id": "todo_new_1",
        "name": "扫描8080端口",
        "description": "详细扫描新发现的8080端口",
        "tool": "nmap_tool",
        "priority": 1,
        "config": {"port": "8080", "target": "..."}
      }
    ],
    "remove_todos": [],
    "modify_todos": []
  },
  
  "subsequent_stages_updates": [],
  "new_stages": [],
  "target_updated": false,
  "priority_adjustments": []
}
```

## 优势

### 相比简单重新开始的优势

1. **保留已完成工作**
   - 已完成阶段的结果不会丢失
   - 节省时间和资源

2. **智能决策**
   - 主控LLM根据上下文做出最优选择
   - 不会因为小补充而重新开始

3. **灵活调整**
   - 可以调整任务优先级
   - 可以添加/删除特定任务
   - 可以修改阶段配置

4. **用户友好**
   - 清晰的反馈（显示选择了哪种策略及原因）
   - 确认步骤（避免意外调整）

## 注意事项

### 1. LLM配置要求

- 主控LLM需要足够的上下文窗口（建议≥8K tokens）
- 需要支持结构化JSON输出
- 温度建议设置为0.7以保持一定创造性

### 2. 最佳实践

**用户输入建议**：
- ✅ 具体明确："发现8080端口运行HTTP服务"
- ✅ 提供上下文："目标是WordPress站点，可能存在插件漏洞"
- ❌ 避免模糊："继续"、"加快速度"

**系统管理员**：
- 定期检查prompt效果，必要时调整
- 监控LLM决策质量（是否选择了合适的策略）
- 记录日志用于分析和改进

### 3. 故障恢复

如果LLM重新规划失败：
- 系统会保持原计划不变
- 显示错误信息给用户
- 用户可以重新尝试或使用不同的表述

## 扩展方向

### 未来可能的改进

1. **多轮对话**
   - 如果LLM不确定用户意图，可以反问澄清
   - 例如："您是想调整当前阶段还是后续阶段？"

2. **撤销功能**
   - 保存调整历史
   - 允许用户撤销上一次的计划调整

3. **智能建议**
   - 基于当前进度，主动建议用户可能感兴趣的调整
   - 例如："检测到MySQL服务，是否添加SQL注入测试？"

4. **可视化对比**
   - 显示调整前后的计划对比
   - 高亮显示变化的部分

## 相关文档

- [ARCHITECTURE.md](../ARCHITECTURE.md) - 整体架构说明
- [master_prompts.py](../src/prompts/master_prompts.py) - Prompt实现
- [master_controller.py](../src/core/master_controller.py) - 控制器实现
