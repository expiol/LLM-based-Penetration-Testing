# LLM渗透测试框架 - 架构设计文档

## 核心架构原则

### 1. 主从Agent分离

#### 主Agent（Master Controller）
- **职责**：战略规划与决策
  - 接收用户描述，生成完整任务列表（Kill Chain + TODOs）
  - 将子任务分配给特定子Agent执行
  - 接收子Agent执行结果
  - 思考并评估结果，决定下一步行动
  - 接收用户中途补充信息，中断当前子Agent，重新规划
  
- **禁止事项**：
  - ❌ 不调用任何工具
  - ❌ 不直接执行扫描、利用等操作
  - ❌ 只做规划和决策

- **实现文件**：`src/core/master_controller.py`

#### 子Agent（Sub Agents）
- **职责**：战术执行
  - 接收主Agent分配的具体任务
  - 调用工具或其他方式完成任务
  - 智能调整策略（工具失败时尝试替代方案）
  - 将执行结果返回给主Agent
  
- **禁止事项**：
  - ❌ 不做全局规划
  - ❌ 不自行决定下一阶段
  
- **实现文件**：
  - `src/agents/recon_agent.py`
  - `src/agents/weaponize_agent.py`
  - `src/agents/exploit_agent.py`
  - 等其他阶段Agent

### 2. 标准工作流程

```
用户输入描述
    ↓
主Agent接收 → 生成任务列表（7个Kill Chain阶段）
    ↓
主Agent分配任务 → 子Agent 1（侦察）
    ↓
子Agent 1执行 → 调用工具（nmap等）→ 智能调整
    ↓
子Agent 1返回结果 → 主Agent
    ↓
主Agent思考评估 → 生成新任务
    ↓
主Agent分配任务 → 子Agent 2（武器化）
    ↓
... 循环直至完成或用户中断
```

### 3. 用户中途补充信息流程

```
用户补充信息（如"发现新端口8080"）
    ↓
主Agent接收中断信号
    ↓
主Agent停止当前子Agent执行
    ↓
主Agent结合新信息重新规划
    ↓
主Agent生成更新的任务列表
    ↓
主Agent分配新任务给子Agent
    ↓
继续执行
```

### 4. 关键设计点

#### 工具调用权限
- **主Agent**：无工具调用权限，只能规划
- **子Agent**：有完整工具调用权限

#### 结果评估
- 子Agent返回结果后，主Agent必须：
  1. 评估任务完成度
  2. 提取关键信息
  3. 决定是否进入下一阶段
  4. 或决定重试当前阶段

#### 错误处理
- 工具失败时，子Agent可智能调整（如nmap失败换用其他扫描工具）
- 子Agent调整仍失败，返回明确错误给主Agent
- 主Agent根据错误决定：重试、跳过、或请求用户输入

#### 并发控制
- 同一时间只有一个子Agent在执行
- 主Agent等待子Agent完成后才继续
- 用户中断可随时打断子Agent

## 实现要点

### 主Agent实现（master_controller.py）
```python
class RayMasterController:
    # 1. 不注册任何工具
    # 2. 只使用LLM做规划
    # 3. 等待子Agent结果
    # 4. 根据结果决策
    
    async def _generate_execution_plan(self, target, options):
        # 使用LLM生成任务列表
        # 返回: {"stages": [...], "todos": [...]}
        
    async def _execute_from_todos_sequential(self, session_id, target, options):
        # 顺序执行：
        # 1. 分配任务给子Agent
        # 2. 等待子Agent完成
        # 3. 评估结果
        # 4. 决定下一步
        
    async def handle_interrupt(self, session_id, user_input):
        # 处理用户中断
        # 1. 停止当前子Agent
        # 2. 结合新信息重新规划
        # 3. 生成新任务列表
```

### 子Agent实现（base_agent.py及各子类）
```python
class LangChainBaseAgent:
    # 1. 注册所需工具
    # 2. 接收主Agent任务
    # 3. 执行并返回结果
    
    async def run(self, target_info, context):
        # 1. 解析任务
        # 2. 选择工具
        # 3. 执行工具
        # 4. 智能调整（失败时）
        # 5. 返回结果
```

### 工具实现（tools/）
```python
class ToolInterface:
    # 纯粹执行，不做决策
    # 失败时返回明确错误
    # 不自动安装、不自动降级
    
    async def execute(self, parameters, context):
        # 执行命令
        # 返回: {"success": bool, "data": {...}, "error": str}
```

## 数据流

### 任务列表结构
```json
{
  "target": "192.168.1.1",
  "stages": [
    {
      "id": "stage_1",
      "type": "reconnaissance",
      "name": "侦察阶段",
      "todos": [
        {
          "id": "todo_1",
          "name": "端口扫描",
          "tool": "nmap",
          "config": {"ports": "1-1000"}
        }
      ]
    }
  ]
}
```

### 子Agent返回结果结构
```json
{
  "success": true,
  "agent": "recon_agent",
  "data": {
    "open_ports": [80, 443],
    "services": [...],
    "tools_used": ["nmap"]
  },
  "error": null
}
```

### 主Agent评估结果
```python
# 主Agent评估子Agent结果
if result["success"]:
    # 提取关键信息
    # 更新全局上下文
    # 决定进入下一阶段
else:
    # 分析失败原因
    # 决定：重试、跳过、或请求用户输入
```

## 配置说明

### 主Agent配置（configs/llm_runtime.json）
```json
{
  "master_agent": {
    "api_key": "...",
    "model_name": "gpt-4",
    "temperature": 0.7,
    "max_tokens": 4096
  }
}
```

### 子Agent配置
```json
{
  "sub_agents": {
    "api_key": "...",
    "model_name": "gpt-4",
    "temperature": 0.7,
    "max_tokens": 2048
  }
}
```

## 关键原则总结

1. **职责分离**：主Agent规划，子Agent执行
2. **工具隔离**：只有子Agent能调用工具
3. **结果驱动**：子Agent返回结果后，主Agent才决策
4. **用户为先**：用户中断随时可打断子Agent
5. **明确错误**：工具失败返回清晰错误，不擅自处理
6. **智能调整**：子Agent可智能选择替代工具，但最终决策在主Agent
