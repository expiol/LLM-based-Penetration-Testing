# LLM-based Penetration Testing Framework

一个基于大语言模型（LLM）的自动化渗透测试框架，采用 LangChain + Ray 架构，实现智能化的渗透测试流程。

## ⚠️ 重要提示

**本项目目前仍处于开发阶段，尚未经过充分测试和完善。** 使用前请注意：

- 可能存在未知的bug和稳定性问题
- 功能可能不完整或存在缺陷
- 建议仅在测试环境中使用
- 请勿用于未授权的渗透测试活动

## 📋 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [技术架构](#技术架构)
- [安装指南](#安装指南)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [使用指南](#使用指南)
- [项目结构](#项目结构)
- [开发状态](#开发状态)
- [注意事项](#注意事项)
- [许可证](#许可证)

## 🎯 项目简介

本项目是一个基于大语言模型的自动化渗透测试框架，通过LLM的智能决策能力，结合传统的渗透测试工具，实现端到端的自动化渗透测试流程。框架采用 Cyber Kill Chain 模型，将渗透测试分为7个阶段，每个阶段由专门的Agent负责执行。

### 设计理念

- **智能化决策**：使用LLM进行任务规划、策略制定和动态调整
- **模块化架构**：基于LangChain的Agent系统和Ray的分布式执行
- **灵活扩展**：支持自定义工具和Agent
- **安全优先**：内置安全模式，防止破坏性操作

## ✨ 核心特性

### 1. 智能任务规划
- 主控LLM自动从用户描述中提取目标信息
- 生成完整的7阶段Kill Chain执行计划
- 为每个任务动态设定超时时间
- 支持任务中断和重新规划

### 2. 多Agent协作
- **Recon Agent（侦察）**：端口扫描、服务识别、信息收集
- **Weaponize Agent（武器化）**：漏洞分析、载荷准备
- **Delivery Agent（投递）**：攻击向量实施
- **Exploit Agent（利用）**：漏洞利用、权限获取
- **Install Agent（安装）**：持久化机制建立
- **C2 Agent（命令控制）**：通信渠道建立
- **Objectives Agent（目标行为）**：数据收集、横向移动

### 3. 动态调整策略
- Agent在工具执行失败时自动尝试替代方案
- 支持多种扫描方法和攻击向量
- 智能错误处理和恢复机制

### 4. 实时监控
- 交互式CLI界面
- 实时任务状态显示
- 进度跟踪和任务列表查看
- 支持中断和重新规划

### 5. 工具集成
- **Nmap**：端口扫描和服务识别
- **Command Executor**：命令执行工具
- **Auto Decode**：自动解码工具
- 支持自定义工具扩展

## 🏗️ 技术架构

### 架构层次

```
┌─────────────────────────────────────────┐
│      Interactive CLI (Pentest.py)      │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│    AutoPentestFramework                  │
│  - 框架初始化和协调                      │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
┌───────▼────────┐  ┌───────▼────────┐
│ Master LLM     │  │  Ray Master    │
│ (任务规划)      │  │  Controller    │
└────────────────┘  └───────┬────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼────────┐  ┌───────▼────────┐  ┌───────▼────────┐
│ LangChain      │  │  Ray Agent     │  │  Tool Manager  │
│ Agents         │  │  Actors        │  │  (工具管理)     │
└───────┬────────┘  └───────┬────────┘  └────────────────┘
        │                   │
        └─────────┬─────────┘
                  │
        ┌─────────▼─────────┐
        │   Tools (Nmap等)  │
        └───────────────────┘
```

### 核心技术栈

- **LangChain 0.3.7+**：Agent框架和工具适配
- **Ray 2.39.0+**：分布式执行和状态管理
- **OpenAI API**：大语言模型服务（支持兼容OpenAI API的服务）
- **Python 3.10+**：主要编程语言
- **SQLAlchemy**：数据库ORM
- **asyncio**：异步编程支持

## 📦 安装指南

### 环境要求

- Python 3.10 或更高版本
- 8GB+ 内存（推荐）
- 网络连接（用于LLM API调用）
- 可选：root权限（用于某些扫描功能）

### 安装步骤

1. **克隆仓库**
```bash
git clone <repository-url>
cd LLM-based-Penetration-Testing
```

2. **创建虚拟环境（推荐使用conda）**
```bash
conda create -n pentest python=3.10
conda activate pentest
```

3. **安装依赖**
```bash
pip install -r requirements.txt
```

4. **配置LLM服务**
编辑 `configs/llm_runtime.json`，配置你的LLM API信息：
```json
{
  "master_agent": {
    "api_key": "your-api-key",
    "base_url": "https://api.example.com",
    "model_name": "gpt-4o"
  },
  "sub_agents": {
    "api_key": "your-api-key",
    "base_url": "https://api.example.com",
    "model_name": "gpt-4o"
  }
}
```

5. **初始化数据库（可选）**
数据库会在首次运行时自动创建。

## 🚀 快速开始

### 基本使用

1. **启动框架**
```bash
python Pentest.py
```

2. **开始渗透测试**
```bash
pentest> start 192.168.1.100这个目标
```

或者直接输入目标描述：
```bash
pentest> 测试192.168.1.100的Web应用漏洞
```

3. **监控执行**
```bash
pentest> monitor
```

4. **查看任务列表**
```bash
pentest> tasks
```

5. **中断和重新规划**
```bash
pentest> interrupt 发现新端口8080
```

### 可用命令

- `start <目标描述>` - 开始新的渗透测试
- `status` - 查看当前会话状态
- `tasks` - 查看所有任务列表
- `monitor` - 实时监控任务执行（按 Ctrl+C 退出监控）
- `interrupt <信息>` - 中断当前执行并重新规划
- `help` - 显示帮助信息
- `quit` - 退出程序

## ⚙️ 配置说明

### LLM配置 (`configs/llm_runtime.json`)

```json
{
  "master_agent": {
    "protocol": "https",
    "host": "api.chatanywhere.tech",
    "port": 443,
    "api_key": "your-api-key",
    "model_name": "gpt-4o-ca",
    "temperature": 0.7,
    "max_tokens": 4096
  },
  "sub_agents": {
    "protocol": "https",
    "host": "api.chatanywhere.tech",
    "port": 443,
    "api_key": "your-api-key",
    "model_name": "gpt-4o-ca",
    "temperature": 0.7,
    "max_tokens": 2048
  }
}
```

### Agent配置

每个Agent可以配置：
- `safe_mode`: 安全模式（默认true）
- `num_cpus`: CPU资源分配
- `num_gpus`: GPU资源分配
- `timeout`: 超时时间（秒）
- `scan_timeout`: 扫描超时时间（秒）

### Ray配置

```json
{
  "ray": {
    "num_cpus": 8,
    "num_gpus": 0,
    "object_store_memory": 2000000000
  }
}
```

## 📖 使用指南

### 1. 启动渗透测试

框架支持自然语言描述目标：
- `start 192.168.1.100这个路由器`
- `start 测试example.com的Web应用`
- `start 扫描192.168.1.0/24网段`

主控LLM会自动：
- 提取目标IP/域名
- 生成7阶段执行计划
- 为每个任务设定超时时间
- 创建详细的TODO列表

### 2. 实时监控

使用 `monitor` 命令可以实时查看：
- 当前正在执行的任务
- 任务进度（完成/总数/百分比）
- 进行中和待处理任务数量

按 `Ctrl+C` 退出监控（不会中断任务执行）。

### 3. 中断和重新规划

如果发现新信息，可以使用 `interrupt` 命令：
```bash
pentest> interrupt 发现新端口8080开放
```

框架会：
- 暂停当前执行
- 结合新信息重新生成执行计划
- 更新TODO列表
- 准备继续执行

### 4. 任务管理

- `tasks` - 查看所有任务状态
- `status` - 查看会话状态
- 任务状态包括：pending, in_progress, completed, failed, cancelled

## 📁 项目结构

```
LLM-based-Penetration-Testing/
├── Pentest.py                 # 主入口文件
├── requirements.txt           # Python依赖
├── configs/
│   └── llm_runtime.json      # LLM配置
├── src/
│   ├── agents/               # LangChain Agents
│   │   ├── base_agent.py
│   │   ├── recon_agent.py
│   │   ├── weaponize_agent.py
│   │   ├── delivery_agent.py
│   │   ├── exploit_agent.py
│   │   ├── install_agent.py
│   │   ├── c2_agent.py
│   │   ├── objectives_agent.py
│   │   └── tools_adapter.py
│   ├── core/                 # 核心组件
│   │   ├── master_controller.py    # 主控制器
│   │   ├── agent_tool_manager.py   # 工具管理
│   │   ├── execution_manager.py    # 执行管理
│   │   └── todo_manager.py         # 任务管理
│   ├── framework/
│   │   └── auto_framework.py       # 框架初始化
│   ├── prompts/              # LLM提示词
│   │   ├── master_prompts.py
│   │   └── agent_prompts.py
│   ├── tools/                 # 工具集
│   │   ├── public/           # 公有工具
│   │   │   ├── nmap_tool.py
│   │   │   ├── cmd_executer.py
│   │   │   └── auto_decode.py
│   │   └── private/          # 私有工具（按Agent分类）
│   ├── ray_integration/      # Ray集成
│   │   ├── ray_agent_actor.py
│   │   └── ray_state_manager.py
│   └── database/             # 数据库
│       ├── models.py
│       └── logging_service.py
└── pentest_events/           # 数据存储
    ├── db/                   # 数据库文件
    └── files/                # 扫描结果、报告等
```

## 🔧 开发状态

### 已完成功能

- ✅ 基础框架架构（LangChain + Ray）
- ✅ 7个Kill Chain Agent实现
- ✅ 主控LLM任务规划
- ✅ 工具集成（Nmap、命令执行等）
- ✅ 交互式CLI界面
- ✅ 实时监控和任务管理
- ✅ 中断和重新规划功能
- ✅ 动态超时时间配置
- ✅ Agent动态调整策略

### 待完善功能

- ⚠️ 更多工具集成
- ⚠️ 报告生成功能
- ⚠️ 更完善的错误处理
- ⚠️ 性能优化
- ⚠️ 单元测试和集成测试
- ⚠️ 文档完善

### 已知问题

- 某些Agent的Prompt模板可能存在格式问题
- 工具执行失败时的重试机制需要优化
- 监控界面可能需要进一步优化
- 数据库模型可能需要扩展

## ⚠️ 注意事项

### 安全警告

1. **仅用于授权测试**：本工具仅应用于已获得明确授权的渗透测试活动
2. **遵守法律法规**：使用本工具进行未授权的渗透测试可能违反法律
3. **安全模式**：默认启用安全模式，但仍需谨慎使用
4. **数据保护**：测试结果可能包含敏感信息，请妥善保管

### 使用限制

1. **LLM API依赖**：需要稳定的LLM API服务
2. **网络要求**：需要网络连接以调用LLM API
3. **资源消耗**：Ray框架会消耗一定的系统资源
4. **权限要求**：某些扫描功能可能需要root权限

### 故障排除

1. **LLM调用失败**：检查API配置和网络连接
2. **工具执行失败**：检查工具是否已安装（如nmap）
3. **Ray启动失败**：检查系统资源和端口占用
4. **数据库错误**：检查数据库文件权限

## ❓ 常见问题

### Q: 如何退出监控？
A: 在监控界面按 `Ctrl+C` 即可退出监控。退出监控不会中断任务执行，任务仍在后台运行。

### Q: 如何查看任务执行状态？
A: 使用 `tasks` 命令查看所有任务列表，或使用 `status` 命令查看当前会话状态。

### Q: LLM API调用失败怎么办？
A: 检查 `configs/llm_runtime.json` 中的API配置，确保：
- API Key正确
- 网络连接正常
- API服务可用

### Q: Nmap扫描失败？
A: 可能的原因：
- 目标不可达
- 防火墙阻止
- 需要root权限（某些扫描类型）
- 检查网络连接和目标状态

### Q: 如何中断执行并重新规划？
A: 使用 `interrupt <补充信息>` 命令，例如：
```bash
pentest> interrupt 发现新端口8080开放
```

### Q: 任务执行时间过长？
A: LLM会为每个任务设定超时时间，如果任务超时：
- 检查网络连接
- 检查目标是否可达
- 考虑使用 `interrupt` 命令重新规划

## 📝 开发计划

- [ ] 完善测试覆盖
- [ ] 优化Agent执行效率
- [ ] 增加更多渗透测试工具
- [ ] 改进报告生成功能
- [ ] 添加Web界面
- [ ] 支持更多LLM服务商
- [ ] 完善错误处理和重试机制
- [ ] 性能优化和资源管理

## 🤝 贡献

欢迎提交Issue和Pull Request。由于项目仍在开发中，请确保：

1. 代码符合项目风格
2. 添加必要的注释
3. 测试新功能
4. 更新相关文档

## 📄 许可证

详见 [LICENSE](LICENSE) 文件。

## 🙏 致谢

- LangChain 团队
- Ray 项目
- 所有开源工具和库的贡献者

---

**再次提醒**：本项目仍在开发中，可能存在bug和功能缺陷。使用前请充分测试，并仅用于合法的渗透测试活动。

