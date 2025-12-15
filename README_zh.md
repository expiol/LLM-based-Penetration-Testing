# 基于LLM的渗透测试框架

基于Kill Chain模型的智能渗透测试框架，由大语言模型（LLM）驱动。该框架自动化从侦察到目标达成的完整渗透测试流程。

## 功能特性

- **自动化Kill Chain执行**：遵循完整的网络杀伤链模型（侦察 → 武器化 → 投递 → 利用 → 安装 → 命令控制 → 目标达成）
- **LLM驱动的规划**：使用主控LLM智能生成和调整执行计划
- **多Agent架构**：为每个Kill Chain阶段配备专门的Agent
- **实时监控**：使用Textual的实时TUI界面进行任务跟踪
- **智能中断**：执行过程中可暂停并根据用户输入重新规划
- **分布式执行**：基于Ray构建，支持可扩展的分布式任务执行
- **双语支持**：支持中英文显示（可配置）

## 系统要求

- Python 3.8+
- LLM API访问权限（兼容OpenAI的API）
- 网络访问权限（用于渗透测试工具）

## 安装

1. 克隆仓库：
```bash
git clone <repository-url>
cd LLM-based-Penetration-Testing
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

3. 在 `configs/llm_runtime.json` 中配置LLM设置：
```json
{
  "master_agent": {
    "protocol": "https",
    "host": "api.example.com",
    "port": 443,
    "api_key": "your-api-key",
    "model_name": "gpt-4",
    "temperature": 0.7,
    "max_tokens": 4096
  },
  "ui": {
    "language": "zh"
  }
}
```

## 配置

### 语言设置

框架支持双语显示（英文/中文）。在 `configs/llm_runtime.json` 中配置语言：

```json
{
  "ui": {
    "language": "zh"  // 或 "en" 表示英文
  }
}
```

默认语言为英文（`"en"`）。

## 使用方法

### 基本使用

启动框架：
```bash
python Pentest.py
```

或直接指定目标：
```bash
python Pentest.py --target "192.168.1.100"
```

### 命令

- `start <目标>` - 开始对目标进行渗透测试
- `status` - 查看当前会话状态
- `help` - 显示帮助信息
- `quit` - 退出程序

### 交互模式

在任务执行过程中，您可以：
- 输入补充信息以暂停并重新规划
- 按 `Ctrl+C` 暂停监控（任务在后台继续执行）
- 输入 `q` 或 `quit` 退出

### UI模式

框架支持两种UI模式：

1. **Textual TUI**（推荐）：现代化的终端UI，无抖动
   - 如果已安装Textual，将自动使用
   - 安装：`pip install textual textual-dev`

2. **简单日志模式**：回退的滚动日志模式
   - 使用 `--simple` 标志强制使用简单模式

## 架构

### 组件

- **主控制器**：协调整个Kill Chain执行
- **Agent池**：每个阶段的专门Agent（侦察、武器化、投递、利用、安装、C2、目标）
- **Todo管理器**：管理任务列表和执行状态
- **状态管理器**：跟踪全局上下文和会话状态
- **工具适配器**：与渗透测试工具（nmap等）的接口

### Kill Chain阶段

1. **侦察**：信息收集和目标发现
2. **武器化**：载荷和漏洞利用准备
3. **投递**：载荷投递机制
4. **利用**：漏洞利用
5. **安装**：持久化机制
6. **命令控制**：C2通道建立
7. **目标达成**：最终目标完成

## 项目结构

```
LLM-based-Penetration-Testing/
├── Pentest.py              # 主入口文件
├── configs/                 # 配置文件
│   └── llm_runtime.json    # LLM和UI配置
├── src/
│   ├── agents/             # Agent实现
│   ├── core/               # 核心控制器和管理器
│   ├── framework/          # 框架初始化
│   ├── ui/                 # 用户界面（Textual TUI）
│   ├── utils/              # 工具类（包括i18n）
│   └── tools/              # 渗透测试工具
├── pentest_events/         # 事件存储和数据库
└── requirements.txt         # Python依赖
```

## 国际化

框架包含全面的国际化支持：

- **英文（en）**：默认语言
- **中文（zh）**：完整的中文翻译

所有UI元素、日志消息和面向用户的文本都已翻译。语言在 `configs/llm_runtime.json` 的 `ui.language` 下配置。

## 开发

### 添加新翻译

翻译在 `src/utils/i18n.py` 中管理。要添加新翻译：

1. 将键添加到 `TRANSLATIONS["en"]` 和 `TRANSLATIONS["zh"]`
2. 在代码中使用 `t("key.name")` 获取翻译

### 扩展Agent

可以通过以下方式添加新Agent：
1. 在 `src/agents/` 中创建新的Agent类
2. 在Agent池中注册
3. 添加相应的Kill Chain阶段映射

## 安全注意事项

⚠️ **重要**：此框架仅用于授权的渗透测试。在测试任何目标之前，请确保您有适当的授权。

- 仅在授权环境中使用
- 执行前审查并理解所有生成的载荷
- 监控所有网络活动
- 遵循负责任的披露实践

## 许可证

详细信息请参阅LICENSE文件。

## 贡献

欢迎贡献！请确保：
- 代码遵循现有风格
- 为新功能添加测试
- 更新文档
- 为新UI文本添加翻译

## 支持

如有问题和疑问，请在仓库中提交issue。

