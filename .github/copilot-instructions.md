# Copilot Coding Agent Instructions for LLM-based Penetration Testing

## 项目架构与核心理念
- 本项目为基于LLM的自动化渗透测试平台，采用LangChain Agent系统与Ray分布式执行。
- 以Cyber Kill Chain为主线，分为Recon、Weaponize、Delivery、Exploit、Install、C2、Objectives七大阶段，每个阶段有独立Agent（见`src/agents/`）。
- 主控LLM负责任务规划、动态调整、TODO分发，详见`src/core/master_controller.py`、`src/core/todo_manager.py`。
- 工具统一由`src/agents/tools_adapter.py`和`src/core/agent_tool_manager.py`调度，支持公有与私有工具（`src/tools/public/`、`src/tools/private/`）。
- Ray集成用于分布式Agent调度（`src/ray_integration/`）。

## 关键开发与调试流程
- 启动入口为`Pentest.py`，交互式CLI，支持自然语言命令（如`start <目标描述>`、`monitor`、`tasks`、`interrupt <信息>`）。
- 配置文件位于`configs/llm_runtime.json`，需设置LLM API信息。
- 数据与事件日志存储于`pentest_events/`，数据库结构见`pentest_events/README.md`。
- 工具开发需遵循现有适配器模式，参考`src/agents/tools_adapter.py`和已有工具实现。
- Prompt模板集中于`src/prompts/`，Agent与主控LLM分别有独立prompt文件。

## 代码风格与约定
- Agent需继承`BaseAgent`（见`src/agents/base_agent.py`），实现`run()`等核心方法。
- 工具需实现标准输入输出接口，便于统一调度和错误处理。
- 所有跨模块通信建议通过明确定义的接口或事件流（如数据库、日志、Ray消息）。
- 配置、状态、任务等均应通过专用管理器（如`todo_manager.py`、`execution_manager.py`）维护。
- 遇到任务失败，Agent应自动尝试替代方案或上报主控LLM重新规划。

## 测试与调试建议
- 推荐在虚拟环境下开发，依赖见`requirements.txt`。
- 主要调试命令：`python Pentest.py` 启动CLI，使用`monitor`、`tasks`、`interrupt`等命令实时观察。
- 工具集成测试可单独运行对应脚本（如`python src/tools/public/nmap_tool.py`）。
- 日志与执行记录详见`pentest_events/files/`与数据库。

## 重要文件/目录参考
- `src/agents/`：各阶段Agent实现与适配器
- `src/core/`：主控、调度、任务与工具管理
- `src/tools/`：公有/私有工具实现
- `src/prompts/`：LLM提示词模板
- `pentest_events/`：数据与日志存储
- `configs/llm_runtime.json`：LLM与Agent配置

## 其他注意事项
- 默认启用安全模式，所有高危操作需显式声明。
- 仅用于授权测试，严禁非法用途。
- 详细开发、集成、调试流程见主`README.md`与各子目录文档。
