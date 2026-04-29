# 项目介绍：LLM-Based Penetration Testing 

## 1. 项目概述
 
仓库当前集成了三条主要能力线：

- `NYU CTF Baseline`
- `D-CIPHER / Single Executor`
- `NYU Multi-Killchain`

代表了三种不同的自动化范式：

- `Baseline` 基本是一个 agent 自己决定下一步干什么，然后直接调工具、跑命令、看结果、继续试。所以它的特点是“直接上手、路径短”。
- `D-CIPHER` 像一个小团队，有“规划的人”和“干活的人”。先有人拆任务、分步骤，再让别的 agent 去执行各自那部分，所以它强调“分工协作”。Planner -> delegate -> Executor -> finish_task -> Planner 再决策
- `Multi-Killchain` 按固定安全分析流程一步步干活，主控调度多个专用 worker，按证据不断派生新任务。



## 2. 项目



- 可复现实验：统一数据集、统一 Docker 环境、统一日志输出。
- 可扩展能力：通过 worker / plugin 机制增加新的分析能力。
- 可审计过程：每次运行都会留下 state、summary、report、events 和 evidence。


## 3. 仓库结构与主要入口

项目根目录中的核心入口如下：

- `run_baseline.py`：运行单智能体基线系统。
- `run_single_executor.py`：运行单执行器版本的多智能体框架。
- `run_dcipher.py`：运行 Planner-Executor 多智能体系统。
- `run_mutil_killchain.py`：运行结构化 Multi-Killchain 工作流。
- `nyuctf_baseline/`：Baseline 核心实现。
- `nyuctf_multiagent/`：D-CIPHER 与 Single Executor 的核心实现。
- `nyuctf_mutil_killchain/`：Multi-Killchain 的 orchestrator、workers、plugins、reporting 等核心实现。
- `configs/`：不同系统的模型、prompt、工具集和实验配置。
- `tests/`：当前维护的回归测试。

环境准备方式如下：

```bash
./setup_mutil_killchain.sh
./setup_baseline.sh
./setup_dcipher.sh
python -m nyuctf.download
```


## 4. 三条能力线的定位

| 系统 | 主要入口 | 核心思想 | 优点 | 局限 |
| --- | --- | --- | --- | --- |
| Baseline | `run_baseline.py` | 单智能体直接调用工具完成题目 | 执行力强、自由度高、容易覆盖复杂题型 | 过程可控性较弱，易出现无序探索 |
| D-CIPHER / Single Executor | `run_dcipher.py` / `run_single_executor.py` | 规划与执行分离，强化任务分解 | 适合长链推理与多步协作 | 系统复杂度更高，调参成本更高 |
| Multi-Killchain | `run_mutil_killchain.py` | 用结构化任务链和 worker 流水线驱动分析 | 结果可审计、便于扩展与复用 | 默认能力更保守，需要持续补充 worker/plugin |


## 5. Baseline：单智能体直接求解

`NYU CTF Baseline` 是整个仓库里最直接的一条线。它的典型流程是：

1. 读取题目元数据与附件。
2. 启动题目容器与智能体容器。
3. 给模型提供工具接口。
4. 让模型通过多轮对话直接分析题目并提交 flag。

它的核心特点是工具权限高、决策自由度高，典型工具包括：

- `run_command`：直接在 Docker 容器中执行 shell 命令。
- `createfile`：在容器中创建脚本或辅助文件。
- `check_flag`：验证候选 flag。
- `decompile_function` / `disassemble_function`：面向二进制题目的 Ghidra 分析工具。

这条线的优势在于：

- 适合复杂题目和开放式探索。
- 对 rev / pwn / crypto 这类需要快速写脚本验证的题型较友好。
- 更接近“让模型自己当选手”。

它的不足在于：

- 分析过程较难被统一抽象。
- 路径依赖模型质量与 prompt 质量。
- 容易出现探索发散或重复试错。


## 6. D-CIPHER / Single Executor：多智能体分工

`D-CIPHER` 使用典型的 Planner-Executor 范式。系统中主要有三个角色：

- `AutoPrompter`：根据题目信息自动生成更贴合题目的提示词。
- `Planner`：负责制定高层计划，决定下一步要做什么。
- `Executor`：负责具体执行命令、读取文件、分析结果并返回摘要。

相应入口：

- `run_dcipher.py`：完整 Planner-Executor 系统。
- `run_single_executor.py`：只保留执行器主导的简化版本。

这一套框架的特点是：

- 更强调计划与执行分离。
- 适合多轮、层级化推理。
- 配置项丰富，可以为不同题型指定不同 prompt 和工具集。

典型默认工具集包括：

- `run_command`
- `delegate`
- `finish_task`
- `disassemble`
- `decompile`
- `create_file`

它更像是“多代理协作求解器”，而不是“结构化安全流水线”。


## 7. Multi-Killchain：结构化安全评估流水线

`NYU Multi-Killchain` 是本项目最偏工程化的一条线。它不再把求解过程完全交给一个自由探索的 agent，而是把能力拆成一组明确的 task、worker 和 plugin。

### 7.1 核心设计思想

核心思路是：  
先把题目视为一个“授权分析目标”，再把分析过程拆成标准化 killchain 步骤，例如：

- 目标归一化
- 文件盘点
- 源码审查
- 运行时探测
- 运算分析
- 主机审计
- Web 元数据收集
- 内容审查
- 漏洞扫描
- flag 验证

这样做的好处是：

- 不依赖模型一次性做出所有决策。
- 每一步都是结构化的，可单独测试、单独扩展。
- 结果以状态机和证据形式沉淀，便于调试、回放和复盘。


### 7.2 核心组件

`Multi-Killchain` 的主流程由以下模块组成：

- `RunConfig`：定义本次运行的目标、授权范围、输出目录、cycle 上限等。
- `GlobalState`：保存运行过程中的资产、发现、证据、任务链、执行记录等共享状态。
- `TaskChain`：维护待执行任务、去重键和状态流转。
- `Orchestrator`：循环执行“规划 -> 选任务 -> 分发给 worker -> 回写状态”。
- `BootstrapPlanner / LLMPlanner`：前者只负责初始种子任务，后者负责 LLM 驱动的后续规划。
- `ExecutionPlane`：统一管理本地命令插件和输出解析器。
- `WorkerAgent`：每种分析能力的统一抽象。


### 7.3 Worker 体系

当前 `Multi-Killchain` 已包含多类 worker：

- `ReconAgent`：根据 scope 建立初始资产。
- `ArtifactTriageAgent`：盘点附件并分类。
- `SourceReviewAgent`：审查源码中的路由、secret 和 flag-like token。
- `BinaryTriageAgent`：分析二进制 strings 与元信息。
- `ArchiveTriageAgent`：分析压缩包及内部成员。
- `SQLiteReviewAgent`：分析数据库文件。
- `PcapReviewAgent`：分析流量包。
- `RepoReviewAgent`：分析嵌入式 git 仓库。
- `HostAuditAgent`：主机端口与服务审计。
- `ServiceBannerAgent`：服务 banner 收集。
- `WebAssessmentAgent`：HTTP 元数据和风险说明。
- `WebContentAgent`：页面内容、链接、表单与关键词审查。
- `WebPathProbeAgent`：路径探测。
- `VulnScanAgent`：漏洞扫描。
- `FlagValidationAgent`：候选 flag 校验。

这套设计最大的特点是：  
每个 worker 只负责一种能力，输入输出都通过结构化 state 来流转。


### 7.4 Plugin 体系

`ExecutionPlane` 背后注册的是一组本地分析插件，典型插件包括：

- `artifact_triage`
- `source_review`
- `binary_triage`
- `archive_triage`
- `sqlite_review`
- `pcap_review`
- `repo_review`
- `host_inventory`
- `tcp_banner_probe`
- `http_metadata`
- `http_content`
- `http_path_probe`
- `vuln_scan`
- `runtime_probe`
- `computation_analysis`







## 9. 一个具体案例：从静态审查到运行时和运算恢复

以 `2021q-rev-checker` 这类题为例，当前 `Multi-Killchain` 的处理链路可以概括为：

1. `artifact_triage` 发现附件中存在 Python 源码。
2. `source_review` 做基础静态审查。
3. `runtime_probe` 执行脚本，回收运行输出中的长二进制串。
4. `computation_analysis` 识别源码中的运算函数与编码逻辑。
5. 运算分析器对输出 bitstring 进行逆推，恢复候选明文。
6. `flag.validate` 自动校验候选 flag。

这个案例说明，项目已经从“只能分类和扫描”进化为“可以对部分本地题型进行动态分析与自动恢复”。


## 10. 运行方式与输出产物

### 10.1 回归测试

```bash
python -m pytest tests/test_mutil_killchain_optimizations.py
```

适用场景：

- 提交前回归
- 修改 worker / plugin / planner 后验证行为

### 10.2 真实题目运行

```bash
python run_mutil_killchain.py --split test --challenge <challenge-name>
```

常用附加参数：

```bash
--api-endpoint <base_url>
--api-key <key>
--model <model_name>
--max-cycles 8
--debug
```

### 10.3 输出目录

默认输出位于：

```text
logs_mutil_killchain/<user>/
```

其中每次运行会生成：

- `<challenge>.json`：总日志
- `state.json`：完整状态快照
- `summary.json`：运行摘要
- `report.md`：Markdown 报告
- `events.log`：orchestrator 事件流
- `evidence.json`：工具证据记录


## 11. 当前项目的优势

当前项目相对完整地覆盖了几类研究问题：

### 11.1 覆盖多种自动化范式

同一仓库内并存：

- 单智能体直接执行
- Planner-Executor 多智能体协作
- 结构化 killchain 工作流

这使得系统天然适合做横向比较和 ablation study。

### 11.2 工程上可扩展

`Multi-Killchain` 的 worker/plugin/state 结构清晰，新能力可以按模块追加，不需要推翻原有系统。

### 11.3 可审计性强

相较于纯对话式智能体，`Multi-Killchain` 的每一步都有任务、状态、证据和日志，更适合研究和复盘。

### 11.4 具备受控执行环境

统一在 Docker 中进行，既便于复现实验，也便于隔离运行环境和题目依赖。


## 12. 当前局限

尽管能力有明显提升，但项目仍然存在边界：

### 12.1 Multi-Killchain 的自由执行能力仍弱于 Baseline

`Baseline` 具备高自由度的 `run_command` 能力，而 `Multi-Killchain` 主要依赖预定义插件。  
这保证了结构化，但也限制了探索空间。

### 12.2 新增能力目前主要覆盖脚本类本地题

`runtime_probe` 和 `computation_analysis` 当前对 Python 以及部分脚本语言最有效。  
对于 ELF、native binary、复杂 VM、非线性约束等题型，仍然需要更强的分析链。

### 12.3 复杂推理仍依赖模型质量

即使引入 LLM planner，任务排序、优先级与工具选择仍会受到模型和 prompt 的影响。





