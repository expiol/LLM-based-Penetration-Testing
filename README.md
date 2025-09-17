# 🔒 LLM-based Penetration Testing Platform (科研版)

本项目是一个基于 **大语言模型（LLM）** 的渗透测试平台，参考 **Cyber Kill Chain（网络杀伤链）** 全流程，设计用于 **模拟/辅助渗透测试**。

* * *

## ✨ 项目目标

* **研究**：探索 LLM 在渗透测试（PenTest）中可用的推理、规划与工具调用能力。
    
* **复现**：基于 Cyber Kill Chain 的阶段化工作流，复现真实攻击路径。
    
* **评测**：设计指标（效率、准确率、误报率、安全性）评估不同模型/提示词策略。
    

* * *

## 📚 原理与流程设计

### 1. 核心思路

* 使用 **LLM Agents** 扮演各个攻击阶段的“顾问/决策器”。
    
* 每个阶段 Agent 读取提示词（Prompts）、上下文（Context）、工具结果（Tools），输出 **结构化 JSON**（动作计划 + 理由 + 证据）。

* Orchestrator 根据 **Kill Chain 状态机** 顺序执行阶段，形成完整渗透链条。
    
* 工具调用通过适配层封装（Nmap、ZAP、PoC Runner、C2 Simulator），在现实运行环境中运行攻击代码（添加安全模式辅助）。
    

### 2. Cyber Kill Chain 流程

1. **Reconnaissance（侦察）**  
    信息收集：端口扫描、服务指纹识别、漏洞数据库匹配。
    
2. **Weaponization（武器化）**  
    构造攻击载荷（payload），结合漏洞信息生成攻击向量。
    
3. **Delivery（投递）**  
    选择传递方式（HTTP 请求、文件上传、社工邮件——仅仿真）。
    
4. **Exploitation（利用）**  
    模拟漏洞利用过程（SQL 注入、XSS、RCE 等）。
    
5. **Installation（安装）**  
    模拟植入后门/持久化（仅 Safe Mode 下生成理论步骤，不会执行）。
    
6. **Command & Control（C2）**  
    与“被攻击服务器”通信。
    
7. **Actions on Objectives（目标行为）**  
    敏感数据访问、横向移动、权限维持。
    


### 3. 安全机制

* **Safe Mode**：默认启用，禁止现实世界 exploit，只做仿真/离线推理。
    
* **工具沙箱化**：Nmap/ZAP 调用限制在容器/隔离环境。
    
* **日志与证据**：全流程日志落盘，可追溯、可复现。
    

* * *

## 📂 项目结构

```
project/
├─ starter.py                 # 启动入口
├─ configs/
│  ├─ settings.py             # 基本配置（环境变量优先）
│  └─ hot_swaps.yaml          # 可热更配置（Safe Mode、LLM 参数）
├─ utils/
│  ├─ hot_swap_watcher.py     # 配置热更监控
│  ├─ logger.py               # 日志统一封装
│  └─ validators.py           # 范围/输入校验
├─ src/
│  ├─ orchestrator/
│  │  ├─ killchain_orchestrator.py  # Orchestrator 主逻辑
│  │  └─ states.py            # 阶段枚举
│  ├─ service/                # FastAPI API 服务
│  │  ├─ scan_api.py          # Recon/Scan API
│  │  ├─ exploit_api.py       # Exploit API
│  │  ├─ payload_api.py       # Payload 生成
│  │  ├─ report_api.py        # 报告生成
│  │  └─ model_manager.py     # LLM 初始化与调用
│  ├─ tools/                  # 工具适配层
│  │  ├─ nmap_adapter.py
│  │  ├─ zap_adapter.py
│  │  ├─ poc_runner.py
│  │  └─ c2_simulator.py
│  ├─ agents/                 # LLM Agents（每个阶段）
│  │  ├─ recon_agent.py
│  │  ├─ weaponize_agent.py
│  │  ├─ delivery_agent.py
│  │  ├─ exploit_agent.py
│  │  ├─ install_agent.py
│  │  ├─ c2_agent.py
│  │  └─ objectives_agent.py
│  ├─ schemas/                # Pydantic 数据结构
│  └─ prompts/                # 提示词模板
├─ pentest_events/            # 渗透事件记录
├─ logs/                      # 日志输出
└─ README.md
```

* * *

## ⚙️ 安装与运行

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

（依赖：`fastapi`、`uvicorn`、`pydantic`、`pyyaml`、`apscheduler`、`httpx` 等）

### 2. 启动服务

```bash
python starter.py --model_name PenTest-LLM --service_port 8080
```



* * *

## 🔑 热更配置

`configs/hot_swaps.yaml` 中可实时修改：

* `pentest.safe_mode`：安全模式开关（默认 true）
    
* `pentest.active_exploration`：是否允许真实 exploit（科研时建议 false）
    
* `llm.request.*`：超时、最大 token、prompt 长度
    

后台 `utils/hot_swap_watcher` 每隔 10s 重新加载。

* * *

## 📊 评测指标

科研场景下可使用以下指标评估不同 LLM 或提示策略：

* **Plan→Action Alignment**：计划与执行是否一致。
    
* **Tool Use Efficiency**：工具调用次数/覆盖率/时间。
    
* **False Positive Rate**：误报比例。
    
* **Safety Violations**：越权/危险操作次数（应为 0）。
    
* **Chain Completion Rate**：能否走完整个 Kill Chain。
    

* * *

## ⚠️ 安全注意事项

* **禁止对非授权目标运行**。
    
* **Safe Mode 开启**（默认 true），科研时如需关闭请在隔离环境，并严格评估风险。
    
* **谨慎使用真实恶意代码**：所有 exploit/payload 在 Safe Mode 下均为模拟。
    
* **日志全量记录**：每一步的计划、命令、结果都会落盘，便于审计与论文复现。
    

* * *

## 🧩 后续扩展

* **多模型对比**：支持 OpenAI、LLaMA、国产大模型等。
    
* **自动报告导出**：PDF/Markdown 渗透测试报告。
    
* **C2 对话**：研究 LLM 在后渗透通信阶段的行为。

    
    

* * *