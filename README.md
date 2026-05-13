# LLM-based Penetration Testing（结构化 Killchain）

面向 CTF / 授权渗透测试场景的 **LLM 编排 + 工具执行** 流水线：在 Docker 内运行题目环境，在宿主机通过 OpenAI 兼容网关调用大模型，按任务链调度 recon、solver、web 等 worker。

## 运行环境：Conda `autopentest`

日常开发与运行请在 **名为 `autopentest` 的 Conda 环境** 中进行（与入口命令 `autopentest` 同名，便于记忆）。

```bash
conda create -n autopentest python=3.11 -y
conda activate autopentest
cd /path/to/LLM-based-Penetration-Testing
pip install -e .
```

说明：

- 要求 **Python ≥ 3.10**；若使用 RAG / 向量相关能力，建议 **3.11** 并预先装好 PyTorch 等（见 `requirements.txt` 与依赖报错按需补全）。
- 安装完成后可使用控制台命令 **`autopentest`**（定义在 `pyproject.toml` 的 `[project.scripts]`），等价于 `python -m killchain_docker`。

## 一次性：Docker 与网络

题目容器默认镜像 **`ctfenv:latest`**，网络 **`ctfnet`**。在项目根目录执行：

```bash
./setup.sh
```

该脚本会：创建 `ctfnet`（若不存在）、构建根目录 `Dockerfile` 并打标签 `ctfenv:latest`、在当前环境中执行 `pip install -e .`。

Apple Silicon 上构建/运行需与 `Dockerfile` 一致使用 **`linux/amd64`**（脚本已带 `--platform linux/amd64`）。

## LLM 网关配置

网关从仓库根目录下的 **`configs/llm_gateway.json`** 读取（OpenAI 兼容 `base_url` / `api_key` / `default_model` 等）。请勿将含真实密钥的文件提交到公开仓库；可用本地覆盖或环境管理密钥。

## 运行题目

### 方式一：根目录 `run.py`（适合改顶部常量快速试跑）

```bash
conda activate autopentest
python run.py --help
# 无参数时使用脚本内默认常量；也可传 CLI 覆盖
python run.py --challenge <name> --split development
python run.py --run-all --split development
```

默认日志目录为 **`logs/<当前系统用户名>/`**（可通过 `--logdir` 或脚本内 `LOGDIR` 修改）。

### 方式二：`autopentest` CLI（子命令）

```bash
conda activate autopentest
autopentest --help
autopentest run --help
autopentest selftest --help   # 默认产物目录 selftest_output/
```

## 仓库结构（简要）

| 路径 | 说明 |
|------|------|
| `killchain_docker/` | 核心 Python 包（包名 `killchain_docker`：orchestrator、agents、tools、LLM 网关等） |
| `run.py` | 批量/单题运行入口脚本 |
| `setup.sh` | Docker 网络 + 镜像构建 + 可编辑安装 |
| `Dockerfile` / `docker_entrypoint.sh` | CTF 解题侧容器 |
| `configs/llm_gateway.json` | LLM 网关 JSON |

## 测试

```bash
conda activate autopentest
pip install -e .   # 确保依赖齐全
pytest tests/ -q
```

## 许可与来源

见仓库内 `LICENSE`。上游数据集与 NYUCTF 相关约定以数据集与课程文档为准。
