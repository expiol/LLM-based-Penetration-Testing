# NYU CTF Automation

这个仓库包含 3 条主要能力线：

- `D-CIPHER`
- `NYU CTF Baseline`
- `NYU Multi-Killchain`


## 环境准备

1. 克隆仓库并进入目录。
2. 准备 Python 3.10+ 环境
3. 按需执行安装脚本：

```bash
./setup_mutil_killchain.sh
./setup_baseline.sh
./setup_dcipher.sh
```

4. 如需真实 NYUCTF 题目运行，下载数据集：

```bash
python -m nyuctf.download
```




### 2. 回归测试

运行当前仓库维护的针对性单测与回归测试。

```bash
python -m pytest tests/test_mutil_killchain_optimizations.py
```

当前覆盖重点：

- web 服务识别逻辑
- artifact / archive 分类
- source review 的归档成员读取
- `max_cycles` 用尽时的状态判定

适用场景：

- 提交前回归
- 改分类规则、planner、orchestrator 后验证行为

### 3. 真实题目运行

连接 NYUCTF 数据集和 Docker 环境，实际跑单题。

```bash
python run_mutil_killchain.py \
  --split test \
  --challenge <challenge-name>
```

常用附加参数：

```bash
--disable-llm
--disable-llm-planner
--api-endpoint <base_url>
--api-key <key>
--model <model_name>
--max-cycles 8
--debug
```

适用场景：

- 验证真实 challenge 上的端到端行为
- 检查 Docker 启动、challenge 文件挂载、日志产物是否正常

## Multi-Killchain 主要入口

- `run_mutil_killchain.py`: 单题真实运行入口
- `run_mutil_killchain_test.py`: 本地自检包装脚本
- `nyuctf_mutil_killchain/cli.py`: 包级 CLI，支持 `run` / `selftest` / `lab`

## Multi-Killchain 输出

真实单题运行默认会在 `logs_mutil_killchain/<user>/` 下写出：

- 每题一个 `<challenge>.json` 总日志
- `artifacts/<challenge>/<run-id>/state.json`
- `artifacts/<challenge>/<run-id>/summary.json`
- `artifacts/<challenge>/<run-id>/report.md`
- `artifacts/<challenge>/<run-id>/events.log`
- `artifacts/<challenge>/<run-id>/evidence.json`

## 其他入口

如果你需要跑仓库里另外两条能力线，入口仍然保留：

```bash
python run_dcipher.py --split <test|development> --challenge <challenge-name>
python run_single_executor.py --split <test|development> --challenge <challenge-name>
python run_baseline.py -c configs/baseline/base_config.yaml --split <test|development> --challenge <challenge-name>
```
