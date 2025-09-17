# -*- coding: utf-8 -*-
import os
import uuid
from pathlib import Path

# 基本服务信息
APP_ENV = os.environ.get("APP_ENV", "development")  # development | staging | production
SERVICE_NAME = os.environ.get("SERVICE_NAME", "llm-pen-test")
SERVICE_UUID = os.environ.get("SERVICE_UUID", str(uuid.uuid4()))
APP_VERSION = os.environ.get("APP_VERSION", "v0.1.0")

# 并发/线程配置
MAX_THREAD = int(os.environ.get("MAX_THREAD", "4"))

# 日志配置
BASE_DIR = Path(__file__).resolve().parent.parent
LOGGING_PATH = os.environ.get("LOGGING_PATH", str(BASE_DIR / "logs"))
LOGGING_NAME = os.environ.get("LOGGING_NAME", "LLM-PENTEST")
LOGGING_MAXBYTES = int(os.environ.get("LOGGING_MAXBYTES", 20 * 1024 * 1024))  # 20MB
LOGGING_BACKUP_COUNT = int(os.environ.get("LOGGING_BACKUP_COUNT", 10))
LOGGING_DAYS_TO_KEEP = int(os.environ.get("LOGGING_DAYS_TO_KEEP", 30))

# 模型 / 服务相关（可通过环境变量覆盖）
MODEL_SERVE_PROTOCOL = os.environ.get("MODEL_SERVE_PROTOCOL", "http")
MODEL_SERVE_IP = os.environ.get("MODEL_SERVE_IP", "127.0.0.1")
MODEL_SERVE_PORT = int(os.environ.get("MODEL_SERVE_PORT", "8000"))
MODEL_API_KEY = os.environ.get("MODEL_API_KEY", "")  # 强烈建议通过安全 Secret 注入

# LLM endpoints（路径）
LORA_GENERATE_URI = os.environ.get("LORA_GENERATE_URI", "/v1/chat/lora")
CHAT_COMPLETIONS_URL = os.environ.get("CHAT_COMPLETIONS_URL", "/v1/chat/completions")

# 默认提示/模板或占位文案
DEFAULT_JUDGE = "No conclusive judgement."
DEFAULT_ANALYZE = "No obvious malicious behavior detected from the provided artifact."

# 文件存储路径（事件 / 输出）
EVENT_FILE_PATH = os.environ.get("EVENT_FILE_PATH", str(BASE_DIR / "pentest_events" / "files"))
EVENT_SQL_PATH = os.environ.get("EVENT_SQL_PATH", str(BASE_DIR / "pentest_events" / "db"))

# 安全 & 风险偏好（这些在 hot_swaps.yaml 中可热更）
# 下面这些为程序启动时的默认值，hot_swap_settings 会在运行时覆盖它们
HTTP_SERVE_TIMEOUT = 600                 # 模型调用超时时间（秒）
USER_PROMPT_STR_MAX_LEN = 3200           # 用户提示最大长度（字符）
ANALYZE_REASONING_TOKEN_MAX = 6000             # 思考模型输入 token 最大
ANALYZE_CHAT_TOKEN_MAX = 4000              # 小模型输入 token 最大
GENERATE_MAX_TOKENS = 2048               # 生成 token 最大值
LOGGER_LEVEL = os.environ.get("LOGGER_LEVEL", "INFO")

# 渗透测试专用开关（默认值）
ACTIVE_EXPLORATION = False               # 是否允许主动利用（exploit）策略（生产环境慎开）
SAFE_MODE = True                         # 安全模式：禁止破坏性操作（强烈建议默认 True）
AUTOMATED_PAYLOAD_GENERATION = True      # 是否允许 LLM 自动生成 payload（受 SAFE_MODE 控制）
VULN_EXPLOIT_SIMULATION = False          # 是否执行真实 exploit（应始终受控）

# 结果信任/过滤
TRUST_REMOTE_SCANNER_RESULTS = True      # 是否采纳外部扫描器的结果
NOISE_REDUCTION = True                   # 告警/结果降噪策略开关

# 其它偏好
REASONING_INTERPRETATION = True
REASONING_INTERPRETATION_MODEL = os.environ.get("REASONING_INTERPRETATION_MODEL", "HengNao-r1")

# 监控/调度
HOT_SWAP_CONFIG_FILE = os.environ.get("HOT_SWAP_CONFIG_FILE", str(BASE_DIR / "configs" / "hot_swaps.yaml"))
HOT_SWAP_POLL_INTERVAL = int(os.environ.get("HOT_SWAP_POLL_INTERVAL", 10))  # 秒

# 安全建议（在运行时或部署文档中引用）
# - 所有网络服务 IP/KEY/SECRET 均应通过 CI/CD 或 secret manager 注入
# - 禁止把真实的远控/破坏性 API key 保存在代码库中

# 导出本模块可被其它模块 import 的名字
__all__ = [
    "APP_ENV", "SERVICE_NAME", "SERVICE_UUID", "APP_VERSION", "MAX_THREAD",
    "LOGGING_PATH", "LOGGING_NAME", "LOGGING_MAXBYTES", "LOGGING_BACKUP_COUNT",
    "LOGGING_DAYS_TO_KEEP", "MODEL_SERVE_PROTOCOL", "MODEL_SERVE_IP", "MODEL_SERVE_PORT",
    "MODEL_API_KEY", "LORA_GENERATE_URI", "CHAT_COMPLETIONS_URL",
    "DEFAULT_JUDGE", "DEFAULT_ANALYZE", "EVENT_FILE_PATH", "EVENT_SQL_PATH",
    "HTTP_SERVE_TIMEOUT", "USER_PROMPT_STR_MAX_LEN", "ANALYZE_REASONING_TOKEN_MAX",
    "ANALYZE_CHAT_TOKEN_MAX", "GENERATE_MAX_TOKENS", "LOGGER_LEVEL",
    "ACTIVE_EXPLORATION", "SAFE_MODE", "AUTOMATED_PAYLOAD_GENERATION",
    "VULN_EXPLOIT_SIMULATION", "TRUST_REMOTE_SCANNER_RESULTS", "NOISE_REDUCTION",
    "REASONING_INTERPRETATION", "REASONING_INTERPRETATION_MODEL",
    "HOT_SWAP_CONFIG_FILE", "HOT_SWAP_POLL_INTERVAL"
]
