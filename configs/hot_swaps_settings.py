# utils/hot_swap_watcher.py
"""
热更监控器（periodic hot-swap）
- 读取 configs.hot_swaps.yaml 并将可更改字段映射到 configs.settings 中对应的全局变量
- 任何敏感字段（如 API_KEY、SECRET）**不应**放在 hot_swaps.yaml；如果发现会忽略并记录警告
"""

import yaml
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from importlib import import_module
from pathlib import Path

logger = logging.getLogger(__name__)
settings = import_module("configs.settings")  # 使用相对路径 import

# 允许热更并映射到 settings 模块中的字段（映射表：yaml-path -> global var name）
HOTSWAP_PATH_TO_VAR = {
    "logger.level": "LOGGER_LEVEL",
    "llm.request.timeout": "HTTP_SERVE_TIMEOUT",
    "llm.request.user_prompt_max": "USER_PROMPT_STR_MAX_LEN",
    "llm.request.analyze_72b_token_max": "ANALYZE_72B_TOKEN_MAX",
    "llm.request.analyze_7b_token_max": "ANALYZE_7B_TOKEN_MAX",
    "llm.request.generate_token_max": "GENERATE_MAX_TOKENS",
    "pentest.active_exploration": "ACTIVE_EXPLORATION",
    "pentest.safe_mode": "SAFE_MODE",
    "pentest.automated_payload_generation": "AUTOMATED_PAYLOAD_GENERATION",
    "pentest.vuln_exploit_simulation": "VULN_EXPLOIT_SIMULATION",
    "pentest.trust_remote_scanner_results": "TRUST_REMOTE_SCANNER_RESULTS",
    "pentest.noise_reduction": "NOISE_REDUCTION",
    "pentest.reasoning_interpretation": "REASONING_INTERPRETATION",
    "pentest.reasoning_interpretation_model": "REASONING_INTERPRETATION_MODEL",
    # add more mappings as you expose new hot-swappable keys
}


def _get_nested_value(data, keys, separator="."):
    if isinstance(keys, str):
        keys = keys.split(separator)
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None
    return current


def _update_setting_if_changed(conf_dict, conf_path, var_name):
    new_value = _get_nested_value(conf_dict, conf_path)
    if new_value is None:
        return False
    # only update if exists on settings
    if not hasattr(settings, var_name):
        logger.warning("settings has no attribute %s, skipping hot-swap for %s", var_name, conf_path)
        return False
    current_value = getattr(settings, var_name)
    if current_value != new_value:
        setattr(settings, var_name, new_value)
        logger.info("hot-swap: updated %s (settings.%s) from %s -> %s", conf_path, var_name, current_value, new_value)
        # special handling: if we're changing log level, update root logger
        if var_name == "LOGGER_LEVEL":
            lvl = getattr(logging, new_value.upper(), None)
            if isinstance(lvl, int):
                logging.getLogger().setLevel(lvl)
        return True
    return False


def check_hot_swaps():
    """
    读取 hot_swaps.yaml 并将可热更配置应用到 settings 模块
    """
    cfg_file = Path(settings.HOT_SWAP_CONFIG_FILE)
    try:
        if not cfg_file.exists():
            logger.warning("hot-swap config file missing: %s", cfg_file)
            return
        with cfg_file.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            # try to read defaults first (backward compatibility)
            defaults = data.get("defaults", {})
            # merge defaults into top-level for lookups
            merged = {}
            merged.update(defaults)
            # include any explicit top-level keys as well
            merged.update(data)

            # iterate over mapping and update
            for conf_path, var_name in HOTSWAP_PATH_TO_VAR.items():
                _update_setting_if_changed(merged, conf_path, var_name)

    except Exception as e:
        logger.exception("failed reading hot swap config %s: %s", cfg_file, e)


def start_hot_swap_watcher(poll_interval_seconds: int = None):
    """
    启动后台定时任务，定期检查并应用 hot_swaps.yaml 的更改
    - poll_interval_seconds 默认读取 settings.HOT_SWAP_POLL_INTERVAL
    """
    interval = poll_interval_seconds or getattr(settings, "HOT_SWAP_POLL_INTERVAL", 10)
    scheduler = BackgroundScheduler()
    scheduler.add_job(check_hot_swaps, "interval", seconds=interval, id="hot_swap_check", replace_existing=True)
    scheduler.start()
    logger.info("started hot-swap watcher, polling every %s seconds", interval)
    return scheduler


# 如果此模块作为脚本执行，则启动 watcher（便于本地测试）
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    check_hot_swaps()
    start_hot_swap_watcher()
    # block main thread when run directly
    import time
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        logger.info("exiting hot_swap_watcher")
