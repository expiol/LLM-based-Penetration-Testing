"""
线程本地存储模块
用于在请求处理过程中存储和获取上下文信息
"""
import threading
from typing import Any, Dict, Optional

# 线程本地存储
_thread_local = threading.local()


def set_data(key: str, value: Any) -> None:
    """设置线程本地数据"""
    if not hasattr(_thread_local, 'data'):
        _thread_local.data = {}
    _thread_local.data[key] = value


def get_data(key: str, default: Any = None) -> Any:
    """获取线程本地数据"""
    if not hasattr(_thread_local, 'data'):
        return default
    return _thread_local.data.get(key, default)


def clear_data() -> None:
    """清除线程本地数据"""
    if hasattr(_thread_local, 'data'):
        _thread_local.data.clear()


def get_all_data() -> Dict[str, Any]:
    """获取所有线程本地数据"""
    if not hasattr(_thread_local, 'data'):
        return {}
    return _thread_local.data.copy()
