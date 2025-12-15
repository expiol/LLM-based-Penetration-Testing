"""
统一日志系统
支持多级别日志，同时输出到文件、UI和控制台
"""
import logging
import sys
from typing import Optional
from enum import Enum

from .logger import SingleLogger

# 延迟导入execution_state，避免循环依赖
def _get_execution_state():
    """延迟获取execution_state"""
    try:
        from ..agents.base_agent import execution_state
        return execution_state
    except ImportError:
        return None


class LogLevel(Enum):
    """日志级别枚举"""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


class UnifiedLogger:
    """
    统一日志记录器
    同时支持：
    1. 文件日志（通过SingleLogger）
    2. UI显示（通过execution_state）
    3. 控制台输出（可选）
    """
    
    def __init__(self, name: str, enable_console: bool = False):
        """
        初始化日志记录器
        
        Args:
            name: 日志记录器名称（通常是模块名）
            enable_console: 是否启用控制台输出
        """
        self.name = name
        self.file_logger = SingleLogger.get_logger()
        self.enable_console = enable_console
        self._ui_enabled = True  # 默认启用UI显示
        
    def _get_pentest_context(self):
        """获取渗透测试上下文信息"""
        context = {}
        try:
            # 从thread-local storage获取
            from ..agents.tools_adapter import _context_storage
            if hasattr(_context_storage, 'agent_context'):
                agent_ctx = _context_storage.agent_context
                if agent_ctx:
                    context['session_id'] = agent_ctx.get('session_id')
                    context['agent'] = agent_ctx.get('agent_type')
                    context['target'] = agent_ctx.get('target')
                    context['stage'] = agent_ctx.get('stage')
            
            # 从execution_state获取
            exec_state = _get_execution_state()
            if exec_state:
                state = exec_state.get_state()
                if state:
                    if not context.get('agent') and state.get('agent'):
                        context['agent'] = state.get('agent')
                    if not context.get('tool') and state.get('tool'):
                        context['tool'] = state.get('tool')
        except:
            pass
        return context
    
    def _log(
        self,
        level: int,
        message: str,
        ui_prefix: Optional[str] = None,
        ui_color: Optional[str] = None,
        **extra_context
    ):
        """
        统一的日志记录方法
        
        Args:
            level: 日志级别
            message: 日志消息
            ui_prefix: UI显示的前缀（如emoji）
            ui_color: UI显示的颜色标记（用于UI格式化）
            **extra_context: 额外的上下文信息（session_id, agent, tool, target, stage等）
        """
        # 获取渗透测试上下文
        pentest_context = self._get_pentest_context()
        pentest_context.update(extra_context)
        
        # 构建日志消息（包含上下文信息）
        log_message = f"[{self.name}] {message}"
        
        # 1. 写入文件日志（通过extra参数传递上下文）
        extra = {}
        if pentest_context.get('session_id'):
            extra['session_id'] = pentest_context['session_id']
        if pentest_context.get('agent'):
            extra['agent'] = pentest_context['agent']
        if pentest_context.get('tool'):
            extra['tool'] = pentest_context['tool']
        if pentest_context.get('target'):
            extra['target'] = pentest_context['target']
        if pentest_context.get('stage'):
            extra['stage'] = pentest_context['stage']
        
        if level == logging.DEBUG:
            self.file_logger.debug(log_message, extra=extra)
        elif level == logging.INFO:
            self.file_logger.info(log_message, extra=extra)
        elif level == logging.WARNING:
            self.file_logger.warning(log_message, extra=extra)
        elif level == logging.ERROR:
            self.file_logger.error(log_message, extra=extra)
        elif level == logging.CRITICAL:
            self.file_logger.critical(log_message, extra=extra)
        
        # 2. 显示到UI（通过execution_state）
        if self._ui_enabled:
            try:
                exec_state = _get_execution_state()
                if exec_state:
                    # 构建UI显示消息
                    ui_message = message
                    if ui_prefix:
                        ui_message = f"{ui_prefix} {ui_message}"
                    
                    # 添加到execution_state的输出行
                    exec_state.add_output_line(ui_message)
            except Exception:
                # 如果execution_state不可用，忽略UI输出
                pass
        
        # 3. 控制台输出（如果启用）
        if self.enable_console:
            # 根据级别选择颜色
            if level >= logging.ERROR:
                color_code = "\033[91m"  # 红色
            elif level >= logging.WARNING:
                color_code = "\033[93m"  # 黄色
            elif level >= logging.INFO:
                color_code = "\033[92m"  # 绿色
            else:
                color_code = "\033[96m"  # 青色（DEBUG）
            
            reset_code = "\033[0m"
            level_name = logging.getLevelName(level)
            print(f"{color_code}[{level_name}][{self.name}]{reset_code} {message}", flush=True)
    
    def debug(self, message: str, ui_prefix: Optional[str] = None, **context):
        """DEBUG级别日志"""
        self._log(logging.DEBUG, message, ui_prefix=ui_prefix, **context)
    
    def info(self, message: str, ui_prefix: Optional[str] = None, **context):
        """INFO级别日志"""
        self._log(logging.INFO, message, ui_prefix=ui_prefix, **context)
    
    def warning(self, message: str, ui_prefix: Optional[str] = None, **context):
        """WARNING级别日志"""
        self._log(logging.WARNING, message, ui_prefix="⚠️", **context)
    
    def error(self, message: str, ui_prefix: Optional[str] = None, **context):
        """ERROR级别日志"""
        self._log(logging.ERROR, message, ui_prefix="❌", **context)
    
    def critical(self, message: str, ui_prefix: Optional[str] = None, **context):
        """CRITICAL级别日志"""
        self._log(logging.CRITICAL, message, ui_prefix="🔴", **context)
    
    def success(self, message: str, **context):
        """成功消息（INFO级别，带成功标记）"""
        self._log(logging.INFO, message, ui_prefix="✅", **context)
    
    def set_ui_enabled(self, enabled: bool):
        """设置是否启用UI显示"""
        self._ui_enabled = enabled
    
    def set_console_enabled(self, enabled: bool):
        """设置是否启用控制台输出"""
        self.enable_console = enabled


# 全局日志记录器字典
_loggers: dict[str, UnifiedLogger] = {}


def get_logger(name: str, enable_console: bool = False) -> UnifiedLogger:
    """
    获取或创建日志记录器
    
    Args:
        name: 日志记录器名称（通常是模块名）
        enable_console: 是否启用控制台输出
        
    Returns:
        UnifiedLogger实例
    """
    if name not in _loggers:
        _loggers[name] = UnifiedLogger(name, enable_console=enable_console)
    return _loggers[name]


# 便捷函数：直接使用模块名创建logger
def get_module_logger(module_name: Optional[str] = None, enable_console: bool = False) -> UnifiedLogger:
    """
    根据调用模块自动创建日志记录器
    
    Args:
        module_name: 模块名，如果为None则自动检测
        enable_console: 是否启用控制台输出
        
    Returns:
        UnifiedLogger实例
    """
    if module_name is None:
        import inspect
        frame = inspect.currentframe().f_back
        module_name = frame.f_globals.get('__name__', 'unknown')
    
    # 提取模块名（去掉包前缀）
    if '.' in module_name:
        module_name = module_name.split('.')[-1]
    
    return get_logger(module_name, enable_console=enable_console)

