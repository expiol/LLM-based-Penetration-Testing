import logging
import json
import os
from pathlib import Path
from concurrent_log_handler import ConcurrentRotatingFileHandler
from datetime import datetime, timedelta

# 日志配置（从环境变量或使用默认值）
BASE_DIR = Path(__file__).resolve().parent.parent.parent
SERVICE_NAME = os.environ.get("SERVICE_NAME", "llm-pen-test")
LOGGING_PATH = os.environ.get("LOGGING_PATH", str(BASE_DIR / "logs"))
LOGGING_NAME = os.environ.get("LOGGING_NAME", "LLM-PENTEST")
LOGGING_MAXBYTES = int(os.environ.get("LOGGING_MAXBYTES", 20 * 1024 * 1024))  # 20MB
LOGGING_BACKUP_COUNT = int(os.environ.get("LOGGING_BACKUP_COUNT", 10))


class JsonFormatter(logging.Formatter):
    """优化的JSON日志格式化器 - 针对渗透测试项目"""

    def formatTime(self, record, datefmt=None):
        # 将时间戳转换为UTC+8时区的datetime对象
        from datetime import timezone
        utc_dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        # 转换为UTC+8时区
        local_tz = timezone(timedelta(hours=8))
        local_dt = utc_dt.astimezone(local_tz)
        # 格式化日期和时间（包括毫秒）
        # 注意：%f 是微秒，我们需要切片来获取毫秒
        time_str = local_dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + '+0800'
        return time_str

    def _get_pentest_context(self, record):
        """从thread-local storage或execution_state获取渗透测试上下文"""
        context = {}
        
        # 首先从record的extra字段获取（优先级最高，如果直接传递）
        if hasattr(record, 'session_id') and record.session_id:
            context['session_id'] = record.session_id
        if hasattr(record, 'agent') and record.agent:
            context['agent'] = record.agent
        if hasattr(record, 'tool') and record.tool:
            context['tool'] = record.tool
        if hasattr(record, 'target') and record.target:
            context['target'] = record.target
        if hasattr(record, 'stage') and record.stage:
            context['stage'] = record.stage
        
        # 如果extra中没有，尝试从thread-local storage获取
        if not context:
            try:
                from src.agents.tools_adapter import _context_storage
                
                # 从agent_context获取
                if hasattr(_context_storage, 'agent_context'):
                    agent_ctx = _context_storage.agent_context
                    if agent_ctx:
                        if not context.get('session_id'):
                            context['session_id'] = agent_ctx.get('session_id')
                        if not context.get('agent'):
                            context['agent'] = agent_ctx.get('agent_type')
                        if not context.get('target'):
                            context['target'] = agent_ctx.get('target')
                        if not context.get('stage'):
                            context['stage'] = agent_ctx.get('stage')
                
                # 从execution_state获取当前执行信息
                try:
                    from src.agents.base_agent import execution_state
                    exec_state = execution_state.get_state()
                    if exec_state:
                        if not context.get('agent') and exec_state.get('agent'):
                            context['agent'] = exec_state.get('agent')
                        if not context.get('tool') and exec_state.get('tool'):
                            context['tool'] = exec_state.get('tool')
                except:
                    pass
                    
            except ImportError:
                # 如果导入失败，忽略
                pass
        
        return context

    def format(self, record):
        """格式化日志记录为JSON，包含渗透测试相关字段"""
        log_record = {
            "timestamp": self.formatTime(record, datefmt='%Y-%m-%dT%H:%M:%S%z'),
            "level": record.levelname,
            "module": record.module,
            "file": f"{record.filename}:{record.lineno}",
            "msg": record.getMessage(),
        }
        
        # 获取渗透测试上下文信息
        pentest_context = self._get_pentest_context(record)
        
        # 只在有值时才添加渗透测试相关字段
        if pentest_context.get('session_id'):
            log_record["session_id"] = pentest_context['session_id']
        if pentest_context.get('agent'):
            log_record["agent"] = pentest_context['agent']
        if pentest_context.get('tool'):
            log_record["tool"] = pentest_context['tool']
        if pentest_context.get('target'):
            log_record["target"] = pentest_context['target']
        if pentest_context.get('stage'):
            log_record["stage"] = pentest_context['stage']
        
        return json.dumps(log_record, ensure_ascii=False)


class SingleLogger(object):
    __instance = None

    def __init__(self):
        pass

    def __new__(cls, *args, **kwd):
        if SingleLogger.__instance is None:
            SingleLogger.__instance = object.__new__(cls, *args, **kwd)
            SingleLogger.__instance._setup_logger()
        return SingleLogger.__instance

    def _setup_logger(self):
        self.__logger = logging.getLogger(LOGGING_NAME)

        self.__logger.setLevel(logging.DEBUG)
        if not os.path.exists(LOGGING_PATH):
            os.makedirs(LOGGING_PATH)
        log_file = os.path.join(LOGGING_PATH, SERVICE_NAME + ".log")

        trfh = ConcurrentRotatingFileHandler(log_file, 'a', LOGGING_MAXBYTES, LOGGING_BACKUP_COUNT,
                                             'UTF-8')
        trfh.setFormatter(JsonFormatter())  # 使用我们定义的JsonFormatter

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(JsonFormatter())  # 控制台输出也使用JSON格式

        self.__logger.addHandler(trfh)
        self.__logger.addHandler(stream_handler)

    @staticmethod
    def get_logger():
        if not SingleLogger.__instance:
            SingleLogger()  # 确保实例被创建
        return SingleLogger.__instance.__logger

    @staticmethod
    def set_log_level(level):
        if SingleLogger.__instance:
            # debug/info/warn/error
            if level == "DEBUG":
                SingleLogger.__instance.__logger.setLevel(logging.DEBUG)
            elif level == "INFO":
                SingleLogger.__instance.__logger.setLevel(logging.INFO)
            elif level == "WARN":
                SingleLogger.__instance.__logger.setLevel(logging.WARNING)
            elif level == "ERROR":
                SingleLogger.__instance.__logger.setLevel(logging.ERROR)
            else:
                SingleLogger.__instance.__logger.setLevel(logging.DEBUG)

    def info(self, message):
        SingleLogger.get_logger().info(message)

    def error(self, message):
        SingleLogger.get_logger().error(message)

    def warning(self, message):
        SingleLogger.get_logger().warning(message)

    def debug(self, message):
        SingleLogger.get_logger().debug(message)