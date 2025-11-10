import logging
import json
import os
from pathlib import Path
from concurrent_log_handler import ConcurrentRotatingFileHandler
from datetime import datetime, timedelta

from src.utils.thread_local_storage import get_data

# 日志配置（从环境变量或使用默认值）
BASE_DIR = Path(__file__).resolve().parent.parent.parent
SERVICE_NAME = os.environ.get("SERVICE_NAME", "llm-pen-test")
LOGGING_PATH = os.environ.get("LOGGING_PATH", str(BASE_DIR / "logs"))
LOGGING_NAME = os.environ.get("LOGGING_NAME", "LLM-PENTEST")
LOGGING_MAXBYTES = int(os.environ.get("LOGGING_MAXBYTES", 20 * 1024 * 1024))  # 20MB
LOGGING_BACKUP_COUNT = int(os.environ.get("LOGGING_BACKUP_COUNT", 10))


class HeaderParamMapping:
    """HTTP Header 参数映射常量"""
    
    # 会话ID
    SID = "X-Session-ID"
    
    # 用户ID
    UID = "X-User-ID"
    
    # 请求顺序号
    ORDER = "X-Request-Order"
    
    # 扩展信息
    EXT = "X-Ext-Info"
    
    # 组织信息
    ORG = "X-Org-ID"
    
    # 请求ID
    REQUEST_ID = "X-Request-ID"
    
    # 追踪ID
    TRACE_ID = "X-Trace-ID"
    
    # 模型名称
    MODEL_NAME = "X-Model-Name"
    
    # 安全模式
    SAFE_MODE = "X-Safe-Mode"


class JsonFormatter(logging.Formatter):

    def formatTime(self, record, datefmt=None):
        # 将UTC时间戳转换为datetime对象（UTC）
        utc_dt = datetime.utcfromtimestamp(record.created)
        # 将UTC时间转换为UTC+8时区的时间
        local_dt = utc_dt + timedelta(hours=8)
        # 格式化日期和时间（包括毫秒）
        # 注意：%f 是微秒，我们需要切片来获取毫秒
        time_str = local_dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + '+0800'
        return time_str

    def handle_request_headers(self, request_headers, header_str):
        if request_headers is not None and request_headers.headers is not None:
            if header_str == HeaderParamMapping.SID:
                return request_headers.headers.get(HeaderParamMapping.SID)
            if header_str == HeaderParamMapping.UID:
                return request_headers.headers.get(HeaderParamMapping.UID)
            if header_str == HeaderParamMapping.ORDER:
                return request_headers.headers.get(HeaderParamMapping.ORDER)
            if header_str == HeaderParamMapping.EXT:
                return request_headers.headers.get(HeaderParamMapping.EXT)
            if header_str == HeaderParamMapping.ORG:
                return request_headers.headers.get(HeaderParamMapping.ORG)
        return get_data(header_str)

    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, datefmt='%Y-%m-%dT%H:%M:%S%z'),
            "application": SERVICE_NAME,
            "category": record.__dict__.get('category', None),
            "module": record.module,
            "level": record.levelname,
            "file": record.filename + ":" + str(record.lineno),
            "sid": self.handle_request_headers(record.__dict__.get('request_headers', None), HeaderParamMapping.SID),
            "uid": self.handle_request_headers(record.__dict__.get('request_headers', None), HeaderParamMapping.UID),
            "order": self.handle_request_headers(record.__dict__.get('request_headers', None), HeaderParamMapping.ORDER),
            "ext": self.handle_request_headers(record.__dict__.get('request_headers', None), HeaderParamMapping.EXT),
            "x-org": self.handle_request_headers(record.__dict__.get('request_headers', None), HeaderParamMapping.ORG),
            "msg": record.getMessage(),
            "url": record.__dict__.get('url', None),
            "toolName": record.__dict__.get('toolName', None),
            "direction": record.__dict__.get('direction', None),
        }
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