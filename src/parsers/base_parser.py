"""
解析器基类
定义所有解析器的通用接口和数据结构
"""
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime
from enum import Enum
from ..utils.i18n import t


class ParseResultType(Enum):
    """解析结果类型"""
    SERVICE = "service"
    CREDENTIAL = "credential"
    HOST = "host"
    VULNERABILITY = "vulnerability"
    PORT = "port"
    DOMAIN = "domain"
    HASH = "hash"
    FILE = "file"
    CERTIFICATE = "certificate"
    SESSION = "session"
    UNKNOWN = "unknown"


@dataclass
class ParseResult:
    """解析结果数据类"""
    result_type: ParseResultType
    data: Dict[str, Any]
    source: str  # 解析来源（工具名称）
    confidence: float = 1.0  # 置信度 0-1
    timestamp: datetime = field(default_factory=datetime.now)
    raw_text: Optional[str] = None  # 原始文本
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "result_type": self.result_type.value,
            "data": self.data,
            "source": self.source,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "raw_text": self.raw_text,
            "metadata": self.metadata,
        }


class BaseParser(ABC):
    """
    解析器基类
    所有具体解析器都需要继承此类
    """
    
    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"parser.{name}")
        self._patterns: Dict[str, re.Pattern] = {}
    
    @abstractmethod
    def can_parse(self, text: str) -> bool:
        """
        检查是否可以解析给定的文本
        
        Args:
            text: 要检查的文本
            
        Returns:
            bool: 是否可以解析
        """
        pass
    
    @abstractmethod
    def parse(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[ParseResult]:
        """
        解析文本并返回结果列表
        
        Args:
            text: 要解析的文本
            context: 解析上下文（可选）
            
        Returns:
            List[ParseResult]: 解析结果列表
        """
        pass
    
    def _compile_pattern(self, name: str, pattern: str, flags: int = 0) -> re.Pattern:
        """
        编译并缓存正则表达式模式
        
        Args:
            name: 模式名称
            pattern: 正则表达式
            flags: 正则表达式标志
            
        Returns:
            re.Pattern: 编译后的模式
        """
        if name not in self._patterns:
            self._patterns[name] = re.compile(pattern, flags)
        return self._patterns[name]
    
    def _safe_extract(self, match: re.Match, group: int = 0, default: str = "") -> str:
        """
        安全提取正则匹配组
        
        Args:
            match: 正则匹配对象
            group: 组号
            default: 默认值
            
        Returns:
            str: 提取的值或默认值
        """
        try:
            result = match.group(group)
            return result if result else default
        except (IndexError, AttributeError):
            return default
    
    def _clean_text(self, text: str) -> str:
        """
        清理文本（去除多余空白等）
        
        Args:
            text: 原始文本
            
        Returns:
            str: 清理后的文本
        """
        # 去除ANSI转义序列
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        text = ansi_escape.sub('', text)
        
        # 去除多余空白行
        text = re.sub(r'\n\s*\n', '\n\n', text)
        
        return text.strip()


class ParserRegistry:
    """解析器注册表"""
    
    _instance = None
    _parsers: Dict[str, BaseParser] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._parsers = {}
        return cls._instance
    
    def register(self, parser: BaseParser) -> None:
        """注册解析器"""
        self._parsers[parser.name] = parser
    
    def unregister(self, name: str) -> None:
        """注销解析器"""
        if name in self._parsers:
            del self._parsers[name]
    
    def get_parser(self, name: str) -> Optional[BaseParser]:
        """获取指定解析器"""
        return self._parsers.get(name)
    
    def get_all_parsers(self) -> List[BaseParser]:
        """获取所有解析器"""
        return list(self._parsers.values())
    
    def find_parser(self, text: str) -> Optional[BaseParser]:
        """
        查找能够解析给定文本的解析器
        
        Args:
            text: 要解析的文本
            
        Returns:
            Optional[BaseParser]: 找到的解析器，如果没有则返回None
        """
        for parser in self._parsers.values():
            if parser.can_parse(text):
                return parser
        return None
    
    def parse_text(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[ParseResult]:
        """
        使用合适的解析器解析文本
        
        Args:
            text: 要解析的文本
            context: 解析上下文
            
        Returns:
            List[ParseResult]: 解析结果列表
        """
        results = []
        for parser in self._parsers.values():
            if parser.can_parse(text):
                try:
                    parser_results = parser.parse(text, context)
                    results.extend(parser_results)
                except Exception as e:
                    parser.logger.error(t("parser.parse_failed", error=str(e)))
        return results


# 全局解析器注册表
parser_registry = ParserRegistry()

