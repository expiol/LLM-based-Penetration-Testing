"""
LLM调用重试和输入优化工具
提供重试机制、输入长度优化和错误处理
"""
import asyncio
import logging
import re
from typing import Any, Dict, List, Optional, Callable, Union
from datetime import datetime

logger = logging.getLogger(__name__)


class LLMRetryHandler:
    """LLM调用重试处理器"""
    
    # 可重试的错误代码
    RETRYABLE_ERROR_CODES = [429, 500, 502, 503, 504]
    # 可重试的错误消息关键词
    RETRYABLE_ERROR_KEYWORDS = [
        "rate limit",
        "rate_limit",
        "too many requests",
        "service unavailable",
        "bad gateway",
        "gateway timeout",
        "timeout",
        "负载较高",
        "负载较高",
        "无返回结果",
        "输入过长"
    ]
    
    def __init__(
        self,
        max_retries: int = 3,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True
    ):
        """
        初始化重试处理器
        
        Args:
            max_retries: 最大重试次数
            initial_delay: 初始延迟（秒）
            max_delay: 最大延迟（秒）
            exponential_base: 指数退避基数
            jitter: 是否添加随机抖动
        """
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
    
    def is_retryable_error(self, error: Exception) -> bool:
        """判断错误是否可重试"""
        error_str = str(error).lower()
        error_type = type(error).__name__
        
        # 检查错误代码
        for code in self.RETRYABLE_ERROR_CODES:
            if f"{code}" in error_str or f"code: {code}" in error_str:
                return True
        
        # 检查错误消息关键词
        for keyword in self.RETRYABLE_ERROR_KEYWORDS:
            if keyword.lower() in error_str:
                return True
        
        # 检查特定异常类型
        if "httpx" in error_type.lower() or "httperror" in error_type.lower():
            return True
        
        return False
    
    def calculate_delay(self, attempt: int) -> float:
        """计算延迟时间（指数退避）"""
        delay = min(
            self.initial_delay * (self.exponential_base ** attempt),
            self.max_delay
        )
        
        if self.jitter:
            import random
            # 添加±20%的随机抖动
            jitter_amount = delay * 0.2
            delay += random.uniform(-jitter_amount, jitter_amount)
            delay = max(0.1, delay)  # 确保延迟不为负
        
        return delay
    
    async def retry_async(
        self,
        func: Callable,
        *args,
        **kwargs
    ) -> Any:
        """
        异步重试调用
        
        Args:
            func: 要调用的异步函数
            *args: 函数位置参数
            **kwargs: 函数关键字参数
            
        Returns:
            函数返回值
            
        Raises:
            最后一次尝试的异常
        """
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                
                # 如果不是最后一次尝试且错误可重试
                if attempt < self.max_retries and self.is_retryable_error(e):
                    delay = self.calculate_delay(attempt)
                    logger.warning(
                        f"LLM调用失败 (尝试 {attempt + 1}/{self.max_retries + 1}): {str(e)[:200]}"
                    )
                    logger.info(f"将在 {delay:.2f} 秒后重试...")
                    await asyncio.sleep(delay)
                else:
                    # 不可重试或已达到最大重试次数
                    if attempt >= self.max_retries:
                        logger.error(
                            f"LLM调用失败，已达到最大重试次数 ({self.max_retries + 1}): {str(e)[:500]}"
                        )
                    else:
                        logger.error(f"LLM调用失败，错误不可重试: {str(e)[:500]}")
                    raise
        
        # 理论上不会到达这里，但为了类型检查
        if last_exception:
            raise last_exception


class InputOptimizer:
    """输入优化器 - 处理过长输入"""
    
    # 默认最大输入长度（字符数，保守估计）
    DEFAULT_MAX_LENGTH = 8000  # 约2000 tokens（假设4字符/token）
    
    # 不同模型的建议输入长度
    MODEL_MAX_LENGTHS = {
        "gpt-4": 8000,
        "gpt-4o": 128000,
        "gpt-4o-ca": 128000,
        "gpt-3.5-turbo": 16000,
        "gpt-3.5-turbo-16k": 16000,
    }
    
    def __init__(self, model_name: Optional[str] = None, max_length: Optional[int] = None):
        """
        初始化输入优化器
        
        Args:
            model_name: 模型名称
            max_length: 最大输入长度（字符数），如果为None则根据模型自动选择
        """
        self.model_name = model_name or "gpt-4"
        self.max_length = max_length or self._get_model_max_length()
    
    def _get_model_max_length(self) -> int:
        """根据模型名称获取最大输入长度"""
        for model_key, max_len in self.MODEL_MAX_LENGTHS.items():
            if model_key in self.model_name.lower():
                return max_len
        return self.DEFAULT_MAX_LENGTH
    
    def optimize_input(self, input_text: str, preserve_structure: bool = True) -> str:
        """
        优化输入文本，如果过长则进行截断或摘要
        
        Args:
            input_text: 输入文本
            preserve_structure: 是否保留结构（如JSON、XML等）
            
        Returns:
            优化后的文本
        """
        if len(input_text) <= self.max_length:
            return input_text
        
        logger.warning(
            f"输入文本过长 ({len(input_text)} 字符)，将进行优化（目标: {self.max_length} 字符）"
        )
        
        # 如果输入是结构化数据（JSON/XML），尝试智能截断
        if preserve_structure:
            optimized = self._smart_truncate(input_text)
            if optimized:
                return optimized
        
        # 否则进行简单截断，保留开头和结尾
        return self._simple_truncate(input_text)
    
    def _smart_truncate(self, text: str) -> Optional[str]:
        """智能截断结构化文本"""
        # 尝试检测JSON
        json_match = re.search(r'\{[\s\S]*\}', text, re.DOTALL)
        if json_match:
            try:
                import json
                json_str = json_match.group(0)
                data = json.loads(json_str)
                
                # 如果是字典，尝试截断长值
                if isinstance(data, dict):
                    truncated = self._truncate_dict_values(data)
                    result = json.dumps(truncated, ensure_ascii=False, indent=2)
                    if len(result) <= self.max_length:
                        return text[:json_match.start()] + result + text[json_match.end():]
            except:
                pass
        
        # 尝试检测XML
        if "<" in text and ">" in text:
            # 简单处理：保留XML结构，截断内容
            return self._truncate_xml(text)
        
        return None
    
    def _truncate_dict_values(self, data: Dict[str, Any], max_value_length: int = 500) -> Dict[str, Any]:
        """截断字典中的长值"""
        result = {}
        for key, value in data.items():
            if isinstance(value, str) and len(value) > max_value_length:
                result[key] = value[:max_value_length] + f"\n...[已截断，原始长度: {len(value)}]"
            elif isinstance(value, dict):
                result[key] = self._truncate_dict_values(value, max_value_length)
            elif isinstance(value, list):
                result[key] = [
                    self._truncate_dict_values(item, max_value_length) if isinstance(item, dict)
                    else (item[:max_value_length] + f"...[已截断]" if isinstance(item, str) and len(item) > max_value_length else item)
                    for item in value[:50]  # 限制列表长度
                ]
            else:
                result[key] = value
        return result
    
    def _truncate_xml(self, text: str) -> Optional[str]:
        """截断XML内容"""
        # 简单实现：保留XML标签结构，截断文本内容
        # 更复杂的实现可以使用XML解析器
        if len(text) <= self.max_length:
            return text
        
        # 保留开头和结尾
        header_length = self.max_length // 3
        footer_length = self.max_length // 3
        middle_length = self.max_length - header_length - footer_length
        
        header = text[:header_length]
        footer = text[-footer_length:]
        
        # 尝试在标签边界截断
        last_tag_end = header.rfind('>')
        if last_tag_end > 0:
            header = text[:last_tag_end + 1]
        
        first_tag_start = footer.find('<')
        if first_tag_start > 0:
            footer = text[-(len(footer) - first_tag_start):]
        
        return header + f"\n\n...[XML内容已截断，原始长度: {len(text)} 字符]...\n\n" + footer
    
    def _simple_truncate(self, text: str) -> str:
        """简单截断：保留开头和结尾"""
        if len(text) <= self.max_length:
            return text
        
        # 保留70%的开头和30%的结尾
        header_length = int(self.max_length * 0.7)
        footer_length = self.max_length - header_length - 100  # 预留100字符给截断提示
        
        header = text[:header_length]
        footer = text[-footer_length:]
        
        return header + f"\n\n...[内容已截断，原始长度: {len(text)} 字符]...\n\n" + footer
    
    def optimize_messages(
        self,
        messages: List[Dict[str, Any]],
        preserve_system_prompt: bool = True
    ) -> List[Dict[str, Any]]:
        """
        优化消息列表
        
        Args:
            messages: 消息列表
            preserve_system_prompt: 是否保留系统提示词
            
        Returns:
            优化后的消息列表
        """
        optimized = []
        total_length = sum(len(str(msg.get("content", ""))) for msg in messages)
        
        if total_length <= self.max_length:
            return messages
        
        logger.warning(
            f"消息总长度过长 ({total_length} 字符)，将进行优化"
        )
        
        for msg in messages:
            role = msg.get("role", "")
            content = str(msg.get("content", ""))
            
            # 保留系统提示词
            if preserve_system_prompt and role == "system":
                optimized.append(msg)
                continue
            
            # 优化用户消息和助手消息
            if len(content) > self.max_length // 2:  # 单个消息不超过一半
                optimized_content = self.optimize_input(content)
                optimized.append({**msg, "content": optimized_content})
            else:
                optimized.append(msg)
        
        return optimized


# 全局重试处理器实例
_default_retry_handler = LLMRetryHandler(max_retries=3, initial_delay=1.0)


async def invoke_with_retry(
    llm: Any,
    messages: Union[List[Dict[str, Any]], Any],
    max_retries: int = 3,
    optimize_input: bool = True,
    model_name: Optional[str] = None
) -> Any:
    """
    带重试和输入优化的LLM调用
    
    Args:
        llm: LLM实例
        messages: 消息列表
        max_retries: 最大重试次数
        optimize_input: 是否优化输入长度
        model_name: 模型名称（用于输入优化）
        
    Returns:
        LLM响应
    """
    retry_handler = LLMRetryHandler(max_retries=max_retries)
    
    # 优化输入
    if optimize_input:
        optimizer = InputOptimizer(model_name=model_name)
        
        # 处理消息列表
        if isinstance(messages, list):
            messages = optimizer.optimize_messages(messages)
        elif hasattr(messages, '__iter__'):
            # 如果是其他可迭代对象，尝试转换
            messages_list = list(messages)
            messages = optimizer.optimize_messages(messages_list)
    
    # 带重试的调用
    async def _invoke():
        return await llm.ainvoke(messages)
    
    return await retry_handler.retry_async(_invoke)

