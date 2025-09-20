"""
模型接口
负责与各种LLM模型进行交互
"""
import asyncio
import logging
import httpx
import json
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class ModelInterface:
    """模型接口"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_url = config.get("base_url", "http://localhost:8000")
        self.api_key = config.get("api_key", "")
        self.timeout = config.get("timeout", 600)
        self.max_retries = config.get("max_retries", 3)
        self.retry_delay = config.get("retry_delay", 1)
        
        # 模型配置
        self.model_name = config.get("model_name", "default")
        self.temperature = config.get("temperature", 0.7)
        self.max_tokens = config.get("max_tokens", 2048)
        
        # 统计信息
        self.call_count = 0
        self.success_count = 0
        self.error_count = 0
        self.total_tokens = 0
    
    async def initialize(self):
        """初始化模型接口"""
        try:
            # 测试连接
            await self._test_connection()
            logger.info("模型接口初始化完成")
            
        except Exception as e:
            logger.error(f"模型接口初始化失败: {e}")
            raise
    
    async def call(self, prompt: str, context: Dict[str, Any] = None) -> str:
        """
        调用模型
        
        Args:
            prompt: 提示词
            context: 上下文信息
            
        Returns:
            str: 模型响应
        """
        try:
            self.call_count += 1
            
            # 构建请求
            request_data = self._build_request(prompt, context)
            
            # 发送请求
            response = await self._send_request(request_data)
            
            # 解析响应
            result = self._parse_response(response)
            
            if result.get("success", False):
                self.success_count += 1
                self.total_tokens += result.get("tokens_used", 0)
                return result.get("content", "")
            else:
                self.error_count += 1
                raise Exception(result.get("error", "模型调用失败"))
                
        except Exception as e:
            logger.error(f"模型调用失败: {e}")
            raise
    
    async def call_with_retry(self, prompt: str, context: Dict[str, Any] = None) -> str:
        """带重试的模型调用"""
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                return await self.call(prompt, context)
                
            except Exception as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    logger.warning(f"模型调用失败，重试 {attempt + 1}/{self.max_retries}: {e}")
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                else:
                    logger.error(f"模型调用最终失败: {e}")
        
        raise last_error
    
    def _build_request(self, prompt: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """构建请求数据"""
        messages = [
            {
                "role": "system", 
                "content": "你是一个专业的网络安全专家，擅长渗透测试和漏洞分析。请严格遵守安全和道德规范，仅在授权范围内进行测试。"
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
        
        # 添加上下文信息
        if context:
            context_message = f"上下文信息: {json.dumps(context, ensure_ascii=False, indent=2)}"
            messages.append({
                "role": "assistant",
                "content": context_message
            })
        
        request_data = {
            "model": self.model_name,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False
        }
        
        return request_data
    
    async def _send_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """发送请求"""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}" if self.api_key else ""
        }
        
        url = f"{self.base_url}/v1/chat/completions"
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(url, json=request_data, headers=headers)
            response.raise_for_status()
            return response.json()
    
    def _parse_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """解析响应"""
        try:
            if "choices" in response and len(response["choices"]) > 0:
                choice = response["choices"][0]
                content = choice.get("message", {}).get("content", "")
                
                # 提取token使用信息
                usage = response.get("usage", {})
                tokens_used = usage.get("total_tokens", 0)
                
                return {
                    "success": True,
                    "content": content,
                    "tokens_used": tokens_used
                }
            else:
                return {
                    "success": False,
                    "error": "响应格式无效"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"响应解析失败: {e}"
            }
    
    async def _test_connection(self):
        """测试连接"""
        try:
            test_prompt = "Hello, this is a connection test."
            await self.call(test_prompt)
            logger.info("模型连接测试成功")
            
        except Exception as e:
            logger.error(f"模型连接测试失败: {e}")
            raise
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        success_rate = (self.success_count / self.call_count * 100) if self.call_count > 0 else 0
        
        return {
            "call_count": self.call_count,
            "success_count": self.success_count,
            "error_count": self.error_count,
            "success_rate": success_rate,
            "total_tokens": self.total_tokens,
            "model_name": self.model_name
        }
    
    def get_config(self) -> Dict[str, Any]:
        """获取配置"""
        return {
            "base_url": self.base_url,
            "model_name": self.model_name,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout,
            "max_retries": self.max_retries
        }
