"""
LLM模型管理器
负责LLM的初始化、调用和管理
"""
import os
import logging
from typing import Dict, Any, Optional, List
import httpx
from configs import settings

logger = logging.getLogger(__name__)

class ModelManager:
    """LLM模型管理器"""
    
    def __init__(self):
        self.model_name: Optional[str] = None
        self.base_url: str = ""
        self.api_key: str = ""
        self.timeout: int = 600
        self._initialized = False
    
    def init_model_serve(self, model_name: str) -> bool:
        """
        初始化模型服务
        
        Args:
            model_name: 模型名称
            
        Returns:
            bool: 初始化是否成功
        """
        try:
            self.model_name = model_name
            self.base_url = f"{settings.MODEL_SERVE_PROTOCOL}://{settings.MODEL_SERVE_IP}:{settings.MODEL_SERVE_PORT}"
            self.api_key = settings.MODEL_API_KEY
            self.timeout = settings.HTTP_SERVE_TIMEOUT
            
            logger.info(f"初始化模型服务: {model_name}")
            logger.info(f"模型服务地址: {self.base_url}")
            
            # 测试连接
            if self._test_connection():
                self._initialized = True
                logger.info("模型服务初始化成功")
                return True
            else:
                logger.error("模型服务连接测试失败")
                return False
                
        except Exception as e:
            logger.error(f"模型服务初始化失败: {e}")
            return False
    
    def _test_connection(self) -> bool:
        """
        测试模型服务连接
        
        Returns:
            bool: 连接是否成功
        """
        try:
            with httpx.Client(timeout=10) as client:
                response = client.get(f"{self.base_url}/health")
                return response.status_code == 200
        except Exception as e:
            logger.warning(f"模型服务连接测试失败: {e}")
            return False
    
    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        max_tokens: Optional[int] = None,
        temperature: float = 0.7,
        **kwargs
    ) -> Dict[str, Any]:
        """
        调用聊天完成API
        
        Args:
            messages: 消息列表
            max_tokens: 最大token数
            temperature: 温度参数
            **kwargs: 其他参数
            
        Returns:
            Dict[str, Any]: API响应
        """
        if not self._initialized:
            raise RuntimeError("模型服务未初始化")
        
        try:
            url = f"{self.base_url}{settings.CHAT_COMPLETIONS_URL}"
            
            payload = {
                "model": self.model_name,
                "messages": messages,
                "temperature": temperature,
                **kwargs
            }
            
            if max_tokens:
                payload["max_tokens"] = max_tokens
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}" if self.api_key else ""
            }
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                
                result = response.json()
                logger.debug(f"模型调用成功: {len(messages)} 条消息")
                return result
                
        except Exception as e:
            logger.error(f"模型调用失败: {e}")
            raise
    
    async def lora_generate(
        self,
        prompt: str,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        调用LoRA生成API
        
        Args:
            prompt: 输入提示
            max_tokens: 最大token数
            **kwargs: 其他参数
            
        Returns:
            Dict[str, Any]: API响应
        """
        if not self._initialized:
            raise RuntimeError("模型服务未初始化")
        
        try:
            url = f"{self.base_url}{settings.LORA_GENERATE_URI}"
            
            payload = {
                "prompt": prompt,
                "max_tokens": max_tokens or settings.GENERATE_MAX_TOKENS,
                **kwargs
            }
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}" if self.api_key else ""
            }
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                
                result = response.json()
                logger.debug(f"LoRA生成成功: {len(prompt)} 字符")
                return result
                
        except Exception as e:
            logger.error(f"LoRA生成失败: {e}")
            raise
    
    def is_initialized(self) -> bool:
        """检查是否已初始化"""
        return self._initialized
    
    def get_model_info(self) -> Dict[str, Any]:
        """获取模型信息"""
        return {
            "model_name": self.model_name,
            "base_url": self.base_url,
            "initialized": self._initialized,
            "timeout": self.timeout
        }


# 全局模型管理器实例
_model_manager = ModelManager()


def init_model_serve(model_name: str) -> bool:
    """
    初始化模型服务（全局函数）
    
    Args:
        model_name: 模型名称
        
    Returns:
        bool: 初始化是否成功
    """
    return _model_manager.init_model_serve(model_name)


def get_model_manager() -> ModelManager:
    """
    获取模型管理器实例
    
    Returns:
        ModelManager: 模型管理器实例
    """
    return _model_manager
