"""
LLM调用管理器
统一管理LLM调用，为各个Agent提供LLM服务
"""
import asyncio
import logging
from typing import Dict, Any, Optional
import json

from .model_interface import ModelInterface
from ..prompts.master_prompts import MasterPrompts
from ..utils.token_manage import TokenManage

logger = logging.getLogger(__name__)


class LLMManager:
    """LLM调用管理器"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # 主模型接口（用于决策和规划）
        self.master_model_interface: Optional[ModelInterface] = None
        
        # 分析模型接口（用于结果分析）
        self.analysis_model_interface: Optional[ModelInterface] = None
        
        # Token管理器
        self.token_manager = TokenManage()
        
        # Token限制配置
        self.max_prompt_tokens = config.get("max_prompt_tokens", 3200)
        self.max_response_tokens = config.get("max_response_tokens", 2048)
        
        # 调用统计
        self.stats = {
            "master_calls": 0,
            "analysis_calls": 0,
            "total_tokens": 0,
            "errors": 0,
            "token_truncations": 0
        }
    
    async def initialize(self):
        """初始化LLM管理器"""
        try:
            # 初始化主模型
            master_config = self.config.get("master_model", {})
            self.master_model_interface = ModelInterface(master_config)
            await self.master_model_interface.initialize()
            
            # 初始化分析模型（可选）
            analysis_config = self.config.get("analysis_model", master_config)
            if analysis_config != master_config:
                self.analysis_model_interface = ModelInterface(analysis_config)
                await self.analysis_model_interface.initialize()
            else:
                self.analysis_model_interface = self.master_model_interface
            
            logger.info("LLM管理器初始化完成")
            
        except Exception as e:
            logger.error(f"LLM管理器初始化失败: {e}")
            raise
    
    async def call_master_model(self, task_type: str, prompt: str, context: Dict[str, Any] = None) -> str:
        """
        调用主模型（用于决策和规划）
        
        Args:
            task_type: 任务类型
            prompt: 提示词
            context: 上下文信息
            
        Returns:
            str: 模型响应
        """
        try:
            self.stats["master_calls"] += 1
            
            # 添加系统提示
            if task_type == "planning":
                system_prompt = MasterPrompts.get_master_system_prompt()
                full_prompt = f"{system_prompt}\n\n{prompt}"
            else:
                full_prompt = prompt
            
            # Token检查和截断
            full_prompt = self._ensure_token_limit(full_prompt)
            
            response = await self.master_model_interface.call(full_prompt, context)
            
            # 更新统计
            self.stats["total_tokens"] += self.token_manager.sum_prompt(response)
            
            return response
            
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"主模型调用失败: {e}")
            raise
    
    async def call_analysis_model(self, prompt: str, context: Dict[str, Any] = None) -> str:
        """
        调用分析模型（用于结果分析）
        
        Args:
            prompt: 提示词
            context: 上下文信息
            
        Returns:
            str: 模型响应
        """
        try:
            self.stats["analysis_calls"] += 1
            
            # Token检查和截断
            prompt = self._ensure_token_limit(prompt)
            
            response = await self.analysis_model_interface.call(prompt, context)
            
            # 更新统计
            self.stats["total_tokens"] += self.token_manager.sum_prompt(response)
            
            return response
            
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"分析模型调用失败: {e}")
            raise
    
    async def call_agent_model(self, agent_type: str, prompt: str, context: Dict[str, Any] = None) -> str:
        """
        为特定Agent调用模型
        
        Args:
            agent_type: Agent类型
            prompt: 提示词
            context: 上下文信息
            
        Returns:
            str: 模型响应
        """
        # 对于Agent调用，统一使用分析模型
        return await self.call_analysis_model(prompt, context)
    
    def get_status(self) -> Dict[str, Any]:
        """获取LLM管理器状态"""
        return {
            "master_model_ready": self.master_model_interface is not None,
            "analysis_model_ready": self.analysis_model_interface is not None,
            "stats": self.stats.copy()
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """获取调用统计"""
        return self.stats.copy()
    
    def _ensure_token_limit(self, prompt: str) -> str:
        """
        确保prompt不超过token限制
        
        Args:
            prompt: 原始提示词
            
        Returns:
            str: 处理后的提示词
        """
        current_tokens = self.token_manager.sum_prompt(prompt)
        
        if current_tokens > self.max_prompt_tokens:
            self.stats["token_truncations"] += 1
            logger.warning(f"Prompt超过token限制 ({current_tokens} > {self.max_prompt_tokens})，进行截断")
            
            # 使用token管理器截断
            truncated_prompt = self.token_manager.reverse_cutting_prompt(prompt, self.max_prompt_tokens)
            
            logger.info(f"Token截断完成: {current_tokens} -> {self.token_manager.sum_prompt(truncated_prompt)}")
            return truncated_prompt
        
        return prompt
    
    def check_response_length(self, response: str) -> str:
        """
        检查响应长度，必要时进行处理
        
        Args:
            response: 模型响应
            
        Returns:
            str: 处理后的响应
        """
        return self.token_manager.response_extract_with_token_judge(response, self.max_response_tokens)
