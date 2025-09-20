"""
自我纠错引擎
负责分析执行结果，识别错误和问题，并自动进行纠正和迭代
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import json
import uuid

logger = logging.getLogger(__name__)


class ErrorType:
    """错误类型"""
    EXECUTION_ERROR = "execution_error"  # 执行错误
    LOGIC_ERROR = "logic_error"  # 逻辑错误
    CONFIGURATION_ERROR = "configuration_error"  # 配置错误
    TOOL_ERROR = "tool_error"  # 工具错误
    TIMEOUT_ERROR = "timeout_error"  # 超时错误
    PERMISSION_ERROR = "permission_error"  # 权限错误


class CorrectionStrategy:
    """纠正策略"""
    RETRY = "retry"  # 重试
    MODIFY_CONFIG = "modify_config"  # 修改配置
    CHANGE_TOOL = "change_tool"  # 更换工具
    SKIP_STEP = "skip_step"  # 跳过步骤
    ESCALATE = "escalate"  # 升级处理


class SelfCorrectionEngine:
    """自我纠错引擎"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.correction_history: List[Dict[str, Any]] = []
        self.error_patterns: Dict[str, Dict[str, Any]] = {}
        self.correction_strategies: Dict[str, List[str]] = {}
        
        # 初始化错误模式和纠正策略
        self._initialize_error_patterns()
        self._initialize_correction_strategies()
        
        # 纠错规则
        self.correction_rules = config.get("rules", {
            "max_retry_attempts": 3,
            "auto_correction_enabled": True,
            "escalation_threshold": 2,
            "learning_enabled": True
        })
    
    async def initialize(self):
        """初始化自我纠错引擎"""
        logger.info("自我纠错引擎初始化完成")
    
    async def should_correct(self, result: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """
        判断是否需要纠错
        
        Args:
            result: 执行结果
            context: 执行上下文
            
        Returns:
            bool: 是否需要纠错
        """
        try:
            # 检查执行是否成功
            if result.get("success", True):
                return False
            
            # 分析错误类型
            error_type = self._analyze_error_type(result)
            
            # 检查是否有可用的纠正策略
            available_strategies = self.correction_strategies.get(error_type, [])
            if not available_strategies:
                return False
            
            # 检查重试次数
            retry_count = self._get_retry_count(result, context)
            if retry_count >= self.correction_rules.get("max_retry_attempts", 3):
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"纠错判断失败: {e}")
            return False
    
    async def correct(self, result: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行纠错
        
        Args:
            result: 执行结果
            context: 执行上下文
            
        Returns:
            Dict[str, Any]: 纠错结果
        """
        try:
            correction_id = str(uuid.uuid4())
            
            # 分析错误
            error_analysis = self._analyze_error(result, context)
            
            # 生成纠正策略
            correction_strategy = await self._generate_correction_strategy(error_analysis, context)
            
            # 执行纠正
            correction_result = await self._execute_correction(correction_strategy, context)
            
            # 记录纠错历史
            correction_record = {
                "id": correction_id,
                "timestamp": datetime.now().isoformat(),
                "original_result": result,
                "error_analysis": error_analysis,
                "correction_strategy": correction_strategy,
                "correction_result": correction_result
            }
            
            self.correction_history.append(correction_record)
            
            # 学习错误模式
            if self.correction_rules.get("learning_enabled", True):
                await self._learn_from_correction(correction_record)
            
            return correction_result
            
        except Exception as e:
            logger.error(f"纠错执行失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "retry": False
            }
    
    def _analyze_error_type(self, result: Dict[str, Any]) -> str:
        """分析错误类型"""
        error_message = result.get("error", "").lower()
        
        # 根据错误消息判断错误类型
        if "timeout" in error_message or "timed out" in error_message:
            return ErrorType.TIMEOUT_ERROR
        elif "permission denied" in error_message or "access denied" in error_message:
            return ErrorType.PERMISSION_ERROR
        elif "not found" in error_message or "command not found" in error_message:
            return ErrorType.TOOL_ERROR
        elif "configuration" in error_message or "config" in error_message:
            return ErrorType.CONFIGURATION_ERROR
        elif "logic" in error_message or "invalid" in error_message:
            return ErrorType.LOGIC_ERROR
        else:
            return ErrorType.EXECUTION_ERROR
    
    def _analyze_error(self, result: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """分析错误详情"""
        error_type = self._analyze_error_type(result)
        error_message = result.get("error", "")
        
        # 提取错误上下文
        stage = result.get("stage", {})
        tools_used = result.get("tools_used", [])
        
        return {
            "error_type": error_type,
            "error_message": error_message,
            "stage_type": stage.get("type", ""),
            "stage_config": stage.get("config", {}),
            "tools_used": tools_used,
            "context": context
        }
    
    async def _generate_correction_strategy(self, error_analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """生成纠正策略"""
        error_type = error_analysis["error_type"]
        available_strategies = self.correction_strategies.get(error_type, [])
        
        # 选择最佳策略
        strategy = self._select_best_strategy(error_analysis, available_strategies, context)
        
        # 生成具体的纠正方案
        correction_plan = await self._generate_correction_plan(strategy, error_analysis, context)
        
        return {
            "strategy": strategy,
            "plan": correction_plan,
            "error_analysis": error_analysis
        }
    
    def _select_best_strategy(self, error_analysis: Dict[str, Any], available_strategies: List[str], context: Dict[str, Any]) -> str:
        """选择最佳纠正策略"""
        error_type = error_analysis["error_type"]
        
        # 根据错误类型和历史经验选择策略
        if error_type == ErrorType.TIMEOUT_ERROR:
            return CorrectionStrategy.MODIFY_CONFIG
        elif error_type == ErrorType.TOOL_ERROR:
            return CorrectionStrategy.CHANGE_TOOL
        elif error_type == ErrorType.CONFIGURATION_ERROR:
            return CorrectionStrategy.MODIFY_CONFIG
        elif error_type == ErrorType.PERMISSION_ERROR:
            return CorrectionStrategy.ESCALATE
        else:
            return CorrectionStrategy.RETRY
    
    async def _generate_correction_plan(self, strategy: str, error_analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """生成纠正计划"""
        if strategy == CorrectionStrategy.RETRY:
            return await self._generate_retry_plan(error_analysis, context)
        elif strategy == CorrectionStrategy.MODIFY_CONFIG:
            return await self._generate_config_modification_plan(error_analysis, context)
        elif strategy == CorrectionStrategy.CHANGE_TOOL:
            return await self._generate_tool_change_plan(error_analysis, context)
        elif strategy == CorrectionStrategy.SKIP_STEP:
            return await self._generate_skip_plan(error_analysis, context)
        elif strategy == CorrectionStrategy.ESCALATE:
            return await self._generate_escalation_plan(error_analysis, context)
        else:
            return {"action": "unknown", "message": "未知的纠正策略"}
    
    async def _generate_retry_plan(self, error_analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """生成重试计划"""
        return {
            "action": "retry",
            "message": "重试执行",
            "retry_count": self._get_retry_count(error_analysis, context) + 1,
            "delay": 5  # 延迟5秒重试
        }
    
    async def _generate_config_modification_plan(self, error_analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """生成配置修改计划"""
        stage_config = error_analysis.get("stage_config", {})
        
        # 根据错误类型修改配置
        modified_config = stage_config.copy()
        
        if error_analysis["error_type"] == ErrorType.TIMEOUT_ERROR:
            modified_config["timeout"] = modified_config.get("timeout", 30) * 2
        
        return {
            "action": "modify_config",
            "message": "修改配置后重试",
            "original_config": stage_config,
            "modified_config": modified_config
        }
    
    async def _generate_tool_change_plan(self, error_analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """生成工具更换计划"""
        tools_used = error_analysis.get("tools_used", [])
        stage_type = error_analysis.get("stage_type", "")
        
        # 根据阶段类型选择替代工具
        alternative_tools = self._get_alternative_tools(stage_type, tools_used)
        
        return {
            "action": "change_tool",
            "message": "更换工具后重试",
            "original_tools": tools_used,
            "alternative_tools": alternative_tools
        }
    
    async def _generate_skip_plan(self, error_analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """生成跳过计划"""
        return {
            "action": "skip",
            "message": "跳过此步骤",
            "reason": "无法纠正的错误"
        }
    
    async def _generate_escalation_plan(self, error_analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """生成升级计划"""
        return {
            "action": "escalate",
            "message": "需要人工干预",
            "reason": "自动纠正失败",
            "error_details": error_analysis
        }
    
    async def _execute_correction(self, correction_strategy: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """执行纠正"""
        strategy = correction_strategy["strategy"]
        plan = correction_strategy["plan"]
        
        if strategy == CorrectionStrategy.RETRY:
            return {
                "success": True,
                "retry": True,
                "corrected_stage": context.get("current_stage", {}),
                "delay": plan.get("delay", 0)
            }
        elif strategy == CorrectionStrategy.MODIFY_CONFIG:
            corrected_stage = context.get("current_stage", {}).copy()
            corrected_stage["config"] = plan["modified_config"]
            return {
                "success": True,
                "retry": True,
                "corrected_stage": corrected_stage
            }
        elif strategy == CorrectionStrategy.CHANGE_TOOL:
            corrected_stage = context.get("current_stage", {}).copy()
            corrected_stage["config"]["tools"] = plan["alternative_tools"]
            return {
                "success": True,
                "retry": True,
                "corrected_stage": corrected_stage
            }
        elif strategy == CorrectionStrategy.SKIP_STEP:
            return {
                "success": True,
                "retry": False,
                "skip": True
            }
        elif strategy == CorrectionStrategy.ESCALATE:
            return {
                "success": False,
                "retry": False,
                "escalate": True,
                "error_details": plan["error_details"]
            }
        else:
            return {
                "success": False,
                "retry": False,
                "error": "未知的纠正策略"
            }
    
    def _get_retry_count(self, result: Dict[str, Any], context: Dict[str, Any]) -> int:
        """获取重试次数"""
        stage = result.get("stage", {})
        stage_type = stage.get("type", "")
        
        # 从执行历史中统计重试次数
        execution_history = context.get("execution_history", [])
        retry_count = 0
        
        for history_item in execution_history:
            if (history_item.get("stage", {}).get("type") == stage_type and 
                not history_item.get("success", True)):
                retry_count += 1
        
        return retry_count
    
    def _get_alternative_tools(self, stage_type: str, current_tools: List[str]) -> List[str]:
        """获取替代工具"""
        tool_alternatives = {
            "reconnaissance": {
                "nmap": ["masscan", "zmap"],
                "nslookup": ["dig", "host"],
                "whois": ["whois", "dig"]
            },
            "exploitation": {
                "metasploit": ["custom_scripts", "burpsuite"],
                "sqlmap": ["custom_scripts", "burpsuite"]
            }
        }
        
        alternatives = []
        stage_alternatives = tool_alternatives.get(stage_type, {})
        
        for tool in current_tools:
            if tool in stage_alternatives:
                alternatives.extend(stage_alternatives[tool])
        
        return list(set(alternatives))  # 去重
    
    async def _learn_from_correction(self, correction_record: Dict[str, Any]):
        """从纠错中学习"""
        try:
            error_analysis = correction_record["error_analysis"]
            correction_strategy = correction_record["correction_strategy"]
            correction_result = correction_record["correction_result"]
            
            # 更新错误模式
            error_type = error_analysis["error_type"]
            if error_type not in self.error_patterns:
                self.error_patterns[error_type] = {
                    "count": 0,
                    "successful_corrections": 0,
                    "strategies": {}
                }
            
            self.error_patterns[error_type]["count"] += 1
            
            if correction_result.get("success", False):
                self.error_patterns[error_type]["successful_corrections"] += 1
                
                strategy = correction_strategy["strategy"]
                if strategy not in self.error_patterns[error_type]["strategies"]:
                    self.error_patterns[error_type]["strategies"][strategy] = 0
                self.error_patterns[error_type]["strategies"][strategy] += 1
            
            logger.info(f"学习纠错经验: {error_type} -> {correction_strategy['strategy']}")
            
        except Exception as e:
            logger.error(f"学习纠错经验失败: {e}")
    
    def _initialize_error_patterns(self):
        """初始化错误模式"""
        self.error_patterns = {}
    
    def _initialize_correction_strategies(self):
        """初始化纠正策略"""
        self.correction_strategies = {
            ErrorType.EXECUTION_ERROR: [CorrectionStrategy.RETRY, CorrectionStrategy.MODIFY_CONFIG],
            ErrorType.LOGIC_ERROR: [CorrectionStrategy.MODIFY_CONFIG, CorrectionStrategy.SKIP_STEP],
            ErrorType.CONFIGURATION_ERROR: [CorrectionStrategy.MODIFY_CONFIG, CorrectionStrategy.RETRY],
            ErrorType.TOOL_ERROR: [CorrectionStrategy.CHANGE_TOOL, CorrectionStrategy.MODIFY_CONFIG],
            ErrorType.TIMEOUT_ERROR: [CorrectionStrategy.MODIFY_CONFIG, CorrectionStrategy.RETRY],
            ErrorType.PERMISSION_ERROR: [CorrectionStrategy.ESCALATE, CorrectionStrategy.SKIP_STEP]
        }
    
    def get_correction_history(self) -> List[Dict[str, Any]]:
        """获取纠错历史"""
        return self.correction_history.copy()
    
    def get_error_patterns(self) -> Dict[str, Dict[str, Any]]:
        """获取错误模式"""
        return self.error_patterns.copy()
    
    def get_status(self) -> Dict[str, Any]:
        """获取状态"""
        return {
            "correction_history_count": len(self.correction_history),
            "error_patterns": self.error_patterns,
            "correction_rules": self.correction_rules
        }
