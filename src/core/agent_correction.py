"""
Agent自我修正和主控Agent修正系统
实现Agent的错误检测、自我修正和主控Agent对其他Agent的修正功能
"""
import asyncio
import logging
import json
import uuid
from typing import Dict, Any, List, Optional, Callable, Union
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import re

from ..database.logging_service import pentest_logger
from ..orchestrator.states import AgentType
from .agent_communication import AgentCommunicationHub, MessageType, MessagePriority


class CorrectionType(Enum):
    """修正类型"""
    PARAMETER_ADJUSTMENT = "parameter_adjustment"
    RETRY_WITH_DELAY = "retry_with_delay"
    ALTERNATIVE_METHOD = "alternative_method"
    TIMEOUT_INCREASE = "timeout_increase"
    ERROR_RECOVERY = "error_recovery"
    STRATEGY_CHANGE = "strategy_change"
    RESOURCE_REALLOCATION = "resource_reallocation"
    ABORT_TASK = "abort_task"


class ErrorSeverity(Enum):
    """错误严重程度"""
    LOW = 1      # 可忽略的警告
    MEDIUM = 2   # 需要修正但不影响继续执行
    HIGH = 3     # 需要立即修正
    CRITICAL = 4 # 需要停止当前任务


@dataclass
class ErrorAnalysis:
    """错误分析结果"""
    error_type: str
    severity: ErrorSeverity
    root_cause: str
    error_pattern: str
    suggested_corrections: List[CorrectionType]
    confidence: float  # 0.0-1.0
    context: Dict[str, Any]


@dataclass
class CorrectionAction:
    """修正动作"""
    correction_id: str
    agent_name: str
    error_analysis: ErrorAnalysis
    correction_type: CorrectionType
    parameters: Dict[str, Any]
    reasoning: str
    expected_outcome: str
    priority: int  # 1-5, 5为最高优先级
    created_at: str
    applied_at: Optional[str] = None
    success: Optional[bool] = None
    result: Optional[Dict[str, Any]] = None


class ErrorDetector:
    """错误检测器"""
    
    def __init__(self):
        self.logger = logging.getLogger("ErrorDetector")
        
        # 错误模式定义
        self.error_patterns = {
            "timeout": {
                "pattern": r"timeout|timed out|time limit|time exceeded",
                "severity": ErrorSeverity.MEDIUM,
                "corrections": [CorrectionType.TIMEOUT_INCREASE, CorrectionType.RETRY_WITH_DELAY]
            },
            "connection_error": {
                "pattern": r"connection.*(?:refused|failed|reset)|network.*error|unreachable",
                "severity": ErrorSeverity.MEDIUM,
                "corrections": [CorrectionType.RETRY_WITH_DELAY, CorrectionType.ALTERNATIVE_METHOD]
            },
            "permission_denied": {
                "pattern": r"permission denied|access denied|unauthorized|forbidden",
                "severity": ErrorSeverity.HIGH,
                "corrections": [CorrectionType.ALTERNATIVE_METHOD, CorrectionType.STRATEGY_CHANGE]
            },
            "resource_exhausted": {
                "pattern": r"out of memory|disk full|resource.*exhausted|no space left",
                "severity": ErrorSeverity.HIGH,
                "corrections": [CorrectionType.RESOURCE_REALLOCATION, CorrectionType.STRATEGY_CHANGE]
            },
            "invalid_parameter": {
                "pattern": r"invalid.*parameter|invalid.*argument|bad.*parameter",
                "severity": ErrorSeverity.MEDIUM,
                "corrections": [CorrectionType.PARAMETER_ADJUSTMENT]
            },
            "tool_not_found": {
                "pattern": r"command not found|tool.*not.*found|executable.*not.*found",
                "severity": ErrorSeverity.HIGH,
                "corrections": [CorrectionType.ALTERNATIVE_METHOD, CorrectionType.STRATEGY_CHANGE]
            },
            "authentication_failed": {
                "pattern": r"authentication.*failed|invalid.*credentials|login.*failed",
                "severity": ErrorSeverity.HIGH,
                "corrections": [CorrectionType.ALTERNATIVE_METHOD, CorrectionType.PARAMETER_ADJUSTMENT]
            },
            "parsing_error": {
                "pattern": r"parse.*error|invalid.*format|malformed.*data",
                "severity": ErrorSeverity.MEDIUM,
                "corrections": [CorrectionType.PARAMETER_ADJUSTMENT, CorrectionType.ERROR_RECOVERY]
            },
            "rate_limited": {
                "pattern": r"rate.*limit|too many.*requests|throttled",
                "severity": ErrorSeverity.MEDIUM,
                "corrections": [CorrectionType.RETRY_WITH_DELAY, CorrectionType.STRATEGY_CHANGE]
            },
            "critical_failure": {
                "pattern": r"critical.*error|fatal.*error|system.*crash|segmentation fault",
                "severity": ErrorSeverity.CRITICAL,
                "corrections": [CorrectionType.ABORT_TASK, CorrectionType.ERROR_RECOVERY]
            }
        }
    
    def analyze_error(self, error_message: str, context: Dict[str, Any] = None) -> ErrorAnalysis:
        """分析错误"""
        error_message_lower = error_message.lower()
        context = context or {}
        
        # 检测错误模式
        detected_patterns = []
        for error_type, pattern_info in self.error_patterns.items():
            if re.search(pattern_info["pattern"], error_message_lower):
                detected_patterns.append((error_type, pattern_info))
        
        # 选择最匹配的模式
        if detected_patterns:
            # 按严重性排序，选择最严重的
            detected_patterns.sort(key=lambda x: x[1]["severity"].value, reverse=True)
            error_type, pattern_info = detected_patterns[0]
            
            return ErrorAnalysis(
                error_type=error_type,
                severity=pattern_info["severity"],
                root_cause=self._identify_root_cause(error_type, error_message, context),
                error_pattern=pattern_info["pattern"],
                suggested_corrections=pattern_info["corrections"],
                confidence=self._calculate_confidence(error_type, error_message),
                context=context
            )
        else:
            # 未知错误类型
            return ErrorAnalysis(
                error_type="unknown",
                severity=ErrorSeverity.MEDIUM,
                root_cause="Unknown error pattern",
                error_pattern="",
                suggested_corrections=[CorrectionType.ERROR_RECOVERY, CorrectionType.RETRY_WITH_DELAY],
                confidence=0.3,
                context=context
            )
    
    def _identify_root_cause(self, error_type: str, error_message: str, context: Dict[str, Any]) -> str:
        """识别根本原因"""
        root_causes = {
            "timeout": "Operation took longer than expected timeout period",
            "connection_error": "Network connectivity issues or target service unavailable",
            "permission_denied": "Insufficient privileges or access controls preventing operation",
            "resource_exhausted": "System resources (memory, disk, CPU) insufficient for operation",
            "invalid_parameter": "Incorrect or malformed input parameters",
            "tool_not_found": "Required tool or executable not available in system PATH",
            "authentication_failed": "Invalid credentials or authentication mechanism failure",
            "parsing_error": "Data format incompatible with expected structure",
            "rate_limited": "Too many requests made too quickly to target service",
            "critical_failure": "Severe system or application fault requiring immediate attention"
        }
        
        base_cause = root_causes.get(error_type, "Unidentified error condition")
        
        # 添加上下文信息
        if context:
            if "target" in context:
                base_cause += f" (Target: {context['target']})"
            if "tool" in context:
                base_cause += f" (Tool: {context['tool']})"
        
        return base_cause
    
    def _calculate_confidence(self, error_type: str, error_message: str) -> float:
        """计算检测置信度"""
        if error_type == "unknown":
            return 0.3
        
        # 基于模式匹配强度计算置信度
        pattern_info = self.error_patterns[error_type]
        pattern = pattern_info["pattern"]
        
        # 计算匹配程度
        matches = re.findall(pattern, error_message.lower())
        match_strength = min(len(matches) * 0.3, 0.9)
        
        # 基础置信度
        base_confidence = 0.7
        
        return min(base_confidence + match_strength, 1.0)


class CorrectionEngine:
    """修正引擎"""
    
    def __init__(self, communication_hub: AgentCommunicationHub):
        self.comm_hub = communication_hub
        self.logger = logging.getLogger("CorrectionEngine")
        
        self.error_detector = ErrorDetector()
        
        # 修正历史
        self.correction_history: List[CorrectionAction] = []
        self.agent_correction_stats: Dict[str, Dict[str, int]] = {}
        
        # 修正策略
        self.correction_strategies = {
            CorrectionType.PARAMETER_ADJUSTMENT: self._apply_parameter_adjustment,
            CorrectionType.RETRY_WITH_DELAY: self._apply_retry_with_delay,
            CorrectionType.ALTERNATIVE_METHOD: self._apply_alternative_method,
            CorrectionType.TIMEOUT_INCREASE: self._apply_timeout_increase,
            CorrectionType.ERROR_RECOVERY: self._apply_error_recovery,
            CorrectionType.STRATEGY_CHANGE: self._apply_strategy_change,
            CorrectionType.RESOURCE_REALLOCATION: self._apply_resource_reallocation,
            CorrectionType.ABORT_TASK: self._apply_abort_task
        }
        
        # 学习机制
        self.success_patterns: Dict[str, List[CorrectionType]] = {}
        
    async def analyze_and_correct(self, agent_name: str, error_message: str, 
                                context: Dict[str, Any] = None, 
                                auto_apply: bool = True) -> List[CorrectionAction]:
        """分析错误并生成修正建议"""
        try:
            # 错误分析
            error_analysis = self.error_detector.analyze_error(error_message, context)
            
            self.logger.info(f"错误分析完成 - Agent: {agent_name}, 类型: {error_analysis.error_type}, "
                           f"严重性: {error_analysis.severity.name}")
            
            # 生成修正动作
            corrections = await self._generate_corrections(agent_name, error_analysis)
            
            # 记录到数据库
            session_id = context.get("session_id") if context else "unknown"
            pentest_logger.log_agent_action(
                session_id=session_id,
                agent_name="CorrectionEngine",
                agent_type=AgentType.RECON_AGENT,
                log_level="INFO",
                log_type="ERROR_ANALYSIS",
                message=f"分析Agent错误: {agent_name}",
                details={
                    "error_type": error_analysis.error_type,
                    "severity": error_analysis.severity.name,
                    "confidence": error_analysis.confidence,
                    "suggested_corrections": [c.value for c in error_analysis.suggested_corrections]
                }
            )
            
            # 自动应用修正（如果启用）
            if auto_apply and error_analysis.severity in [ErrorSeverity.MEDIUM, ErrorSeverity.HIGH]:
                for correction in corrections[:1]:  # 只应用第一个修正
                    await self._apply_correction(correction)
            
            return corrections
            
        except Exception as e:
            self.logger.error(f"错误分析失败: {e}")
            return []
    
    async def _generate_corrections(self, agent_name: str, error_analysis: ErrorAnalysis) -> List[CorrectionAction]:
        """生成修正动作"""
        corrections = []
        
        # 根据历史成功模式调整建议顺序
        adjusted_corrections = self._adjust_corrections_by_history(agent_name, error_analysis.suggested_corrections)
        
        for i, correction_type in enumerate(adjusted_corrections):
            correction = CorrectionAction(
                correction_id=str(uuid.uuid4()),
                agent_name=agent_name,
                error_analysis=error_analysis,
                correction_type=correction_type,
                parameters=self._generate_correction_parameters(correction_type, error_analysis),
                reasoning=self._generate_correction_reasoning(correction_type, error_analysis),
                expected_outcome=self._generate_expected_outcome(correction_type, error_analysis),
                priority=len(adjusted_corrections) - i,  # 越前面优先级越高
                created_at=datetime.now().isoformat()
            )
            corrections.append(correction)
        
        return corrections
    
    def _adjust_corrections_by_history(self, agent_name: str, 
                                     suggested_corrections: List[CorrectionType]) -> List[CorrectionType]:
        """根据历史成功模式调整修正建议"""
        if agent_name not in self.success_patterns:
            return suggested_corrections
        
        successful_patterns = self.success_patterns[agent_name]
        
        # 按成功率排序
        def correction_score(correction_type):
            success_count = successful_patterns.count(correction_type)
            # 基础分数 + 历史成功次数
            base_score = suggested_corrections.index(correction_type) if correction_type in suggested_corrections else 10
            return success_count * 2 - base_score
        
        return sorted(suggested_corrections, key=correction_score, reverse=True)
    
    def _generate_correction_parameters(self, correction_type: CorrectionType, 
                                      error_analysis: ErrorAnalysis) -> Dict[str, Any]:
        """生成修正参数"""
        parameters = {}
        context = error_analysis.context
        
        if correction_type == CorrectionType.PARAMETER_ADJUSTMENT:
            parameters = {
                "validate_parameters": True,
                "use_safe_defaults": True,
                "parameter_checks": ["type", "range", "format"]
            }
        
        elif correction_type == CorrectionType.RETRY_WITH_DELAY:
            parameters = {
                "max_retries": 3,
                "initial_delay": 5,
                "backoff_factor": 2.0,
                "jitter": True
            }
        
        elif correction_type == CorrectionType.TIMEOUT_INCREASE:
            current_timeout = context.get("timeout", 30)
            parameters = {
                "new_timeout": current_timeout * 2,
                "timeout_strategy": "exponential_increase"
            }
        
        elif correction_type == CorrectionType.ALTERNATIVE_METHOD:
            parameters = {
                "fallback_methods": ["socket_scan", "manual_enumeration"],
                "method_priority": ["safe", "reliable", "fast"]
            }
        
        elif correction_type == CorrectionType.STRATEGY_CHANGE:
            parameters = {
                "new_strategy": "conservative",
                "reduce_aggressiveness": True,
                "increase_stealth": True
            }
        
        elif correction_type == CorrectionType.RESOURCE_REALLOCATION:
            parameters = {
                "reduce_concurrency": True,
                "memory_optimization": True,
                "cleanup_resources": True
            }
        
        return parameters
    
    def _generate_correction_reasoning(self, correction_type: CorrectionType, 
                                     error_analysis: ErrorAnalysis) -> str:
        """生成修正理由"""
        reasoning_templates = {
            CorrectionType.PARAMETER_ADJUSTMENT: f"参数错误导致{error_analysis.error_type}，需要调整参数配置",
            CorrectionType.RETRY_WITH_DELAY: f"临时性{error_analysis.error_type}，延迟重试可能解决问题",
            CorrectionType.ALTERNATIVE_METHOD: f"{error_analysis.error_type}表明当前方法不可行，需要尝试替代方法",
            CorrectionType.TIMEOUT_INCREASE: f"操作超时，增加超时时间可能允许操作完成",
            CorrectionType.ERROR_RECOVERY: f"从{error_analysis.error_type}中恢复，重置状态并继续",
            CorrectionType.STRATEGY_CHANGE: f"{error_analysis.error_type}需要改变整体策略",
            CorrectionType.RESOURCE_REALLOCATION: f"资源不足导致{error_analysis.error_type}，需要重新分配资源",
            CorrectionType.ABORT_TASK: f"严重错误{error_analysis.error_type}，建议终止当前任务"
        }
        
        return reasoning_templates.get(correction_type, f"应用{correction_type.value}修正{error_analysis.error_type}")
    
    def _generate_expected_outcome(self, correction_type: CorrectionType, 
                                 error_analysis: ErrorAnalysis) -> str:
        """生成预期结果"""
        outcome_templates = {
            CorrectionType.PARAMETER_ADJUSTMENT: "参数验证通过，操作成功执行",
            CorrectionType.RETRY_WITH_DELAY: "重试成功，临时问题已解决",
            CorrectionType.ALTERNATIVE_METHOD: "替代方法成功完成任务",
            CorrectionType.TIMEOUT_INCREASE: "操作在延长时间内完成",
            CorrectionType.ERROR_RECOVERY: "错误状态清除，正常执行恢复",
            CorrectionType.STRATEGY_CHANGE: "新策略避免错误重现",
            CorrectionType.RESOURCE_REALLOCATION: "资源优化，操作稳定执行",
            CorrectionType.ABORT_TASK: "任务安全终止，避免进一步损害"
        }
        
        return outcome_templates.get(correction_type, "错误得到修正")
    
    async def _apply_correction(self, correction: CorrectionAction) -> bool:
        """应用修正"""
        try:
            self.logger.info(f"应用修正: {correction.correction_type.value} for {correction.agent_name}")
            
            # 记录应用开始
            correction.applied_at = datetime.now().isoformat()
            
            # 调用对应的修正策略
            strategy_func = self.correction_strategies.get(correction.correction_type)
            if strategy_func:
                result = await strategy_func(correction)
                correction.success = result.get("success", False)
                correction.result = result
                
                # 更新统计
                self._update_correction_stats(correction)
                
                # 学习成功模式
                if correction.success:
                    self._learn_success_pattern(correction.agent_name, correction.correction_type)
                
                # 记录结果
                self.correction_history.append(correction)
                
                # 通知Agent修正结果
                await self._notify_correction_result(correction)
                
                return correction.success
            else:
                self.logger.error(f"未找到修正策略: {correction.correction_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"修正应用失败: {e}")
            correction.success = False
            correction.result = {"error": str(e)}
            return False
    
    async def _apply_parameter_adjustment(self, correction: CorrectionAction) -> Dict[str, Any]:
        """应用参数调整修正"""
        # 向Agent发送参数调整指令
        await self.comm_hub.send_message(
            source_agent="CorrectionEngine",
            target_agent=correction.agent_name,
            message_type=MessageType.COMMAND,
            content={
                "command": "adjust_parameters",
                "parameters": correction.parameters,
                "correction_id": correction.correction_id
            },
            priority=MessagePriority.HIGH
        )
        
        return {"success": True, "action": "parameter_adjustment_sent"}
    
    async def _apply_retry_with_delay(self, correction: CorrectionAction) -> Dict[str, Any]:
        """应用延迟重试修正"""
        delay = correction.parameters.get("initial_delay", 5)
        
        # 等待指定延迟
        await asyncio.sleep(delay)
        
        # 向Agent发送重试指令
        await self.comm_hub.send_message(
            source_agent="CorrectionEngine",
            target_agent=correction.agent_name,
            message_type=MessageType.COMMAND,
            content={
                "command": "retry_last_operation",
                "parameters": correction.parameters,
                "correction_id": correction.correction_id
            },
            priority=MessagePriority.HIGH
        )
        
        return {"success": True, "action": "retry_scheduled", "delay": delay}
    
    async def _apply_alternative_method(self, correction: CorrectionAction) -> Dict[str, Any]:
        """应用替代方法修正"""
        await self.comm_hub.send_message(
            source_agent="CorrectionEngine",
            target_agent=correction.agent_name,
            message_type=MessageType.COMMAND,
            content={
                "command": "use_alternative_method",
                "parameters": correction.parameters,
                "correction_id": correction.correction_id
            },
            priority=MessagePriority.HIGH
        )
        
        return {"success": True, "action": "alternative_method_suggested"}
    
    async def _apply_timeout_increase(self, correction: CorrectionAction) -> Dict[str, Any]:
        """应用超时增加修正"""
        await self.comm_hub.send_message(
            source_agent="CorrectionEngine",
            target_agent=correction.agent_name,
            message_type=MessageType.COMMAND,
            content={
                "command": "increase_timeout",
                "parameters": correction.parameters,
                "correction_id": correction.correction_id
            },
            priority=MessagePriority.HIGH
        )
        
        return {"success": True, "action": "timeout_increased"}
    
    async def _apply_error_recovery(self, correction: CorrectionAction) -> Dict[str, Any]:
        """应用错误恢复修正"""
        await self.comm_hub.send_message(
            source_agent="CorrectionEngine",
            target_agent=correction.agent_name,
            message_type=MessageType.COMMAND,
            content={
                "command": "recover_from_error",
                "parameters": correction.parameters,
                "correction_id": correction.correction_id
            },
            priority=MessagePriority.HIGH
        )
        
        return {"success": True, "action": "error_recovery_initiated"}
    
    async def _apply_strategy_change(self, correction: CorrectionAction) -> Dict[str, Any]:
        """应用策略变更修正"""
        await self.comm_hub.send_message(
            source_agent="CorrectionEngine",
            target_agent=correction.agent_name,
            message_type=MessageType.COMMAND,
            content={
                "command": "change_strategy",
                "parameters": correction.parameters,
                "correction_id": correction.correction_id
            },
            priority=MessagePriority.HIGH
        )
        
        return {"success": True, "action": "strategy_change_requested"}
    
    async def _apply_resource_reallocation(self, correction: CorrectionAction) -> Dict[str, Any]:
        """应用资源重新分配修正"""
        await self.comm_hub.send_message(
            source_agent="CorrectionEngine",
            target_agent=correction.agent_name,
            message_type=MessageType.COMMAND,
            content={
                "command": "reallocate_resources",
                "parameters": correction.parameters,
                "correction_id": correction.correction_id
            },
            priority=MessagePriority.HIGH
        )
        
        return {"success": True, "action": "resource_reallocation_requested"}
    
    async def _apply_abort_task(self, correction: CorrectionAction) -> Dict[str, Any]:
        """应用任务终止修正"""
        await self.comm_hub.send_message(
            source_agent="CorrectionEngine",
            target_agent=correction.agent_name,
            message_type=MessageType.COMMAND,
            content={
                "command": "abort_current_task",
                "parameters": correction.parameters,
                "correction_id": correction.correction_id,
                "reason": correction.reasoning
            },
            priority=MessagePriority.CRITICAL
        )
        
        return {"success": True, "action": "task_abort_requested"}
    
    def _update_correction_stats(self, correction: CorrectionAction):
        """更新修正统计"""
        agent_name = correction.agent_name
        if agent_name not in self.agent_correction_stats:
            self.agent_correction_stats[agent_name] = {
                "total_corrections": 0,
                "successful_corrections": 0,
                "failed_corrections": 0,
                "correction_types": {}
            }
        
        stats = self.agent_correction_stats[agent_name]
        stats["total_corrections"] += 1
        
        if correction.success:
            stats["successful_corrections"] += 1
        else:
            stats["failed_corrections"] += 1
        
        correction_type = correction.correction_type.value
        if correction_type not in stats["correction_types"]:
            stats["correction_types"][correction_type] = {"total": 0, "successful": 0}
        
        stats["correction_types"][correction_type]["total"] += 1
        if correction.success:
            stats["correction_types"][correction_type]["successful"] += 1
    
    def _learn_success_pattern(self, agent_name: str, correction_type: CorrectionType):
        """学习成功模式"""
        if agent_name not in self.success_patterns:
            self.success_patterns[agent_name] = []
        
        self.success_patterns[agent_name].append(correction_type)
        
        # 保持模式历史在合理范围内
        if len(self.success_patterns[agent_name]) > 100:
            self.success_patterns[agent_name] = self.success_patterns[agent_name][-50:]
    
    async def _notify_correction_result(self, correction: CorrectionAction):
        """通知修正结果"""
        await self.comm_hub.send_message(
            source_agent="CorrectionEngine",
            target_agent=correction.agent_name,
            message_type=MessageType.RESPONSE,
            content={
                "correction_id": correction.correction_id,
                "success": correction.success,
                "result": correction.result,
                "timestamp": datetime.now().isoformat()
            },
            priority=MessagePriority.HIGH,
            correlation_id=correction.correction_id
        )
    
    def get_correction_statistics(self) -> Dict[str, Any]:
        """获取修正统计信息"""
        total_corrections = len(self.correction_history)
        successful_corrections = len([c for c in self.correction_history if c.success])
        
        return {
            "total_corrections": total_corrections,
            "successful_corrections": successful_corrections,
            "success_rate": successful_corrections / total_corrections if total_corrections > 0 else 0,
            "agent_stats": self.agent_correction_stats,
            "recent_corrections": [
                {
                    "agent": c.agent_name,
                    "type": c.correction_type.value,
                    "success": c.success,
                    "timestamp": c.applied_at
                }
                for c in self.correction_history[-10:]
            ]
        }
    
    def get_agent_correction_recommendations(self, agent_name: str) -> List[str]:
        """获取Agent修正建议"""
        if agent_name not in self.agent_correction_stats:
            return ["暂无修正历史数据"]
        
        stats = self.agent_correction_stats[agent_name]
        recommendations = []
        
        # 成功率分析
        success_rate = stats["successful_corrections"] / stats["total_corrections"]
        if success_rate < 0.7:
            recommendations.append(f"该Agent修正成功率较低({success_rate:.1%})，建议检查Agent配置")
        
        # 修正类型分析
        for correction_type, type_stats in stats["correction_types"].items():
            type_success_rate = type_stats["successful"] / type_stats["total"]
            if type_success_rate < 0.5 and type_stats["total"] >= 3:
                recommendations.append(f"{correction_type}类型修正成功率低，建议优化相关逻辑")
        
        # 频繁修正警告
        if stats["total_corrections"] > 20:
            recommendations.append("该Agent频繁需要修正，建议全面检查Agent稳定性")
        
        if not recommendations:
            recommendations.append("Agent修正表现良好，无特殊建议")
        
        return recommendations
