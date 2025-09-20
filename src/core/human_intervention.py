"""
人工干预管理器
负责处理人工干预请求，允许用户在渗透测试过程中提供反馈和调整
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
import json
import uuid

logger = logging.getLogger(__name__)


class InterventionType:
    """干预类型"""
    APPROVAL = "approval"  # 需要批准
    MODIFICATION = "modification"  # 需要修改
    ADDITION = "addition"  # 需要添加
    SKIP = "skip"  # 跳过
    STOP = "stop"  # 停止


class HumanInterventionManager:
    """人工干预管理器"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.intervention_queue: List[Dict[str, Any]] = []
        self.pending_interventions: Dict[str, Dict[str, Any]] = {}
        self.intervention_history: List[Dict[str, Any]] = []
        
        # 干预规则
        self.intervention_rules = config.get("rules", {
            "auto_approve_low_risk": True,
            "require_approval_for_destructive": True,
            "require_approval_for_external_tools": True,
            "intervention_timeout": 300  # 5分钟超时
        })
        
        # 回调函数
        self.callbacks = {
            "on_intervention_required": [],
            "on_intervention_completed": [],
            "on_intervention_timeout": []
        }
    
    async def initialize(self):
        """初始化人工干预管理器"""
        logger.info("人工干预管理器初始化完成")
    
    async def should_intervene(self, stage: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """
        判断是否需要人工干预
        
        Args:
            stage: 当前阶段信息
            context: 执行上下文
            
        Returns:
            bool: 是否需要干预
        """
        try:
            # 检查干预规则
            if self._check_intervention_rules(stage, context):
                return True
            
            # 检查是否有待处理的干预请求
            if self._has_pending_interventions():
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"干预判断失败: {e}")
            return False
    
    async def get_feedback(self, stage: Dict[str, Any]) -> Dict[str, Any]:
        """
        获取人工反馈
        
        Args:
            stage: 当前阶段信息
            
        Returns:
            Dict[str, Any]: 人工反馈
        """
        try:
            intervention_id = str(uuid.uuid4())
            
            # 创建干预请求
            intervention_request = {
                "id": intervention_id,
                "type": self._determine_intervention_type(stage),
                "stage": stage,
                "timestamp": datetime.now().isoformat(),
                "status": "pending",
                "message": self._build_intervention_message(stage),
                "options": self._build_intervention_options(stage)
            }
            
            # 添加到待处理队列
            self.pending_interventions[intervention_id] = intervention_request
            
            # 触发回调
            await self._trigger_callbacks("on_intervention_required", intervention_request)
            
            # 等待人工反馈
            feedback = await self._wait_for_feedback(intervention_id)
            
            # 记录干预历史
            self.intervention_history.append({
                "intervention_request": intervention_request,
                "feedback": feedback,
                "timestamp": datetime.now().isoformat()
            })
            
            return feedback
            
        except Exception as e:
            logger.error(f"获取人工反馈失败: {e}")
            return {"type": "skip", "message": "干预失败，跳过此阶段"}
    
    def _check_intervention_rules(self, stage: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """检查干预规则"""
        stage_type = stage.get("type", "")
        stage_config = stage.get("config", {})
        
        # 检查是否需要批准破坏性操作
        if self.intervention_rules.get("require_approval_for_destructive", True):
            if self._is_destructive_operation(stage_type, stage_config):
                return True
        
        # 检查是否需要批准外部工具使用
        if self.intervention_rules.get("require_approval_for_external_tools", True):
            if self._uses_external_tools(stage_config):
                return True
        
        # 检查风险等级
        risk_level = self._assess_risk_level(stage_type, stage_config)
        if risk_level == "high" and not self.intervention_rules.get("auto_approve_low_risk", True):
            return True
        
        return False
    
    def _is_destructive_operation(self, stage_type: str, stage_config: Dict[str, Any]) -> bool:
        """判断是否为破坏性操作"""
        destructive_operations = [
            "exploitation", "payload_execution", "privilege_escalation",
            "data_exfiltration", "system_modification"
        ]
        
        return stage_type in destructive_operations
    
    def _uses_external_tools(self, stage_config: Dict[str, Any]) -> bool:
        """判断是否使用外部工具"""
        tools = stage_config.get("tools", [])
        external_tools = ["metasploit", "sqlmap", "burpsuite", "custom_scripts"]
        
        return any(tool in external_tools for tool in tools)
    
    def _assess_risk_level(self, stage_type: str, stage_config: Dict[str, Any]) -> str:
        """评估风险等级"""
        high_risk_stages = ["exploitation", "payload_execution", "privilege_escalation"]
        medium_risk_stages = ["reconnaissance", "weaponization", "delivery"]
        
        if stage_type in high_risk_stages:
            return "high"
        elif stage_type in medium_risk_stages:
            return "medium"
        else:
            return "low"
    
    def _determine_intervention_type(self, stage: Dict[str, Any]) -> str:
        """确定干预类型"""
        stage_type = stage.get("type", "")
        
        if self._is_destructive_operation(stage_type, stage.get("config", {})):
            return InterventionType.APPROVAL
        
        return InterventionType.MODIFICATION
    
    def _build_intervention_message(self, stage: Dict[str, Any]) -> str:
        """构建干预消息"""
        stage_type = stage.get("type", "unknown")
        stage_name = stage.get("name", stage_type)
        
        return f"""
需要人工干预确认

阶段: {stage_name}
类型: {stage_type}
风险等级: {self._assess_risk_level(stage_type, stage.get("config", {}))}

请选择如何处理此阶段：
1. 批准执行
2. 修改配置后执行
3. 跳过此阶段
4. 停止整个测试

详细配置: {json.dumps(stage.get("config", {}), ensure_ascii=False, indent=2)}
"""
    
    def _build_intervention_options(self, stage: Dict[str, Any]) -> List[Dict[str, Any]]:
        """构建干预选项"""
        return [
            {
                "id": "approve",
                "label": "批准执行",
                "type": "approval",
                "description": "按原计划执行此阶段"
            },
            {
                "id": "modify",
                "label": "修改配置",
                "type": "modification",
                "description": "修改配置后执行",
                "config_template": stage.get("config", {})
            },
            {
                "id": "skip",
                "label": "跳过此阶段",
                "type": "skip",
                "description": "跳过此阶段，继续下一阶段"
            },
            {
                "id": "stop",
                "label": "停止测试",
                "type": "stop",
                "description": "停止整个渗透测试"
            }
        ]
    
    async def _wait_for_feedback(self, intervention_id: str) -> Dict[str, Any]:
        """等待人工反馈"""
        timeout = self.intervention_rules.get("intervention_timeout", 300)
        
        try:
            # 等待反馈或超时
            await asyncio.wait_for(
                self._wait_for_intervention_response(intervention_id),
                timeout=timeout
            )
            
            # 获取反馈
            feedback = self.pending_interventions[intervention_id].get("feedback")
            if feedback:
                del self.pending_interventions[intervention_id]
                return feedback
            else:
                # 超时处理
                return await self._handle_intervention_timeout(intervention_id)
                
        except asyncio.TimeoutError:
            return await self._handle_intervention_timeout(intervention_id)
    
    async def _wait_for_intervention_response(self, intervention_id: str):
        """等待干预响应"""
        while intervention_id in self.pending_interventions:
            if self.pending_interventions[intervention_id].get("feedback"):
                break
            await asyncio.sleep(1)
    
    async def _handle_intervention_timeout(self, intervention_id: str) -> Dict[str, Any]:
        """处理干预超时"""
        logger.warning(f"干预请求超时: {intervention_id}")
        
        # 触发超时回调
        await self._trigger_callbacks("on_intervention_timeout", {
            "intervention_id": intervention_id,
            "intervention_request": self.pending_interventions.get(intervention_id, {})
        })
        
        # 默认跳过
        if intervention_id in self.pending_interventions:
            del self.pending_interventions[intervention_id]
        
        return {
            "type": "skip",
            "message": "干预超时，自动跳过此阶段",
            "timeout": True
        }
    
    def submit_feedback(self, intervention_id: str, feedback: Dict[str, Any]) -> bool:
        """
        提交人工反馈
        
        Args:
            intervention_id: 干预ID
            feedback: 反馈内容
            
        Returns:
            bool: 是否提交成功
        """
        try:
            if intervention_id not in self.pending_interventions:
                logger.error(f"干预ID不存在: {intervention_id}")
                return False
            
            # 验证反馈
            if not self._validate_feedback(feedback):
                logger.error(f"反馈格式无效: {feedback}")
                return False
            
            # 保存反馈
            self.pending_interventions[intervention_id]["feedback"] = feedback
            self.pending_interventions[intervention_id]["status"] = "completed"
            
            # 触发完成回调
            asyncio.create_task(self._trigger_callbacks("on_intervention_completed", {
                "intervention_id": intervention_id,
                "feedback": feedback
            }))
            
            logger.info(f"人工反馈已提交: {intervention_id}")
            return True
            
        except Exception as e:
            logger.error(f"提交反馈失败: {e}")
            return False
    
    def _validate_feedback(self, feedback: Dict[str, Any]) -> bool:
        """验证反馈格式"""
        required_fields = ["type"]
        return all(field in feedback for field in required_fields)
    
    def _has_pending_interventions(self) -> bool:
        """检查是否有待处理的干预"""
        return len(self.pending_interventions) > 0
    
    async def _trigger_callbacks(self, event_type: str, data: Any):
        """触发回调函数"""
        callbacks = self.callbacks.get(event_type, [])
        for callback in callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(data)
                else:
                    callback(data)
            except Exception as e:
                logger.error(f"回调函数执行失败: {e}")
    
    def register_callback(self, event_type: str, callback: Callable):
        """注册回调函数"""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
    
    def get_pending_interventions(self) -> List[Dict[str, Any]]:
        """获取待处理的干预请求"""
        return list(self.pending_interventions.values())
    
    def get_intervention_history(self) -> List[Dict[str, Any]]:
        """获取干预历史"""
        return self.intervention_history.copy()
    
    def get_status(self) -> Dict[str, Any]:
        """获取状态"""
        return {
            "pending_interventions": len(self.pending_interventions),
            "intervention_history_count": len(self.intervention_history),
            "intervention_rules": self.intervention_rules
        }
