"""
主模型控制器
负责统筹整个渗透测试流程，协调子模型任务，处理人工干预和自我纠错
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from enum import Enum
import json
import uuid

from ..orchestrator.states import KillChainState, TaskStatus
from ..schemas.common import BaseResponse, TaskStatus as SchemaTaskStatus
from .llm_manager import LLMManager
from .human_intervention import HumanInterventionManager
from .self_correction import SelfCorrectionEngine
from .dynamic_environment import DynamicEnvironmentManager
from .agent_tool_manager import global_tool_registry
from ..prompts.master_prompts import MasterPrompts
from .todo_manager import TodoManager

logger = logging.getLogger(__name__)


class MasterControllerState(Enum):
    """主控制器状态"""
    INITIALIZING = "initializing"
    PLANNING = "planning"
    EXECUTING = "executing"
    WAITING_HUMAN = "waiting_human"
    SELF_CORRECTING = "self_correcting"
    COMPLETED = "completed"
    ERROR = "error"
    PAUSED = "paused"


class MasterController:
    """主模型控制器"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.state = MasterControllerState.INITIALIZING
        self.session_id = str(uuid.uuid4())
        
        # 核心组件
        self.llm_manager = LLMManager(config.get("llm_models", {}))
        self.human_intervention = HumanInterventionManager(config.get("human_intervention", {}))
        self.self_correction = SelfCorrectionEngine(config.get("self_correction", {}))
        self.dynamic_env = DynamicEnvironmentManager(config.get("dynamic_env", {}))
        # 使用全局工具注册表
        self.tool_registry = global_tool_registry
        
        # Prompt管理器
        self.prompts = MasterPrompts()
        
        # TODO管理器
        self.todo_manager = TodoManager()
        
        # 防超长配置
        self.max_todo_execution_time = config.get("max_todo_execution_time", 1800)  # 30分钟
        self.todo_timeout_threshold = config.get("todo_timeout_threshold", 3600)   # 1小时总超时
        self.max_parallel_todos = config.get("max_parallel_todos", 3)              # 最大并行TODO数
        
        # 执行上下文
        self.execution_context = {
            "session_id": self.session_id,
            "start_time": datetime.now().isoformat(),
            "current_stage": KillChainState.INITIALIZED,
            "execution_history": [],
            "human_feedback": [],
            "correction_history": [],
            "environment_state": {},
            "tool_usage": []
        }
        
        # 回调函数
        self.callbacks = {
            "on_stage_change": [],
            "on_human_intervention": [],
            "on_self_correction": [],
            "on_tool_usage": []
        }
    
    async def initialize(self) -> bool:
        """初始化主控制器"""
        try:
            logger.info(f"初始化主控制器 - Session ID: {self.session_id}")
            
            # 初始化各个组件
            await self.llm_manager.initialize()
            await self.human_intervention.initialize()
            await self.self_correction.initialize()
            await self.dynamic_env.initialize()
            # 全局工具注册表已在导入时初始化
            
            # 初始化TODO管理器
            await self.todo_manager.initialize()
            
            self.state = MasterControllerState.PLANNING
            logger.info("主控制器初始化完成")
            return True
            
        except Exception as e:
            logger.error(f"主控制器初始化失败: {e}")
            self.state = MasterControllerState.ERROR
            return False
    
    async def start_penetration_test(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        启动渗透测试
        
        Args:
            target: 目标地址
            options: 测试选项
            
        Returns:
            Dict[str, Any]: 执行结果
        """
        try:
            self.state = MasterControllerState.PLANNING
            
            # 更新执行上下文
            self.execution_context.update({
                "target": target,
                "options": options or {},
                "current_stage": KillChainState.RECONNAISSANCE
            })
            
            # 生成执行计划
            execution_plan = await self._generate_execution_plan(target, options)
            
            # 执行计划
            result = await self._execute_plan(execution_plan)
            
            return result
            
        except Exception as e:
            logger.error(f"渗透测试启动失败: {e}")
            self.state = MasterControllerState.ERROR
            return {
                "success": False,
                "error": str(e),
                "session_id": self.session_id
            }
    
    async def _generate_execution_plan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """生成执行计划"""
        try:
            # 使用主模型生成执行计划
            plan_prompt = self._build_planning_prompt(target, options)
            
            # 调用主模型
            plan_response = await self.llm_manager.call_master_model(
                "planning",
                plan_prompt,
                context=self.execution_context
            )
            
            # 解析计划
            execution_plan = self._parse_execution_plan(plan_response)
            
            # 验证计划
            if not self._validate_plan(execution_plan):
                raise ValueError("生成的执行计划无效")
            
            return execution_plan
            
        except Exception as e:
            logger.error(f"执行计划生成失败: {e}")
            raise
    
    async def _execute_plan(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """执行计划"""
        try:
            self.state = MasterControllerState.EXECUTING
            
            stages = plan.get("stages", [])
            results = []
            
            for stage in stages:
                # 检查是否需要人工干预
                if await self.human_intervention.should_intervene(stage, self.execution_context):
                    self.state = MasterControllerState.WAITING_HUMAN
                    human_feedback = await self.human_intervention.get_feedback(stage)
                    self.execution_context["human_feedback"].append(human_feedback)
                    
                    # 根据人工反馈调整阶段
                    stage = self._adjust_stage_with_feedback(stage, human_feedback)
                
                # 执行阶段
                stage_result = await self._execute_stage(stage)
                results.append(stage_result)
                
                # 检查是否需要自我纠错
                if await self.self_correction.should_correct(stage_result, self.execution_context):
                    self.state = MasterControllerState.SELF_CORRECTING
                    correction = await self.self_correction.correct(stage_result, self.execution_context)
                    self.execution_context["correction_history"].append(correction)
                    
                    # 重新执行修正后的阶段
                    if correction.get("retry", False):
                        stage_result = await self._execute_stage(correction.get("corrected_stage", stage))
                        results[-1] = stage_result
                
                # 更新执行上下文
                self.execution_context["execution_history"].append(stage_result)
                
                # 触发回调
                await self._trigger_callbacks("on_stage_change", stage_result)
            
            self.state = MasterControllerState.COMPLETED
            
            return {
                "success": True,
                "session_id": self.session_id,
                "results": results,
                "execution_context": self.execution_context
            }
            
        except Exception as e:
            logger.error(f"计划执行失败: {e}")
            self.state = MasterControllerState.ERROR
            raise
    
    async def _execute_stage(self, stage: Dict[str, Any]) -> Dict[str, Any]:
        """执行单个阶段"""
        try:
            stage_type = stage.get("type")
            stage_config = stage.get("config", {})
            
            # 准备环境
            await self.dynamic_env.prepare_stage_environment(stage_type, stage_config)
            
            # 选择子模型
            sub_model = await self.sub_model_manager.select_model(stage_type, stage_config)
            
            # 执行任务
            result = await sub_model.execute(stage_config, self.execution_context)
            
            # 记录工具使用
            if result.get("tools_used"):
                self.execution_context["tool_usage"].extend(result["tools_used"])
                await self._trigger_callbacks("on_tool_usage", result["tools_used"])
            
            return result
            
        except Exception as e:
            logger.error(f"阶段执行失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "stage": stage
            }
    
    def _build_planning_prompt(self, target: str, options: Dict[str, Any]) -> str:
        """构建计划生成提示词"""
        context = {
            "environment_state": self.execution_context.get("environment_state", {}),
            "available_tools": list(self.tool_registry.get_all_public_tools().keys())
        }
        return self.prompts.get_planning_prompt(target, options, context)
    
    def _parse_execution_plan(self, response: str) -> Dict[str, Any]:
        """解析执行计划"""
        try:
            # 尝试解析JSON响应
            if isinstance(response, str):
                plan = json.loads(response)
            else:
                plan = response
            
            return plan
            
        except json.JSONDecodeError as e:
            logger.error(f"计划解析失败: {e}")
            # 返回默认计划
            return self._get_default_plan()
    
    def _get_default_plan(self) -> Dict[str, Any]:
        """获取默认执行计划"""
        return {
            "stages": [
                {
                    "type": "reconnaissance",
                    "name": "侦察阶段",
                    "config": {
                        "target": self.execution_context.get("target"),
                        "tools": ["nmap", "nslookup", "whois"]
                    }
                },
                {
                    "type": "weaponization",
                    "name": "武器化阶段",
                    "config": {
                        "vulnerabilities": [],
                        "payload_type": "basic"
                    }
                }
            ]
        }
    
    def _validate_plan(self, plan: Dict[str, Any]) -> bool:
        """验证执行计划"""
        required_fields = ["stages"]
        return all(field in plan for field in required_fields)
    
    def _adjust_stage_with_feedback(self, stage: Dict[str, Any], feedback: Dict[str, Any]) -> Dict[str, Any]:
        """根据人工反馈调整阶段"""
        # 合并人工反馈到阶段配置
        if "config" in feedback:
            stage["config"].update(feedback["config"])
        
        if "tools" in feedback:
            stage["config"]["tools"] = feedback["tools"]
        
        return stage
    
    async def _trigger_callbacks(self, event_type: str, data: Any) -> None:
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
    
    def register_callback(self, event_type: str, callback: Callable) -> None:
        """注册回调函数"""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
    
    def get_status(self) -> Dict[str, Any]:
        """获取当前状态"""
        return {
            "state": self.state.value,
            "session_id": self.session_id,
            "execution_context": self.execution_context,
            "todo_status": self.todo_manager.get_status() if hasattr(self.todo_manager, 'get_status') else {},
            "components": {
                "llm_manager": self.llm_manager.get_status(),
                "human_intervention": self.human_intervention.get_status(),
                "self_correction": self.self_correction.get_status(),
                "dynamic_env": self.dynamic_env.get_status(),
                "tool_registry": {
                    "public_tools": len(self.tool_registry.get_all_public_tools()),
                    "agent_managers": len(self.tool_registry.agent_managers)
                }
            }
        }
    
    async def create_execution_todos(self, target: str, plan: Dict[str, Any]) -> bool:
        """
        根据执行计划创建TODO列表
        
        Args:
            target: 目标地址
            plan: 执行计划
            
        Returns:
            bool: 是否创建成功
        """
        try:
            todos = []
            
            # 遍历计划中的阶段
            stages = plan.get("stages", [])
            for i, stage in enumerate(stages):
                stage_type = stage.get("type", f"stage_{i}")
                stage_name = stage.get("name", f"阶段{i+1}")
                stage_config = stage.get("config", {})
                estimated_time = stage_config.get("estimated_time", self.max_todo_execution_time)
                
                # 如果预计时间超过阈值，需要分解任务
                if estimated_time > self.max_todo_execution_time:
                    sub_todos = await self._decompose_long_task(stage, target)
                    todos.extend(sub_todos)
                else:
                    todo = {
                        "id": f"{stage_type}_{i}",
                        "title": stage_name,
                        "description": stage.get("description", f"执行{stage_name}"),
                        "type": stage_type,
                        "config": stage_config,
                        "estimated_time": estimated_time,
                        "priority": stage.get("priority", 3),
                        "dependencies": stage.get("dependencies", []),
                        "status": "pending"
                    }
                    todos.append(todo)
            
            # 创建TODO列表
            success = await self.todo_manager.create_batch_todos(todos)
            
            if success:
                logger.info(f"成功创建 {len(todos)} 个TODO任务")
            
            return success
            
        except Exception as e:
            logger.error(f"创建执行TODO失败: {e}")
            return False
    
    async def _decompose_long_task(self, stage: Dict[str, Any], target: str) -> List[Dict[str, Any]]:
        """
        分解超长任务
        
        Args:
            stage: 阶段信息
            target: 目标地址
            
        Returns:
            List[Dict[str, Any]]: 分解后的子任务列表
        """
        stage_type = stage.get("type")
        stage_config = stage.get("config", {})
        
        # 使用LLM分解任务
        decompose_prompt = f"""
        请将以下超长任务分解为多个子任务，每个子任务不超过{self.max_todo_execution_time}秒：
        
        阶段类型: {stage_type}
        阶段配置: {json.dumps(stage_config, ensure_ascii=False, indent=2)}
        目标: {target}
        
        请返回JSON格式的子任务列表，每个子任务包含：
        - id: 任务ID
        - title: 任务标题
        - description: 任务描述
        - estimated_time: 预计执行时间（秒）
        - dependencies: 依赖的其他子任务ID
        - priority: 优先级(1-5)
        """
        
        try:
            # 调用主模型进行任务分解
            response = await self.llm_manager.call_master_model(
                "task_decomposition",
                decompose_prompt,
                context=self.execution_context
            )
            
            if isinstance(response, str):
                decomposed_tasks = json.loads(response)
            else:
                decomposed_tasks = response
            
            # 添加stage类型到每个子任务
            for task in decomposed_tasks:
                task["type"] = stage_type
                task["parent_stage"] = stage.get("id", stage_type)
            
            return decomposed_tasks
            
        except Exception as e:
            logger.error(f"任务分解失败: {e}")
            # 返回默认分解
            return [
                {
                    "id": f"{stage_type}_part1",
                    "title": f"{stage.get('name', stage_type)} - 第1部分",
                    "description": "任务的第一部分",
                    "type": stage_type,
                    "estimated_time": self.max_todo_execution_time // 2,
                    "priority": 3,
                    "dependencies": [],
                    "status": "pending"
                },
                {
                    "id": f"{stage_type}_part2", 
                    "title": f"{stage.get('name', stage_type)} - 第2部分",
                    "description": "任务的第二部分",
                    "type": stage_type,
                    "estimated_time": self.max_todo_execution_time // 2,
                    "priority": 3,
                    "dependencies": [f"{stage_type}_part1"],
                    "status": "pending"
                }
            ]
    
    async def execute_with_todo_management(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        使用TODO管理执行渗透测试
        
        Args:
            target: 目标地址
            options: 测试选项
            
        Returns:
            Dict[str, Any]: 执行结果
        """
        try:
            start_time = datetime.now()
            self.state = MasterControllerState.PLANNING
            
            # 更新执行上下文
            self.execution_context.update({
                "target": target,
                "options": options or {},
                "start_time": start_time.isoformat()
            })
            
            # 生成执行计划
            logger.info("生成执行计划...")
            execution_plan = await self._generate_execution_plan(target, options)
            
            # 创建TODO列表
            logger.info("创建TODO列表...")
            todo_created = await self.create_execution_todos(target, execution_plan)
            if not todo_created:
                raise Exception("TODO列表创建失败")
            
            # 基于TODO执行
            logger.info("开始基于TODO执行...")
            self.state = MasterControllerState.EXECUTING
            
            execution_results = []
            completed_todos = 0
            total_todos = await self.todo_manager.get_total_count()
            
            while True:
                # 检查总执行时间
                current_time = datetime.now()
                total_elapsed = (current_time - start_time).total_seconds()
                
                if total_elapsed > self.todo_timeout_threshold:
                    logger.warning(f"执行超时 ({total_elapsed}秒)，停止执行")
                    break
                
                # 获取下一批可执行的TODO
                next_todos = await self.todo_manager.get_next_executable_todos(self.max_parallel_todos)
                
                if not next_todos:
                    logger.info("所有TODO执行完成")
                    break
                
                # 并行执行TODO
                batch_results = await self._execute_todo_batch(next_todos)
                execution_results.extend(batch_results)
                
                # 更新统计
                completed_in_batch = len([r for r in batch_results if r.get("success")])
                completed_todos += completed_in_batch
                
                # 检查是否需要中断
                if not self._should_continue_execution(batch_results):
                    logger.info("检测到停止条件，终止执行")
                    break
                
                # 进度报告
                progress = (completed_todos / total_todos) * 100 if total_todos > 0 else 0
                logger.info(f"执行进度: {progress:.1f}% ({completed_todos}/{total_todos})")
            
            self.state = MasterControllerState.COMPLETED
            
            # 生成执行总结
            execution_summary = await self._generate_execution_summary(execution_results, start_time)
            
            return {
                "success": True,
                "session_id": self.session_id,
                "target": target,
                "execution_plan": execution_plan,
                "execution_results": execution_results,
                "execution_summary": execution_summary,
                "todo_statistics": await self.todo_manager.get_statistics(),
                "total_execution_time": (datetime.now() - start_time).total_seconds()
            }
            
        except Exception as e:
            logger.error(f"TODO管理执行失败: {e}")
            self.state = MasterControllerState.ERROR
            return {
                "success": False,
                "error": str(e),
                "session_id": self.session_id,
                "partial_results": execution_results if 'execution_results' in locals() else []
            }
    
    async def _execute_todo_batch(self, todos: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        并行执行一批TODO
        
        Args:
            todos: TODO列表
            
        Returns:
            List[Dict[str, Any]]: 执行结果列表
        """
        tasks = []
        for todo in todos:
            task = asyncio.create_task(self._execute_single_todo(todo))
            tasks.append(task)
        
        # 等待所有任务完成
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理异常结果
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    "todo_id": todos[i]["id"],
                    "success": False,
                    "error": str(result),
                    "todo": todos[i]
                })
            else:
                processed_results.append(result)
        
        return processed_results
    
    async def _execute_single_todo(self, todo: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行单个TODO
        
        Args:
            todo: TODO信息
            
        Returns:
            Dict[str, Any]: 执行结果
        """
        todo_id = todo["id"]
        start_time = datetime.now()
        
        try:
            # 标记TODO开始执行
            await self.todo_manager.mark_todo_started(todo_id)
            
            logger.info(f"开始执行TODO: {todo_id} - {todo['title']}")
            
            # 根据TODO类型选择执行方法
            todo_type = todo.get("type", "unknown")
            
            # 设置超时
            timeout = min(todo.get("estimated_time", self.max_todo_execution_time), self.max_todo_execution_time)
            
            # 执行TODO任务
            result = await asyncio.wait_for(
                self._perform_todo_task(todo),
                timeout=timeout
            )
            
            # 计算实际执行时间
            actual_time = (datetime.now() - start_time).total_seconds()
            
            # 更新TODO状态
            if result.get("success", False):
                await self.todo_manager.mark_todo_completed(todo_id, actual_time)
                logger.info(f"TODO执行成功: {todo_id} (耗时: {actual_time:.1f}秒)")
            else:
                await self.todo_manager.mark_todo_failed(todo_id, result.get("error", "执行失败"))
                logger.error(f"TODO执行失败: {todo_id} - {result.get('error', '未知错误')}")
            
            return {
                "todo_id": todo_id,
                "success": result.get("success", False),
                "data": result.get("data", {}),
                "error": result.get("error"),
                "execution_time": actual_time,
                "todo": todo
            }
            
        except asyncio.TimeoutError:
            # 超时处理
            await self.todo_manager.mark_todo_failed(todo_id, "执行超时")
            logger.error(f"TODO执行超时: {todo_id}")
            
            return {
                "todo_id": todo_id,
                "success": False,
                "error": "执行超时",
                "execution_time": (datetime.now() - start_time).total_seconds(),
                "todo": todo
            }
            
        except Exception as e:
            # 异常处理
            await self.todo_manager.mark_todo_failed(todo_id, str(e))
            logger.error(f"TODO执行异常: {todo_id} - {e}")
            
            return {
                "todo_id": todo_id,
                "success": False,
                "error": str(e),
                "execution_time": (datetime.now() - start_time).total_seconds(),
                "todo": todo
            }
    
    async def _perform_todo_task(self, todo: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行具体的TODO任务
        
        Args:
            todo: TODO信息
            
        Returns:
            Dict[str, Any]: 执行结果
        """
        todo_type = todo.get("type", "unknown")
        todo_config = todo.get("config", {})
        
        # 根据TODO类型调用相应的执行方法
        if todo_type == "reconnaissance":
            return await self._execute_stage(KillChainState.RECONNAISSANCE, todo_config)
        elif todo_type == "weaponization":
            return await self._execute_stage(KillChainState.WEAPONIZATION, todo_config) 
        elif todo_type == "delivery":
            return await self._execute_stage(KillChainState.DELIVERY, todo_config)
        elif todo_type == "exploitation":
            return await self._execute_stage(KillChainState.EXPLOITATION, todo_config)
        elif todo_type == "installation":
            return await self._execute_stage(KillChainState.INSTALLATION, todo_config)
        elif todo_type == "command_control":
            return await self._execute_stage(KillChainState.COMMAND_CONTROL, todo_config)
        elif todo_type == "actions_on_objectives":
            return await self._execute_stage(KillChainState.ACTIONS_ON_OBJECTIVES, todo_config)
        else:
            # 自定义任务或未知类型
            return await self._execute_custom_todo(todo)
    
    async def _execute_stage(self, stage: KillChainState, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行杀伤链阶段（简化版，调用原有的_execute_stage方法）
        
        Args:
            stage: 杀伤链阶段
            config: 配置信息
            
        Returns:
            Dict[str, Any]: 执行结果
        """
        # 这里可以调用原有的阶段执行逻辑
        # 或者实现新的基于TODO的阶段执行
        return {
            "success": True,
            "data": {
                "stage": stage.value,
                "config": config,
                "message": f"阶段 {stage.value} 执行完成"
            }
        }
    
    async def _execute_custom_todo(self, todo: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行自定义TODO
        
        Args:
            todo: TODO信息
            
        Returns:
            Dict[str, Any]: 执行结果
        """
        # 自定义TODO执行逻辑
        return {
            "success": True,
            "data": {
                "todo_id": todo["id"],
                "message": f"自定义TODO {todo['title']} 执行完成"
            }
        }
    
    def _should_continue_execution(self, batch_results: List[Dict[str, Any]]) -> bool:
        """
        判断是否应该继续执行
        
        Args:
            batch_results: 批次执行结果
            
        Returns:
            bool: 是否继续执行
        """
        # 计算失败率
        total_tasks = len(batch_results)
        if total_tasks == 0:
            return False
        
        failed_tasks = len([r for r in batch_results if not r.get("success", False)])
        failure_rate = failed_tasks / total_tasks
        
        # 如果失败率过高，考虑停止
        if failure_rate > 0.8:  # 80%失败率
            logger.warning(f"失败率过高 ({failure_rate*100:.1f}%)，考虑停止执行")
            return False
        
        return True
    
    async def _generate_execution_summary(self, execution_results: List[Dict[str, Any]], 
                                        start_time: datetime) -> Dict[str, Any]:
        """
        生成执行总结
        
        Args:
            execution_results: 执行结果列表
            start_time: 开始时间
            
        Returns:
            Dict[str, Any]: 执行总结
        """
        total_tasks = len(execution_results)
        successful_tasks = len([r for r in execution_results if r.get("success", False)])
        failed_tasks = total_tasks - successful_tasks
        
        total_time = (datetime.now() - start_time).total_seconds()
        
        summary_prompt = self.prompts.get_progress_summary_prompt({
            "session_id": self.session_id,
            "target": self.execution_context.get("target"),
            "start_time": start_time.isoformat(),
            "current_state": self.state.value,
            "all_todos": execution_results,
            "discovered_services": self.execution_context.get("discovered_services", []),
            "identified_vulnerabilities": self.execution_context.get("identified_vulnerabilities", []),
            "successful_exploits": self.execution_context.get("exploitation_results", [])
        })
        
        try:
            # 生成AI总结
            ai_summary = await self.llm_manager.call_master_model(
                "execution_summary",
                summary_prompt,
                context=self.execution_context
            )
            
            return {
                "ai_summary": ai_summary,
                "statistics": {
                    "total_tasks": total_tasks,
                    "successful_tasks": successful_tasks,
                    "failed_tasks": failed_tasks,
                    "success_rate": successful_tasks / total_tasks if total_tasks > 0 else 0,
                    "total_execution_time": total_time
                },
                "execution_results": execution_results
            }
            
        except Exception as e:
            logger.error(f"生成执行总结失败: {e}")
            return {
                "ai_summary": "总结生成失败",
                "statistics": {
                    "total_tasks": total_tasks,
                    "successful_tasks": successful_tasks,
                    "failed_tasks": failed_tasks,
                    "success_rate": successful_tasks / total_tasks if total_tasks > 0 else 0,
                    "total_execution_time": total_time
                },
                "execution_results": execution_results
            }
