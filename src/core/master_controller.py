"""
基于Ray的Master Controller
使用Ray进行分布式任务调度和状态管理
"""
import asyncio
import logging
import json
import re
import os
from typing import Any, Dict, List, Optional
from datetime import datetime
import ray

from ..orchestrator.states import KillChainState, AgentType
from ..ray_integration.ray_agent_actor import RayAgentPool
from ..ray_integration.ray_state_manager import RayStateManager
from ..core.todo_manager import TodoManager
from ..prompts.master_prompts import MasterPrompts
from ..utils.llm_retry import LLMRetryHandler, InputOptimizer

logger = logging.getLogger(__name__)

# 静默模式控制 - 当设置为True时抑制调试输出
QUIET_MODE = os.environ.get("PENTEST_QUIET_MODE", "0") == "1"


def _print(msg: str, *args, **kwargs):
    """条件输出 - 静默模式下不输出"""
    if not QUIET_MODE:
        print(msg, *args, **kwargs)


class RayMasterController:
    """
    基于Ray的主控制器
    负责协调整个渗透测试流程，使用Ray进行分布式调度
    """
    
    def __init__(self, config: Dict[str, Any]):
        from ..core.execution_manager import get_execution_manager
        
        self.config = config
        self.logger = logging.getLogger("ray_master_controller")
        self.running_sessions: Dict[str, asyncio.Task] = {}
        self.execution_manager = get_execution_manager()
        
        # 确保 Ray 已初始化（应该已经在框架初始化时完成）
        if not self.execution_manager.is_ray_initialized():
            self.logger.warning("Ray not initialized, initializing now...")
            ray_config = config.get("ray", {})
            self.execution_manager.initialize_ray(ray_config)
        
        # Agent池
        self.agent_pool = RayAgentPool(config)
        
        # 状态管理器
        self.state_manager = RayStateManager()
        
        # TODO管理器
        self.todo_manager = TodoManager()
        
        # 主控LLM（用于生成任务列表）
        self.master_llm = None
        self._master_model_name: Optional[str] = None  # 保存模型名称用于输入优化
        self._master_retry_handler: Optional[LLMRetryHandler] = None  # 重试处理器
        self._init_master_llm()
        
        # Kill Chain映射
        self.kill_chain_mapping = {
            KillChainState.RECONNAISSANCE: AgentType.RECON_AGENT,
            KillChainState.WEAPONIZATION: AgentType.WEAPONIZE_AGENT,
            KillChainState.DELIVERY: AgentType.DELIVERY_AGENT,
            KillChainState.EXPLOITATION: AgentType.EXPLOIT_AGENT,
            KillChainState.INSTALLATION: AgentType.INSTALL_AGENT,
            KillChainState.COMMAND_CONTROL: AgentType.C2_AGENT,
            KillChainState.ACTIONS_ON_OBJECTIVES: AgentType.OBJECTIVES_AGENT
        }
    
    def _init_master_llm(self):
        """初始化主控LLM - 从配置读取"""
        try:
            from langchain_openai import ChatOpenAI
            
            # 从配置读取主控LLM设置（已经由 build_framework_config 从 llm_runtime.json 构建）
            llm_config = self.config.get("llm_models", {}).get("master_model", {})
            if not llm_config:
                llm_config = self.config.get("master_model", {})
            
            if not llm_config:
                self.logger.warning("未找到主控LLM配置")
                print("⚠️  警告：未找到主控LLM配置", flush=True)
                return
            
            api_key = llm_config.get("api_key")
            base_url = llm_config.get("base_url")
            model_name = llm_config.get("model_name") or llm_config.get("model", "gpt-4")
            
            # 保存模型名称用于输入优化
            self._master_model_name = model_name
            
            if not api_key:
                self.logger.warning("未配置主控LLM API Key")
                print("⚠️  警告：未配置主控LLM API Key", flush=True)
                return
            
            # 创建重试处理器
            max_retries = self.config.get("execution", {}).get("max_retry_attempts", 3)
            self._master_retry_handler = LLMRetryHandler(max_retries=max_retries)
            
            # 创建 ChatOpenAI 实例
            # 🔧 禁用streaming和可能不兼容的参数：第三方API可能不支持某些参数
            kwargs = {
                "model": model_name,
                "temperature": llm_config.get("temperature", 0.7),
                "max_tokens": llm_config.get("max_tokens", 4096),
                "api_key": api_key,
                "streaming": False,  # 禁用streaming，避免第三方API不兼容
                "timeout": llm_config.get("timeout", 60.0),  # 设置超时
            }
            
            if base_url:
                kwargs["base_url"] = base_url
            
            # 🔧 确保不传递可能不兼容的参数
            # 某些第三方API不支持 parallel_tool_calls, tool_choice 等参数
            # 通过 model_kwargs 显式控制，确保不传递这些参数
            kwargs["model_kwargs"] = {}  # 显式设置为空，避免默认参数
            
            self.master_llm = ChatOpenAI(**kwargs)
            
            # 🔧 验证并确保没有不兼容的参数
            if hasattr(self.master_llm, 'model_kwargs'):
                # 移除可能不兼容的参数
                if self.master_llm.model_kwargs:
                    incompatible_params = ['parallel_tool_calls', 'tool_choice', 'response_format']
                    for param in incompatible_params:
                        if param in self.master_llm.model_kwargs:
                            self.logger.warning(f"移除可能不兼容的参数: {param}")
                            del self.master_llm.model_kwargs[param]
            self.logger.info(f"主控LLM初始化成功 - Model: {model_name}, Base URL: {base_url}")
            _print(f"✅ 主控LLM初始化成功 - Model: {model_name}", flush=True)
            
        except Exception as e:
            self.logger.error(f"主控LLM初始化失败: {e}")
            self.master_llm = None
    
    async def register_agent(
        self,
        agent_class: type,
        agent_type: AgentType,
        agent_config: Dict[str, Any],
        num_cpus: float = 1.0,
        num_gpus: float = 0.0
    ):
        """
        注册Agent到Ray Actor池
        
        Args:
            agent_class: Agent类（不是实例）
            agent_type: Agent类型
            agent_config: Agent配置
            num_cpus: CPU资源分配
            num_gpus: GPU资源分配
        """
        try:
            actor = await self.agent_pool.create_actor(
                agent_class,
                agent_type,
                agent_config,
                num_cpus=num_cpus,
                num_gpus=num_gpus
            )
            self.logger.info(f"Registered agent: {agent_type.value}")
            return actor
        except Exception as e:
            self.logger.error(f"Failed to register agent {agent_type.value}: {e}")
            raise
    
    async def start_penetration_test(
        self,
        target: str,
        options: Dict[str, Any] = None,
        parallel: bool = False,
        async_mode: bool = False
    ) -> Dict[str, Any]:
        """
        启动渗透测试
        
        Args:
            target: 目标地址（可能是 "auto_extract" 表示让LLM自动提取）
            options: 测试选项（包含 raw_description）
            parallel: 是否并行执行（部分阶段）
            
        Returns:
            Dict[str, Any]: 执行结果
        """
        try:
            # 生成session_id
            import uuid
            session_id = str(uuid.uuid4())
            
            _print(f"\n{'=' * 72}", flush=True)
            _print(f"🔄 创建会话: {session_id}", flush=True)
            self.logger.info(f"Creating session: {session_id}")
            
            # 初始化TODO管理器
            _print(f"🔄 初始化TODO管理器...", flush=True)
            await self.todo_manager.initialize()
            _print(f"✅ TODO管理器初始化完成", flush=True)
            
            # 如果target是"auto_extract"，使用原始描述
            raw_description = (options or {}).get("raw_description", "")
            if target == "auto_extract" and raw_description:
                _print(f"📝 使用原始描述，让主控LLM自动提取目标: {raw_description[:50]}...", flush=True)
            
            # 初始化会话状态
            _print(f"🔄 初始化会话状态...", flush=True)
            await self.state_manager.put_session_state(session_id, {
                "target": target,
                "options": options or {},
                "start_time": datetime.now().isoformat(),
                "status": "planning",
                "parallel": parallel,
                "raw_description": raw_description,
                "session_id": session_id
            })
            
            # 初始化全局上下文（目标会在LLM生成计划后更新）
            _print(f"🔄 初始化全局上下文...", flush=True)
            await self.state_manager.put_global_context(session_id, {
                "target": target if target != "auto_extract" else "",
                "discovered_services": [],
                "identified_vulnerabilities": [],
                "exploitation_results": [],
                "current_access_level": "none"
            })
            
            # 步骤1: 生成完整的任务列表（LLM会提取目标并生成计划）
            _print(f"🔄 正在调用主控LLM生成完整的任务列表...", flush=True)
            if target == "auto_extract":
                raw_desc = (options or {}).get("raw_description", "")
                _print(f"   主控LLM将自动从描述中提取目标并生成执行计划", flush=True)
                if raw_desc:
                    _print(f"   原始描述: {raw_desc[:100]}...", flush=True)
            _print(f"   开始调用LLM API...", flush=True)
            try:
                execution_plan = await self._generate_execution_plan(target, options or {}, session_id)
                _print(f"   ✅ 执行计划生成完成", flush=True)
            except Exception as e:
                _print(f"   ❌ 执行计划生成失败: {e}", flush=True)
                self.logger.error(f"执行计划生成失败: {e}", exc_info=True)
                raise
            
            if not execution_plan or not execution_plan.get("stages"):
                raise ValueError("未能生成有效的执行计划")
            
            # 从执行计划中获取提取的目标
            extracted_target = execution_plan.get("target") or target
            final_target = extracted_target or target
            if final_target == "auto_extract":
                # fallback 到原始输入，至少保证向下游传递字符串
                final_target = (options or {}).get("raw_description", "").strip() or target
            
            # 如果主控成功解析出了更准确的目标，提示并更新状态
            if final_target and final_target != target:
                if target == "auto_extract":
                    _print(f"✅ 主控LLM已提取目标: {final_target}", flush=True)
                else:
                    _print(f"ℹ️ 主控LLM规范化目标: {final_target}", flush=True)
            
            await self.state_manager.update_session_state(session_id, {
                "target": final_target
            })
            await self.state_manager.update_global_context(session_id, {
                "target": final_target
            })
            
            # 步骤2: 将任务列表保存到TodoManager
            _print(f"🔄 正在保存任务列表到TodoManager...", flush=True)
            await self._save_execution_plan_to_todos(execution_plan, session_id)
            
            # 更新会话状态，保存执行计划
            await self.state_manager.update_session_state(session_id, {
                "status": "running",
                "execution_plan": execution_plan,
                "target": final_target
            })
            
            _print(f"✅ 任务列表生成完成，共 {len(execution_plan.get('stages', []))} 个阶段", flush=True)
            self.logger.info(f"Execution plan generated - {len(execution_plan.get('stages', []))} stages, target: {final_target}")
            
            # 步骤3: 根据模式启动执行
            if async_mode:
                _print("▶️ 会话进入异步执行模式，可实时查看执行状态", flush=True)
                execution_task = asyncio.create_task(
                    self._run_execution_pipeline(session_id, final_target, options or {}, parallel)
                )
                self.running_sessions[session_id] = execution_task
                execution_task.add_done_callback(lambda task, sid=session_id: self.running_sessions.pop(sid, None))
                return {
                    "success": True,
                    "session_id": session_id,
                    "target": final_target,
                    "execution_plan": execution_plan,
                    "status": "running",
                    "async_mode": True
                }
            
            execution_summary = await self._run_execution_pipeline(session_id, final_target, options or {}, parallel)
            execution_summary.update({
                "session_id": session_id,
                "target": final_target,
                "execution_plan": execution_plan
            })
            return execution_summary
            
        except Exception as e:
            self.logger.error(f"Penetration test failed: {e}")
            if "session_id" in locals():
                await self.state_manager.update_session_state(session_id, {
                    "status": "failed",
                    "error": str(e)
                })
            
            return {
                "success": False,
                "error": str(e)
            }
    async def _run_execution_pipeline(
        self,
        session_id: str,
        target: str,
        options: Dict[str, Any],
        parallel: bool
    ) -> Dict[str, Any]:
        """执行Kill Chain并在结束时更新状态"""
        try:
            _print(f"🔄 开始执行任务列表...", flush=True)
            if parallel:
                results = await self._execute_from_todos_parallel(session_id, target, options)
            else:
                results = await self._execute_from_todos_sequential(session_id, target, options)
            
            await self.state_manager.update_session_state(session_id, {
                "status": "completed",
                "end_time": datetime.now().isoformat(),
                "results": results
            })
            self.logger.info(f"Session {session_id} completed successfully")
            return {
                "success": True,
                "results": results
            }
        except Exception as exc:
            self.logger.error(f"Execution pipeline failed for session {session_id}: {exc}", exc_info=True)
            await self.state_manager.update_session_state(session_id, {
                "status": "error",
                "end_time": datetime.now().isoformat(),
                "error": str(exc)
            })
            return {
                "success": False,
                "error": str(exc)
            }
    
    async def _generate_execution_plan(
        self,
        target: str,
        options: Dict[str, Any],
        session_id: str
    ) -> Dict[str, Any]:
        """
        使用主控LLM生成完整的执行计划
        
        Args:
            target: 目标地址
            options: 测试选项
            session_id: 会话ID
            
        Returns:
            Dict[str, Any]: 执行计划（包含stages和todos）
        """
        try:
            if not self.master_llm:
                raise ValueError("主控LLM未初始化，无法生成执行计划")
            
            # 准备上下文
            context = {
                "environment_state": {},
                "available_tools": ["nmap", "dns_enum", "subdomain_enum", "sql_injection", "cmd_executer"]
            }
            
            # 获取规划提示词
            _print(f"   📝 准备提示词...", flush=True)
            self.logger.info("准备规划提示词...")
            planning_prompt = MasterPrompts.get_planning_prompt(target, options, context)
            system_prompt = MasterPrompts.get_master_system_prompt()
            _print(f"   ✅ 提示词准备完成，系统提示词长度: {len(system_prompt)}, 规划提示词长度: {len(planning_prompt)}", flush=True)
            self.logger.info(f"提示词准备完成，系统提示词长度: {len(system_prompt)}, 规划提示词长度: {len(planning_prompt)}")
            
            # 优化输入长度
            if self._master_model_name:
                optimizer = InputOptimizer(model_name=self._master_model_name)
                system_prompt = optimizer.optimize_input(system_prompt)
                planning_prompt = optimizer.optimize_input(planning_prompt)
            
            # 调用LLM生成计划
            from langchain_core.messages import SystemMessage, HumanMessage
            
            _print(f"   📦 构建消息对象...", flush=True)
            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=planning_prompt)
            ]
            _print(f"   ✅ 消息对象构建完成", flush=True)
            
            # 检查 master_llm 是否已初始化
            if not self.master_llm:
                error_msg = "主控LLM未初始化，无法生成执行计划"
                self.logger.error(error_msg)
                _print(f"   ❌ {error_msg}", flush=True)
                raise ValueError(error_msg)
            
            self.logger.info("调用主控LLM生成执行计划...")
            _print(f"🔄 正在调用主控LLM生成执行计划...", flush=True)
            _print(f"   目标: {target}", flush=True)
            if target == "auto_extract":
                raw_desc = (options or {}).get("raw_description", "")
                if raw_desc:
                    _print(f"   原始描述: {raw_desc[:100]}...", flush=True)
            
            _print(f"   请稍候，LLM正在思考中...", flush=True)
            self.logger.info("开始调用LLM API...")
            
            try:
                # 使用重试机制调用LLM
                async def _invoke_llm():
                    _print(f"   📡 正在发送请求到LLM API...", flush=True)
                    self.logger.info("发送请求到LLM API...")
                    
                    # 确保输出立即刷新
                    import sys
                    sys.stdout.flush()
                    
                    # 添加超时控制（5分钟，因为某些LLM可能响应较慢）
                    response = await asyncio.wait_for(
                        self.master_llm.ainvoke(messages),
                        timeout=300.0  # 5分钟超时
                    )
                    
                    _print(f"   ✅ LLM API响应已接收", flush=True)
                    self.logger.info("LLM API响应已接收")
                    sys.stdout.flush()
                    
                    content = response.content if hasattr(response, 'content') else str(response)
                    _print(f"   ✅ LLM响应接收成功，长度: {len(content)} 字符", flush=True)
                    self.logger.info(f"LLM响应接收成功，长度: {len(content)} 字符")
                    return response
                
                # 使用重试处理器执行
                if self._master_retry_handler:
                    response = await self._master_retry_handler.retry_async(_invoke_llm)
                else:
                    response = await _invoke_llm()
                
                content = response.content if hasattr(response, 'content') else str(response)
                
            except KeyboardInterrupt:
                error_msg = "用户中断LLM调用"
                self.logger.warning(error_msg)
                _print(f"   ⚠️  {error_msg}", flush=True)
                raise
            except asyncio.TimeoutError:
                error_msg = "LLM调用超时（超过5分钟）"
                self.logger.error(error_msg)
                _print(f"   ❌ {error_msg}", flush=True)
                _print(f"   提示: 可能是网络问题或LLM服务响应慢，请检查网络连接", flush=True)
                raise ValueError(error_msg)
            except Exception as e:
                error_msg = f"LLM调用失败: {e}"
                self.logger.error(error_msg, exc_info=True)
                _print(f"   ❌ {error_msg}", flush=True)
                import traceback
                error_trace = traceback.format_exc()
                self.logger.error(error_trace)
                _print(f"   详细错误信息已记录到日志", flush=True)
                _print(f"   错误类型: {type(e).__name__}", flush=True)
                raise
            
            # 解析JSON响应
            # 尝试提取JSON（可能包含markdown代码块）
            _print(f"🔄 正在解析LLM返回的JSON...", flush=True)
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
            else:
                json_str = content
            
            try:
                execution_plan = json.loads(json_str)
                _print(f"✅ JSON解析成功", flush=True)
            except json.JSONDecodeError as e:
                self.logger.error(f"JSON解析失败，原始内容前500字符: {content[:500]}")
                _print(f"❌ JSON解析失败，尝试提取JSON片段...", flush=True)
                # 尝试更宽松的JSON提取
                json_match = re.search(r'\{[\s\S]*"stages"[\s\S]*\}', content, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0)
                    execution_plan = json.loads(json_str)
                    _print(f"✅ 使用备用方法解析JSON成功", flush=True)
                else:
                    raise
            
            # 验证执行计划格式
            if "target" not in execution_plan:
                execution_plan["target"] = target
            if "stages" not in execution_plan:
                raise ValueError("执行计划中缺少stages字段")
            
            self.logger.info(f"执行计划生成成功，包含 {len(execution_plan.get('stages', []))} 个阶段")
            return execution_plan
            
        except json.JSONDecodeError as e:
            self.logger.error(f"解析LLM返回的JSON失败: {e}")
            self.logger.error(f"LLM返回内容: {content[:500]}")
            raise ValueError(f"无法解析执行计划JSON: {e}")
        except Exception as e:
            self.logger.error(f"生成执行计划失败: {e}")
            raise
    
    async def _save_execution_plan_to_todos(
        self,
        execution_plan: Dict[str, Any],
        session_id: str
    ):
        """
        将执行计划保存到TodoManager
        
        Args:
            execution_plan: 执行计划
            session_id: 会话ID
        """
        try:
            all_todos = []
            
            for stage in execution_plan.get("stages", []):
                stage_id = stage.get("id", "")
                stage_type = stage.get("type", "")
                stage_name = stage.get("name", "")
                stage_config = stage.get("config", {})
                stage_todos = stage.get("todos", [])
                
                # 为每个stage的todo创建TodoItem
                for todo in stage_todos:
                    todo_item = {
                        "id": todo.get("id", f"{stage_id}_{len(all_todos)}"),
                        "title": todo.get("name", todo.get("title", "未命名任务")),
                        "description": todo.get("description", ""),
                        "status": "pending",
                        "phase": stage_type,
                        "tool": todo.get("tool"),
                        "priority": todo.get("priority", 0),
                        "dependencies": todo.get("dependencies", []),
                        "estimated_duration": todo.get("estimated_duration", 0),
                        "type": todo.get("type", "generic"),
                        "config": {
                            **stage_config,
                            **todo.get("config", {})
                        },
                        "parent_stage": stage_id
                    }
                    all_todos.append(todo_item)
            
            # 保存到TodoManager
            list_name = f"execution_plan_{session_id}"
            success = await self.todo_manager.create_todo_list(list_name, all_todos)
            
            if success:
                self.logger.info(f"任务列表已保存，共 {len(all_todos)} 个任务")
            else:
                raise ValueError("保存任务列表到TodoManager失败")
                
        except Exception as e:
            self.logger.error(f"保存执行计划到TODO失败: {e}")
            raise
    
    async def _execute_from_todos_sequential(
        self,
        session_id: str,
        target: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        从TodoManager读取任务并顺序执行
        
        核心设计原则：
        1. 主Agent（Master Controller）把控整个流程
        2. 子Agent接收任务并执行工具调用
        3. 子Agent返回结果给主Agent
        4. 主Agent评估结果，决定是否进入下一阶段
        5. 严格遵循 Kill Chain 顺序：侦察 -> 武器化 -> 投递 -> 利用 -> 安装 -> C2 -> 目标行为
        """
        results = []
        
        # 阶段历史记录（用于总结和防止重复）
        stage_history: Dict[str, Dict[str, Any]] = {}
        
        # 全局上下文历史（用于压缩）
        context_history: List[Dict[str, Any]] = []
        
        try:
            # 获取执行计划
            session_state = await self.state_manager.get_session_state(session_id)
            execution_plan = session_state.get("execution_plan", {})
            stages = execution_plan.get("stages", [])
            
            if not stages:
                self.logger.warning("执行计划中没有阶段，使用默认Kill Chain")
                return await self._execute_kill_chain_sequential(session_id, target, options)
            
            # 🔧 严格的阶段顺序定义（Kill Chain 顺序）
            STAGE_ORDER = [
                "reconnaissance",
                "weaponization", 
                "delivery",
                "exploitation",
                "installation",
                "command_control",
                "actions_on_objectives"
            ]
            
            # 🔧 阶段完成状态跟踪
            completed_stages: Dict[str, bool] = {s: False for s in STAGE_ORDER}
            stage_results_summary: Dict[str, str] = {}  # 每个阶段的结果摘要
            
            # 按顺序执行每个阶段
            stage_index = 0
            while stage_index < len(stages):
                stage = stages[stage_index]
                stage_id = stage.get("id", "")
                stage_type = stage.get("type", "").lower()
                stage_name = stage.get("name", "")
                stage_config = stage.get("config", {})
                stage_todos = stage.get("todos", [])
                
                # 🔧 严格的阶段前置检查：确保按顺序执行
                if stage_type in STAGE_ORDER:
                    stage_order_index = STAGE_ORDER.index(stage_type)
                    # 检查前置阶段是否完成
                    for prev_stage in STAGE_ORDER[:stage_order_index]:
                        if not completed_stages.get(prev_stage, False):
                            # 前置阶段未完成，检查是否在stages列表中
                            prev_stage_exists = any(s.get("type", "").lower() == prev_stage for s in stages)
                            if prev_stage_exists:
                                _print(f"⚠️ 阶段 {stage_name} 需要等待前置阶段 {prev_stage} 完成", flush=True)
                                self.logger.warning(f"阶段 {stage_type} 需要等待前置阶段 {prev_stage} 完成")
                                # 跳过当前阶段，让前置阶段先执行
                                # 这种情况不应该发生，因为stages应该是有序的
                                # 但作为安全检查保留
                
                # 阶段重试计数器（最多重试3次）
                stage_retry_count = stage.get("_retry_count", 0)
                max_stage_retries = 3
                
                # 初始化尝试历史（记录已尝试的命令和工具）
                if "_attempt_history" not in stage:
                    stage["_attempt_history"] = []
                
                attempt_history = stage["_attempt_history"]
                
                # 🔧 检查并压缩上下文历史（防止token过长）
                global_context = await self.state_manager.get_global_context(session_id)
                context_size = len(json.dumps(global_context, ensure_ascii=False))
                if context_size > 10000:  # 上下文超过10KB时压缩
                    _print(f"📦 上下文过长 ({context_size} 字符)，正在压缩历史...", flush=True)
                    compressed_context = await self._compress_context_history(
                        session_id, global_context, stage_results_summary
                    )
                    await self.state_manager.update_global_context(session_id, compressed_context)
                    global_context = compressed_context
                    _print(f"✅ 上下文已压缩至 {len(json.dumps(global_context, ensure_ascii=False))} 字符", flush=True)
                
                self.logger.info(f"执行阶段: {stage_name} ({stage_type}), 重试次数: {stage_retry_count}")
                if stage_retry_count > 0:
                    _print(f"🔄 重试阶段: {stage_name} (第{stage_retry_count}次重试)...", flush=True)
                    _print(f"📋 已尝试的方法: {len(attempt_history)} 种", flush=True)
                else:
                    _print(f"🔄 执行阶段: {stage_name}...", flush=True)
                
                # 🔧 显示当前阶段在 Kill Chain 中的位置
                if stage_type in STAGE_ORDER:
                    current_pos = STAGE_ORDER.index(stage_type) + 1
                    total_stages = len(STAGE_ORDER)
                    completed_count = sum(1 for s in STAGE_ORDER if completed_stages.get(s, False))
                    _print(f"📍 Kill Chain 进度: {stage_type} ({current_pos}/{total_stages}), 已完成: {completed_count} 个阶段", flush=True)
                
                # 获取对应的Agent类型
                kill_chain_state = self._map_stage_type_to_kill_chain(stage_type)
                if not kill_chain_state:
                    self.logger.warning(f"无法映射阶段类型: {stage_type}")
                    stage_index += 1
                    continue
                
                agent_type = self.kill_chain_mapping.get(kill_chain_state)
                if not agent_type:
                    self.logger.warning(f"没有对应的Agent类型: {kill_chain_state}")
                    stage_index += 1
                    continue
                
                # 获取Agent Actor
                actor = self.agent_pool.get_actor(agent_type)
                if not actor:
                    self.logger.warning(f"没有可用的Agent Actor: {agent_type}")
                    stage_index += 1
                    continue
                
                # 🔧 在开始新阶段前，清除旧的执行状态并设置正确的Agent名称
                try:
                    from src.agents.base_agent import execution_state
                    # 格式化Agent名称（如 recon_agent -> Recon Agent）
                    agent_display_name = agent_type.value.replace("_", " ").title()
                    execution_state.clear()  # 清除旧状态
                    execution_state.set_current_execution(
                        agent=agent_display_name,
                        tool="",
                        command="",
                        description=f"准备执行 {stage_name}"
                    )
                    execution_state.add_output_line(f"📍 开始阶段: {stage_name}")
                    execution_state.add_output_line(f"🤖 分配给: {agent_display_name}")
                except Exception as e:
                    self.logger.warning(f"清除执行状态失败: {e}")
                
                # 准备执行上下文，包含任务列表
                context = [{
                    "session_id": session_id,
                    "stage": stage_type,
                    "stage_id": stage_id,
                    "stage_config": stage_config,
                    "todos": stage_todos,
                    "global_context": await self.state_manager.get_global_context(session_id)
                }]
                
                # 准备目标信息，包含阶段配置
                target_info = {
                    "target": stage_config.get("target", target),
                    **(options or {}),
                    **stage_config
                }
                
                # 执行Agent（使用执行管理器统一处理）
                _print(f"🔄 将任务和目标发送给 {agent_type.value}...", flush=True)
                _print(f"📋 当前阶段任务: {stage_name}", flush=True)
                if stage_todos:
                    _print(f"   待执行任务数: {len(stage_todos)}", flush=True)
                    for idx, todo in enumerate(stage_todos[:3], 1):
                        todo_name = todo.get("name", todo.get("title", "未命名任务"))
                        todo_id = todo.get("id")
                        _print(f"   {idx}. {todo_name}", flush=True)
                        # 标记任务为进行中
                        if todo_id:
                            await self.todo_manager.mark_todo_started(todo_id)
                
                # 执行Agent，带超时和重试
                max_retries = 2
                retry_count = 0
                result = None
                
                while retry_count < max_retries:
                    try:
                        future = actor.execute.remote(target_info, context)
                        # 设置执行超时（默认10分钟）
                        execution_timeout = stage_config.get("timeout", 600)
                        result = await self.execution_manager.run_ray_get(future, timeout=execution_timeout)
                        break  # 成功，退出重试循环
                    except asyncio.TimeoutError:
                        retry_count += 1
                        if retry_count < max_retries:
                            _print(f"⚠️ 执行超时，正在重试 ({retry_count}/{max_retries})...", flush=True)
                            self.logger.warning(f"Agent {agent_type.value} 执行超时，重试 {retry_count}/{max_retries}")
                        else:
                            result = {
                                "success": False,
                                "error": f"执行超时 ({execution_timeout}秒)",
                                "agent": agent_type.value
                            }
                            _print(f"❌ 执行超时，已达最大重试次数", flush=True)
                    except Exception as e:
                        retry_count += 1
                        error_msg = str(e)
                        self.logger.error(f"Agent {agent_type.value} 执行错误: {error_msg}")
                        if retry_count < max_retries:
                            _print(f"⚠️ 执行错误: {error_msg[:50]}...，正在重试 ({retry_count}/{max_retries})...", flush=True)
                        else:
                            result = {
                                "success": False,
                                "error": error_msg,
                                "agent": agent_type.value
                            }
                            _print(f"❌ 执行失败: {error_msg[:80]}", flush=True)
                
                if result is None:
                    result = {
                        "success": False,
                        "error": "未知执行错误",
                        "agent": agent_type.value
                    }
                
                # 存储结果
                await self.state_manager.put_agent_result(session_id, agent_type.value, result)
                results.append({
                    "stage": stage_type,
                    "stage_id": stage_id,
                    "agent": agent_type.value,
                    "result": result
                })
                
                # 📝 记录本次尝试历史（用于避免重复尝试）
                tools_used = result.get("data", {}).get("tools_used", [])
                command = result.get("data", {}).get("command", "")
                
                # 提取本次执行的有用信息（无论成功失败都可能有用）
                useful_info = self._extract_useful_info(result, stage_type)
                
                attempt_info = {
                    "tools": tools_used,
                    "command": command,
                    "success": result.get("success", False),
                    "error": result.get("error", ""),
                    "useful_info": useful_info,  # 本次收集的有用信息
                    "timestamp": datetime.now().isoformat()
                }
                attempt_history.append(attempt_info)
                self.logger.info(f"记录尝试历史: {attempt_info}")
                
                # 📊 更新阶段信息摘要（累积有用信息）
                # 先获取全局上下文
                global_context = await self.state_manager.get_global_context(session_id)
                stage_info_key = f"{stage_type}_info_summary"
                current_summary = global_context.get(stage_info_key, {
                    "collected_info": [],
                    "tools_tried": [],
                    "total_attempts": 0
                })
                
                # 累积有用信息
                if useful_info and useful_info != "无有用信息":
                    current_summary["collected_info"].append({
                        "attempt": len(attempt_history),
                        "info": useful_info,
                        "tools": tools_used
                    })
                    
                    # 📝 实时输出本次收集的有用信息到日志
                    try:
                        from src.agents.base_agent import execution_state
                        execution_state.add_output_line(f"📊 [步骤 #{len(attempt_history)}] 收集到有用信息: {useful_info}")
                        _print(f"📊 本次执行收集到有用信息: {useful_info}", flush=True)
                    except Exception as e:
                        self.logger.warning(f"输出有用信息失败: {e}")
                
                # 记录已尝试的工具
                for tool in tools_used:
                    if tool not in current_summary["tools_tried"]:
                        current_summary["tools_tried"].append(tool)
                
                current_summary["total_attempts"] = len(attempt_history)
                
                # 更新全局上下文
                await self.state_manager.update_global_context(session_id, {
                    stage_info_key: current_summary
                })
                
                # 📋 显示累积信息摘要
                if current_summary.get("collected_info"):
                    accumulated_count = len(current_summary["collected_info"])
                    try:
                        from src.agents.base_agent import execution_state
                        execution_state.add_output_line(f"📈 当前阶段已累积 {accumulated_count} 条有用信息")
                        _print(f"📈 当前阶段已累积 {accumulated_count} 条有用信息", flush=True)
                    except Exception:
                        pass
                
                # 更新全局上下文（原有逻辑）
                if result.get("success") and result.get("data"):
                    await self._update_global_context(session_id, kill_chain_state, result["data"])
                    
                    # 实时显示结果摘要
                    data = result.get("data", {})
                    if kill_chain_state == KillChainState.RECONNAISSANCE:
                        if "open_ports" in data:
                            ports = data.get("open_ports", [])
                            _print(f"✅ 侦察完成: 发现 {len(ports)} 个开放端口", flush=True)
                        if "services" in data:
                            services = data.get("services", [])
                            _print(f"✅ 侦察完成: 识别 {len(services)} 个服务", flush=True)
                    elif kill_chain_state == KillChainState.WEAPONIZATION:
                        if "payloads" in data:
                            payloads = data.get("payloads", [])
                            _print(f"✅ 武器化完成: 准备 {len(payloads)} 个载荷", flush=True)
                    elif kill_chain_state == KillChainState.EXPLOITATION:
                        if "exploitation_results" in data:
                            exploits = data.get("exploitation_results", [])
                            _print(f"✅ 利用完成: {len(exploits)} 个利用结果", flush=True)
                
                # 更新TODO状态
                for todo in stage_todos:
                    todo_id = todo.get("id")
                    if todo_id:
                        if result.get("success"):
                            await self.todo_manager.mark_todo_completed(todo_id)
                        else:
                            await self.todo_manager.mark_todo_failed(todo_id, result.get("error", "执行失败"))
                
                # 确保所有进行中的任务在阶段完成后被标记为完成或失败
                list_name = f"execution_plan_{session_id}"
                all_todos = await self.todo_manager.get_todo_list(list_name)
                for todo in all_todos:
                    if todo.get("status") == "in_progress" and todo.get("parent_stage") == stage_id:
                        # 如果任务还在进行中但阶段已完成，根据结果更新状态
                        if result.get("success"):
                            await self.todo_manager.mark_todo_completed(todo.get("id"))
                        else:
                            await self.todo_manager.mark_todo_failed(todo.get("id"), result.get("error", "阶段执行失败"))
                
                # 检查阶段是否完成，评估结果决定下一步
                _print(f"📊 正在评估阶段 {stage_name} 的执行结果...", flush=True)
                
                # 📋 显示当前累积信息摘要（评估前）
                global_context = await self.state_manager.get_global_context(session_id)
                stage_info_key = f"{stage_type}_info_summary"
                stage_summary = global_context.get(stage_info_key, {
                    "collected_info": [],
                    "tools_tried": [],
                    "total_attempts": 0
                })
                
                if stage_summary.get("collected_info"):
                    try:
                        from src.agents.base_agent import execution_state
                        execution_state.add_output_line("─" * 60)
                        execution_state.add_output_line("📋 当前阶段累积信息摘要:")
                        for idx, info_item in enumerate(stage_summary["collected_info"], 1):
                            attempt_num = info_item.get("attempt", 0)
                            info = info_item.get("info", "")
                            tools = ", ".join(info_item.get("tools", []))
                            execution_state.add_output_line(f"  {idx}. [尝试 #{attempt_num}] ({tools}): {info}")
                        execution_state.add_output_line("─" * 60)
                        _print(f"📋 当前阶段已收集 {len(stage_summary['collected_info'])} 条有用信息", flush=True)
                    except Exception:
                        pass
                
                # 无论成功还是失败，都使用主Agent LLM评估结果
                evaluation = await self._evaluate_stage_result(
                    session_id=session_id,
                    stage_type=stage_type,
                    stage_name=stage_name,
                    result=result,
                    target=target,
                    attempt_history=attempt_history  # 传递尝试历史
                )
                
                # 📊 显示评估结论
                evaluation_text = evaluation.get("evaluation", "")
                if evaluation_text:
                    try:
                        from src.agents.base_agent import execution_state
                        execution_state.add_output_line(f"🤖 主Agent评估结论: {evaluation_text[:200]}")
                        _print(f"🤖 主Agent评估: {evaluation_text[:150]}...", flush=True)
                    except Exception:
                        pass
                
                if not result.get("success"):
                    error_msg = result.get("error", "执行失败")
                    _print(f"⚠️  阶段 {stage_name} 执行未成功: {error_msg}", flush=True)
                    
                    # 检查是否需要重试
                    if evaluation.get("should_retry") and stage_retry_count < max_stage_retries:
                        retry_reason = evaluation.get("retry_reason", "需要使用其他方法")
                        _print(f"🔄 主Agent评估：{retry_reason}", flush=True)
                        
                        # 动态添加重试任务
                        new_tasks = evaluation.get("new_tasks", [])
                        if new_tasks:
                            await self._add_dynamic_tasks(session_id, stage_id, new_tasks)
                            _print(f"📋 已添加 {len(new_tasks)} 个新任务进行重试", flush=True)
                        
                        # 增加重试计数并继续当前阶段
                        stage["_retry_count"] = stage_retry_count + 1
                        _print(f"🔁 开始第{stage_retry_count + 1}次重试...", flush=True)
                        continue  # 保持stage_index，重试当前阶段
                    
                    elif stage_retry_count >= max_stage_retries:
                        # 已达最大重试次数
                        _print(f"⚠️ 已达最大重试次数({max_stage_retries}次)，跳过当前阶段", flush=True)
                        stage_index += 1  # 移到下一阶段
                        continue
                    
                    elif evaluation.get("can_proceed"):
                        # 虽然失败但可以继续（比如部分信息已足够）
                        _print(f"⚠️ 虽然有失败，但已获取足够信息，继续下一阶段", flush=True)
                        stage_index += 1  # 移到下一阶段
                        continue
                    
                    else:
                        # 无法继续，需要暂停
                        _print(f"⏸️  无法继续执行，暂停等待处理...", flush=True)
                        await self.state_manager.update_session_state(session_id, {
                            "status": "paused",
                            "error": error_msg,
                            "paused_at": datetime.now().isoformat()
                        })
                        break
                else:
                    _print(f"✅ 阶段 {stage_name} 执行完成", flush=True)
                    
                    if evaluation.get("need_more_info") and stage_retry_count < max_stage_retries:
                        # 主Agent认为信息不足，需要继续调用Agent
                        _print(f"🔄 主Agent评估：需要更多信息", flush=True)
                        
                        # 动态添加新任务
                        new_tasks = evaluation.get("new_tasks", [])
                        if new_tasks:
                            await self._add_dynamic_tasks(session_id, stage_id, new_tasks)
                            _print(f"📋 已添加 {len(new_tasks)} 个新任务", flush=True)
                        
                        # 增加计数并继续收集信息
                        stage["_retry_count"] = stage_retry_count + 1
                        continue  # 保持stage_index，继续当前阶段
                    
                    elif evaluation.get("switch_agent"):
                        # 需要切换到其他Agent
                        new_agent_type = evaluation.get("switch_to_agent")
                        _print(f"🔀 主Agent决定切换到 {new_agent_type}", flush=True)
                    
                    # 🔧 阶段完成：更新完成状态和结果摘要
                    if stage_type in STAGE_ORDER:
                        completed_stages[stage_type] = True
                        # 生成阶段结果摘要
                        key_findings = evaluation.get("key_findings", [])
                        if key_findings:
                            stage_results_summary[stage_type] = "; ".join(key_findings[:5])
                        else:
                            stage_results_summary[stage_type] = f"阶段 {stage_name} 已完成"
                        
                        _print(f"✅ 阶段 {stage_name} 评估通过，标记为完成", flush=True)
                        self.logger.info(f"阶段 {stage_type} 完成，结果摘要: {stage_results_summary.get(stage_type, '')[:100]}")
                    
                    # 阶段完成，移动到下一阶段
                    _print(f"✅ 阶段 {stage_name} 评估通过", flush=True)
                    stage_index += 1  # 移到下一阶段
                    
        except Exception as e:
            self.logger.error(f"从TODO执行失败: {e}")
            results.append({
                "success": False,
                "error": str(e)
            })
        
        return results
    
    def _extract_useful_info(self, result: Dict[str, Any], stage_type: str) -> str:
        """
        从执行结果中提取有用信息（无论成功失败）
        
        Args:
            result: Agent执行结果
            stage_type: 阶段类型
            
        Returns:
            str: 有用信息摘要
        """
        useful_info_parts = []
        data = result.get("data", {})
        
        if stage_type == "reconnaissance":
            # 侦察阶段：提取端口、服务、主机信息
            if "hosts" in data:
                for host in data.get("hosts", []):
                    host_state = host.get("state", "unknown")
                    if host_state != "unknown":
                        useful_info_parts.append(f"主机状态: {host_state}")
                    
                    if host.get("ports"):
                        ports = [f"{p.get('port')}/{p.get('protocol', 'tcp')}" for p in host["ports"]]
                        if len(ports) > 10:
                            useful_info_parts.append(f"发现 {len(ports)} 个开放端口: {', '.join(ports[:10])}...")
                        else:
                            useful_info_parts.append(f"发现 {len(ports)} 个开放端口: {', '.join(ports)}")
                    
                    if host.get("services"):
                        services = []
                        for s in host["services"][:10]:
                            service_name = s.get("name", "unknown")
                            service_version = s.get("version", "")
                            if service_version:
                                services.append(f"{service_name}({service_version})")
                            else:
                                services.append(service_name)
                        if len(host["services"]) > 10:
                            useful_info_parts.append(f"发现 {len(host['services'])} 个服务: {', '.join(services)}...")
                        else:
                            useful_info_parts.append(f"发现 {len(host['services'])} 个服务: {', '.join(services)}")
                    
                    if host.get("os"):
                        useful_info_parts.append(f"操作系统: {host['os']}")
            
            # 检查是否有open_ports字段（另一种数据格式）
            if "open_ports" in data:
                ports = data.get("open_ports", [])
                if ports:
                    ports_str = ", ".join([str(p) for p in ports[:10]])
                    if len(ports) > 10:
                        useful_info_parts.append(f"发现 {len(ports)} 个开放端口: {ports_str}...")
                    else:
                        useful_info_parts.append(f"发现 {len(ports)} 个开放端口: {ports_str}")
            
            # 检查是否有services字段（另一种数据格式）
            if "services" in data:
                services = data.get("services", [])
                if services:
                    services_str = ", ".join([s.get("name", "unknown") for s in services[:10]])
                    if len(services) > 10:
                        useful_info_parts.append(f"发现 {len(services)} 个服务: {services_str}...")
                    else:
                        useful_info_parts.append(f"发现 {len(services)} 个服务: {services_str}")
            
            # 即使失败也可能有部分信息
            if not result.get("success"):
                # 检查是否有部分输出
                if data.get("raw_output"):
                    raw = str(data.get("raw_output", ""))[:200]
                    if "host" in raw.lower() or "port" in raw.lower() or "up" in raw.lower():
                        useful_info_parts.append(f"部分输出线索: {raw[:100]}...")
                
                # 检查错误信息中是否有有用线索
                error = result.get("error", "")
                if error and ("timeout" not in error.lower() and "connection refused" not in error.lower()):
                    useful_info_parts.append(f"错误线索: {error[:80]}")
        
        elif stage_type == "weaponization":
            # 武器化阶段：提取漏洞、载荷信息
            if "vulnerabilities" in data:
                vulns = data.get("vulnerabilities", [])
                useful_info_parts.append(f"识别漏洞: {len(vulns)} 个")
            if "payloads" in data:
                payloads = data.get("payloads", [])
                useful_info_parts.append(f"准备载荷: {len(payloads)} 个")
        
        elif stage_type == "exploitation":
            # 利用阶段：提取利用结果
            if "exploitation_results" in data:
                exploits = data.get("exploitation_results", [])
                useful_info_parts.append(f"利用结果: {len(exploits)} 个")
        
        # 通用：提取错误信息（可能包含有用线索）
        if not result.get("success"):
            error = result.get("error", "")
            if error and len(error) < 150:
                useful_info_parts.append(f"错误信息: {error}")
        
        return " | ".join(useful_info_parts) if useful_info_parts else "无有用信息"
    
    async def _evaluate_stage_result(
        self,
        session_id: str,
        stage_type: str,
        stage_name: str,
        result: Dict[str, Any],
        target: str,
        attempt_history: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        使用主Agent LLM评估子Agent执行结果
        决定是否需要更多信息或切换Agent
        
        Args:
            attempt_history: 已尝试的方法历史，用于避免重复
        """
        try:
            # 导入输出解析器
            from .output_parser import output_manager
            
            # 获取全局上下文
            global_context = await self.state_manager.get_global_context(session_id)
            
            # 📊 获取阶段信息摘要（累积的有用信息）
            stage_info_key = f"{stage_type}_info_summary"
            stage_summary = global_context.get(stage_info_key, {
                "collected_info": [],
                "tools_tried": [],
                "total_attempts": 0
            })
            
            # 结构化解析子Agent的输出
            agent_output = result.get("data", {}).get("output", "")
            tools_used = result.get("data", {}).get("tools_used", [])
            
            # 过滤输出，保留有用信息
            filtered_outputs = []
            for tool in tools_used:
                filtered = output_manager.filter_for_llm(tool, agent_output, max_length=1500)
                if filtered:
                    filtered_outputs.append(f"【{tool}输出】\n{filtered}")
            
            filtered_output_text = "\n\n".join(filtered_outputs) if filtered_outputs else agent_output[:2000]
            
            # 获取错误信息（如果有）
            error_msg = result.get("error", "") if not result.get("success") else ""
            
            # 📋 格式化累积信息摘要
            accumulated_info_text = ""
            if stage_summary.get("collected_info"):
                accumulated_info_text = "\n## 📊 已累积的有用信息摘要\n"
                for info_item in stage_summary["collected_info"]:
                    attempt_num = info_item.get("attempt", 0)
                    info = info_item.get("info", "")
                    tools = ", ".join(info_item.get("tools", []))
                    if info and info != "无有用信息":
                        accumulated_info_text += f"尝试 #{attempt_num} ({tools}): {info}\n"
                
                if not accumulated_info_text.endswith("\n"):
                    accumulated_info_text += "\n"
            
            # 格式化尝试历史
            attempt_history_text = ""
            if attempt_history:
                attempt_history_text = "\n## ⚠️ 已尝试的方法历史（必须避免重复）\n"
                for idx, attempt in enumerate(attempt_history, 1):
                    tools_str = ", ".join(attempt.get("tools", []))
                    command_str = attempt.get("command", "")[:100]
                    status = "✅ 成功" if attempt.get("success") else "❌ 失败"
                    useful_info = attempt.get("useful_info", "")
                    attempt_history_text += f"{idx}. 工具: {tools_str}\n"
                    if command_str:
                        attempt_history_text += f"   命令: {command_str}\n"
                    attempt_history_text += f"   结果: {status}\n"
                    if useful_info and useful_info != "无有用信息":
                        attempt_history_text += f"   有用信息: {useful_info}\n"
                    attempt_history_text += "\n"
            
            # 已尝试的工具列表
            tools_tried = stage_summary.get("tools_tried", [])
            tools_tried_text = f"\n## 🔧 已尝试的工具列表\n{', '.join(tools_tried) if tools_tried else '无'}\n\n" if tools_tried else ""
            
            # 构建评估提示
            evaluation_prompt = f"""你是渗透测试的主控Agent，负责评估子Agent的执行结果并决定下一步行动。

## 当前阶段
阶段类型: {stage_type}
阶段名称: {stage_name}
目标: {target}
总尝试次数: {stage_summary.get("total_attempts", 0)}

{tools_tried_text}

{accumulated_info_text}

{attempt_history_text}

## 本次执行结果
执行状态: {"✅ 成功" if result.get("success") else "❌ 失败"}
{"错误信息: " + error_msg if error_msg else ""}
使用的工具: {', '.join(tools_used) if tools_used else '无'}

## 本次子Agent输出（已过滤）
{filtered_output_text}

## 全局上下文（完整信息）
{json.dumps(global_context, ensure_ascii=False, indent=2)[:1500]}

## 请评估并返回JSON格式的决策：
{{
    "evaluation": "对执行结果的详细评估说明",
    "information_sufficient": true/false,  // 当前阶段收集的信息是否足够进入下一阶段
    
    // ===== 失败处理相关 =====
    "should_retry": true/false,  // 如果执行失败，是否应该重试
    "retry_reason": "重试的原因说明",  // 如果should_retry为true，说明原因
    "can_proceed": true/false,  // 虽然失败但是否可以继续（比如已有部分有用信息）
    
    // ===== 成功后续处理 =====
    "need_more_info": true/false,  // 是否需要继续收集更多信息
    "new_tasks": [  // 如果需要重试或需要更多信息，列出新任务
        {{
            "name": "任务名称",
            "description": "任务描述", 
            "tool": "建议使用的工具（如nmap、其他参数等）",
            "parameters": {{}},  // 具体参数
            "priority": 1
        }}
    ],
    "switch_agent": false,  // 是否需要切换到其他Agent
    "switch_to_agent": null,  // 如果需要切换，指定Agent类型
    "key_findings": [  // 关键发现摘要
        "发现1",
        "发现2"
    ],
    "next_stage_ready": true/false  // 是否可以进入下一阶段
}}

## ⚠️ 重要评估标准：

### 🎯 核心原则：主Agent严格把控阶段流转
1. **侦察阶段必须完成才能进入下一阶段**：
   - 必须收集到**开放端口**或**服务信息**才算完成侦察
   - 如果没有发现任何端口/服务，必须继续侦察或使用其他方法
   - **绝对不允许在没有侦察信息的情况下进入武器化阶段**
   
2. **基于累积信息判断**：不要只看单次执行结果，要综合"已累积的有用信息摘要"来判断
3. **即使单次失败，如果累积信息足够，也可以继续**：例如，虽然某次nmap失败，但之前已经收集到端口信息，可以继续
4. **每次重试都要补充新信息**：使用不同的工具或参数，获取之前没有的信息

### 🔴 避免重复尝试（关键！）：
1. **必须检查"已尝试的工具列表"和"已尝试的方法历史"**
2. **每次重试必须使用不同的工具或方法**：
   - 如果已尝试 `nmap`，下次可以：
     * 使用 `masscan`（快速扫描）
     * 使用 `nmap` 但换参数（如 `-Pn`, `-sS`, `-sU`, `-p-`）
     * 使用其他侦察工具（如 `rustscan`, `zmap`）
   - 如果已尝试特定端口范围，换其他范围
   - 如果已尝试TCP扫描，尝试UDP扫描
3. **如果所有合理工具和方法都已尝试，设置 should_retry=false**

### 📊 基于累积信息判断是否可以继续：
1. **侦察阶段**：
   - 如果累积信息包含：开放端口、服务信息、主机状态 → `next_stage_ready=true`
   - 如果只有部分信息（如只有端口但无服务）→ `need_more_info=true`，继续收集
   - 如果完全没有有用信息 → `should_retry=true`，使用不同工具重试
   
2. **武器化阶段**：
   - 如果累积信息包含：漏洞信息、可利用载荷 → `next_stage_ready=true`
   - 如果只有部分信息 → `need_more_info=true`
   
3. **其他阶段**：根据实际情况判断

### 🔄 重试策略（渐进式）：
- **第1次重试**：使用不同的工具或参数（如nmap换参数，或换masscan）
- **第2次重试**：使用更激进的参数或完全不同的工具
- **第3次重试**：尝试边缘情况或特殊方法
- **判断标准**：综合所有累积信息，如果足够就继续，不够就重试
- **绝对不要重复相同的命令或工具！**

### 💡 示例判断逻辑：
- 场景1：nmap失败，但之前masscan已发现端口 → `can_proceed=true`，继续下一阶段
- 场景2：nmap失败，累积信息为空 → `should_retry=true`，使用masscan重试
- 场景3：nmap和masscan都失败，但累积信息显示目标可能离线 → `can_proceed=false`，暂停

请只返回JSON，不要有其他内容。"""

            # 调用主Agent LLM进行评估
            from langchain_core.messages import HumanMessage
            
            # 🔧 使用基本的ainvoke调用，不传递额外参数
            # 参数兼容性已在初始化时处理
            response = await self.master_llm.ainvoke([HumanMessage(content=evaluation_prompt)])
            response_text = response.content if hasattr(response, 'content') else str(response)
            
            # 解析JSON响应
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                evaluation = json.loads(json_match.group(0))
                self.logger.info(f"主Agent评估结果: {evaluation.get('evaluation', '')[:100]}")
                
                # 更新全局上下文中的关键发现
                key_findings = evaluation.get("key_findings", [])
                if key_findings:
                    await self.state_manager.update_global_context(session_id, {
                        f"{stage_type}_findings": key_findings
                    })
                
                return evaluation
            else:
                self.logger.warning(f"无法解析主Agent评估结果: {response_text[:200]}")
                # 🔧 修复：解析失败时，基于累积信息判断
                return self._fallback_evaluation(stage_summary, result, stage_type)
                
        except Exception as e:
            self.logger.error(f"评估阶段结果失败: {e}")
            # 🔧 修复：评估失败时，基于累积信息判断，而不是默认继续
            return self._fallback_evaluation(stage_summary, result, stage_type, error=str(e))
    
    def _fallback_evaluation(
        self,
        stage_summary: Dict[str, Any],
        result: Dict[str, Any],
        stage_type: str,
        error: str = None
    ) -> Dict[str, Any]:
        """
        当LLM评估失败时的回退评估逻辑
        基于累积信息判断是否可以继续，而不是默认继续
        
        Args:
            stage_summary: 阶段信息摘要（累积的有用信息）
            result: Agent执行结果
            stage_type: 阶段类型
            error: 错误信息（如果有）
            
        Returns:
            Dict[str, Any]: 评估结果
        """
        collected_info = stage_summary.get("collected_info", [])
        total_attempts = stage_summary.get("total_attempts", 0)
        
        # 检查是否有有用信息（排除"无有用信息"）
        useful_info_count = sum(
            1 for info in collected_info 
            if info.get("info") and info.get("info") != "无有用信息"
        )
        
        self.logger.info(f"回退评估: 阶段={stage_type}, 累积信息={useful_info_count}条, 尝试次数={total_attempts}")
        
        # 基于阶段类型和累积信息判断
        if stage_type == "reconnaissance":
            # 🔧 侦察阶段：必须有端口或服务信息才能继续
            # 这是最关键的阶段，没有侦察信息绝对不能进入下一阶段
            has_port_info = any(
                "端口" in info.get("info", "") or "port" in info.get("info", "").lower() or
                "发现" in info.get("info", "") and ("个" in info.get("info", "") or "开放" in info.get("info", ""))
                for info in collected_info
            )
            has_service_info = any(
                "服务" in info.get("info", "") or "service" in info.get("info", "").lower()
                for info in collected_info
            )
            has_host_info = any(
                "主机状态" in info.get("info", "") or "host" in info.get("info", "").lower()
                for info in collected_info
            )
            
            # 🔧 更严格的判断：必须有端口或服务信息
            if has_port_info or has_service_info:
                _print(f"📊 回退评估: 侦察阶段已收集到端口/服务信息，可以继续", flush=True)
                return {
                    "evaluation": f"[回退评估] 侦察阶段完成，已收集到{useful_info_count}条有用信息（端口/服务）",
                    "information_sufficient": True,
                    "should_retry": False,
                    "can_proceed": True,
                    "need_more_info": False,
                    "next_stage_ready": True,
                    "key_findings": [info.get("info", "") for info in collected_info if info.get("info") != "无有用信息"],
                    "fallback": True
                }
            elif has_host_info and total_attempts >= 2:
                # 有主机信息但没有端口信息，可能目标被过滤
                _print(f"📊 回退评估: 侦察阶段只有主机信息，目标可能被防火墙过滤", flush=True)
                return {
                    "evaluation": f"[回退评估] 侦察阶段部分完成，有主机信息但无端口信息（可能被过滤）",
                    "information_sufficient": False,
                    "should_retry": True,
                    "retry_reason": "尝试使用其他扫描方法（如-Pn跳过ping、使用UDP扫描等）",
                    "can_proceed": False,
                    "need_more_info": True,
                    "next_stage_ready": False,
                    "new_tasks": [
                        {
                            "name": "绕过防火墙扫描",
                            "description": "使用-Pn参数跳过主机发现，直接扫描端口",
                            "tool": "nmap",
                            "parameters": {"scan_type": "tcp_connect", "skip_host_discovery": True}
                        }
                    ],
                    "fallback": True
                }
            elif total_attempts < 3:
                _print(f"📊 回退评估: 侦察阶段信息严重不足，必须重试 (尝试 {total_attempts}/3)", flush=True)
                _print(f"⚠️ 侦察未完成，不允许进入武器化阶段！", flush=True)
                return {
                    "evaluation": f"[回退评估] 侦察阶段信息严重不足（无端口/服务信息），必须继续侦察",
                    "information_sufficient": False,
                    "should_retry": True,
                    "retry_reason": "没有收集到任何端口或服务信息，无法进行后续阶段",
                    "can_proceed": False,  # 🔧 绝对不允许继续
                    "need_more_info": True,
                    "next_stage_ready": False,  # 🔧 绝对不允许进入下一阶段
                    "fallback": True
                }
            else:
                _print(f"📊 回退评估: 侦察阶段已达最大重试次数且无有效信息，暂停", flush=True)
                _print(f"⏸️ 暂停执行，等待人工干预", flush=True)
                return {
                    "evaluation": f"[回退评估] 侦察阶段已达最大重试次数({total_attempts})且无有效信息，需要人工干预",
                    "information_sufficient": False,
                    "should_retry": False,
                    "can_proceed": False,  # 🔧 绝对不允许继续
                    "need_more_info": False,
                    "next_stage_ready": False,  # 🔧 绝对不允许进入下一阶段
                    "fallback": True
                }
        
        elif stage_type == "weaponization":
            # 武器化阶段：需要依赖侦察阶段的信息
            if useful_info_count == 0 and total_attempts >= 2:
                _print(f"📊 回退评估: 武器化阶段无可用信息，暂停", flush=True)
                return {
                    "evaluation": f"[回退评估] 武器化阶段缺少必要的侦察信息，无法继续",
                    "information_sufficient": False,
                    "should_retry": False,
                    "can_proceed": False,
                    "need_more_info": False,
                    "next_stage_ready": False,
                    "fallback": True
                }
        
        # 默认：如果有有用信息就继续，否则重试（最多3次）
        if useful_info_count > 0:
            return {
                "evaluation": f"[回退评估] 已收集到{useful_info_count}条有用信息，可以继续",
                "information_sufficient": True,
                "should_retry": False,
                "can_proceed": True,
                "need_more_info": False,
                "next_stage_ready": True,
                "fallback": True
            }
        elif total_attempts < 3:
            return {
                "evaluation": f"[回退评估] 信息不足，需要重试",
                "information_sufficient": False,
                "should_retry": True,
                "retry_reason": "累积信息不足",
                "can_proceed": False,
                "need_more_info": True,
                "next_stage_ready": False,
                "fallback": True
            }
        else:
            return {
                "evaluation": f"[回退评估] 已达最大重试次数，暂停等待人工干预",
                "information_sufficient": False,
                "should_retry": False,
                "can_proceed": False,
                "need_more_info": False,
                "next_stage_ready": False,
                "fallback": True
            }
    
    async def _compress_context_history(
        self,
        session_id: str,
        global_context: Dict[str, Any],
        stage_results_summary: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        压缩上下文历史，防止token过长
        
        策略：
        1. 保留关键信息（目标、发现的服务、漏洞等）
        2. 将详细的执行历史压缩为摘要
        3. 使用LLM生成简洁的历史总结
        
        Args:
            session_id: 会话ID
            global_context: 当前全局上下文
            stage_results_summary: 各阶段结果摘要
            
        Returns:
            Dict[str, Any]: 压缩后的上下文
        """
        try:
            # 保留核心信息
            compressed = {
                "target": global_context.get("target", ""),
                "discovered_services": [],  # 只保留关键服务
                "identified_vulnerabilities": [],  # 只保留关键漏洞
                "current_access_level": global_context.get("current_access_level", "none"),
                "_compressed": True,
                "_compression_time": datetime.now().isoformat()
            }
            
            # 压缩发现的服务（只保留关键信息）
            services = global_context.get("discovered_services", [])
            if services:
                # 只保留每个服务的名称、端口和版本
                compressed_services = []
                for svc in services[:20]:  # 最多保留20个服务
                    if isinstance(svc, dict):
                        compressed_services.append({
                            "name": svc.get("name", "unknown"),
                            "port": svc.get("port", ""),
                            "version": svc.get("version", "")
                        })
                    else:
                        compressed_services.append(str(svc))
                compressed["discovered_services"] = compressed_services
            
            # 压缩漏洞信息
            vulns = global_context.get("identified_vulnerabilities", [])
            if vulns:
                compressed_vulns = []
                for vuln in vulns[:10]:  # 最多保留10个漏洞
                    if isinstance(vuln, dict):
                        compressed_vulns.append({
                            "name": vuln.get("name", "unknown"),
                            "severity": vuln.get("severity", "unknown"),
                            "cve": vuln.get("cve", "")
                        })
                    else:
                        compressed_vulns.append(str(vuln))
                compressed["identified_vulnerabilities"] = compressed_vulns
            
            # 添加阶段结果摘要
            compressed["stage_summaries"] = stage_results_summary
            
            # 使用LLM生成历史总结（如果上下文非常大）
            original_size = len(json.dumps(global_context, ensure_ascii=False))
            if original_size > 20000 and self.master_llm:  # 超过20KB才使用LLM总结
                try:
                    from langchain_core.messages import HumanMessage
                    
                    summary_prompt = f"""请将以下渗透测试执行上下文压缩为简洁的摘要，保留关键发现：

上下文内容（部分）：
{json.dumps(global_context, ensure_ascii=False)[:5000]}

请返回JSON格式的摘要：
{{
    "key_findings": ["关键发现1", "关键发现2"],
    "important_services": ["重要服务1", "重要服务2"],
    "important_vulnerabilities": ["重要漏洞1"],
    "execution_progress": "执行进度描述"
}}"""
                    
                    response = await self.master_llm.ainvoke([HumanMessage(content=summary_prompt)])
                    response_text = response.content if hasattr(response, 'content') else str(response)
                    
                    # 解析LLM响应
                    json_match = re.search(r'\{[\s\S]*\}', response_text)
                    if json_match:
                        llm_summary = json.loads(json_match.group(0))
                        compressed["_llm_summary"] = llm_summary
                        
                except Exception as e:
                    self.logger.warning(f"LLM历史总结失败: {e}")
            
            self.logger.info(f"上下文压缩完成: {original_size} -> {len(json.dumps(compressed, ensure_ascii=False))} 字符")
            return compressed
            
        except Exception as e:
            self.logger.error(f"上下文压缩失败: {e}")
            # 返回简化的上下文
            return {
                "target": global_context.get("target", ""),
                "discovered_services": global_context.get("discovered_services", [])[:10],
                "identified_vulnerabilities": global_context.get("identified_vulnerabilities", [])[:5],
                "current_access_level": global_context.get("current_access_level", "none"),
                "_compressed": True,
                "_compression_error": str(e)
            }
    
    async def _add_dynamic_tasks(
        self,
        session_id: str,
        stage_id: str,
        new_tasks: List[Dict[str, Any]]
    ):
        """动态添加新任务到当前阶段"""
        try:
            list_name = f"execution_plan_{session_id}"
            
            for idx, task in enumerate(new_tasks):
                task_id = f"{stage_id}_dynamic_{idx}_{datetime.now().strftime('%H%M%S')}"
                todo_item = {
                    "id": task_id,
                    "title": task.get("name", "动态任务"),
                    "description": task.get("description", ""),
                    "status": "pending",
                    "tool": task.get("tool"),
                    "priority": task.get("priority", 0),
                    "parent_stage": stage_id,
                    "dynamic": True  # 标记为动态添加的任务
                }
                
                # 添加到TODO列表
                await self.todo_manager.add_todo(list_name, todo_item)
                self.logger.info(f"动态添加任务: {task.get('name')}")
                
        except Exception as e:
            self.logger.error(f"添加动态任务失败: {e}")
    
    async def _execute_from_todos_parallel(
        self,
        session_id: str,
        target: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """从TodoManager读取任务并并行执行（部分阶段）"""
        # 暂时使用顺序执行，后续可以优化为真正的并行
        return await self._execute_from_todos_sequential(session_id, target, options)
    
    def _map_stage_type_to_kill_chain(self, stage_type: str) -> Optional[KillChainState]:
        """将阶段类型映射到Kill Chain状态"""
        mapping = {
            "reconnaissance": KillChainState.RECONNAISSANCE,
            "weaponization": KillChainState.WEAPONIZATION,
            "delivery": KillChainState.DELIVERY,
            "exploitation": KillChainState.EXPLOITATION,
            "installation": KillChainState.INSTALLATION,
            "command_control": KillChainState.COMMAND_CONTROL,
            "actions_on_objectives": KillChainState.ACTIONS_ON_OBJECTIVES
        }
        return mapping.get(stage_type.lower())
    
    async def _execute_kill_chain_sequential(
        self,
        session_id: str,
        target: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """顺序执行Kill Chain"""
        results = []
        
        # Kill Chain阶段
        stages = [
            (KillChainState.RECONNAISSANCE, "侦察阶段"),
            (KillChainState.WEAPONIZATION, "武器化阶段"),
            (KillChainState.DELIVERY, "投递阶段"),
            (KillChainState.EXPLOITATION, "利用阶段"),
            (KillChainState.INSTALLATION, "安装阶段"),
            (KillChainState.COMMAND_CONTROL, "命令控制阶段"),
            (KillChainState.ACTIONS_ON_OBJECTIVES, "目标行为阶段")
        ]
        
        for stage, stage_name in stages:
            try:
                self.logger.info(f"Executing stage: {stage_name}")
                
                # 获取对应的Agent类型
                agent_type = self.kill_chain_mapping.get(stage)
                if not agent_type:
                    self.logger.warning(f"No agent for stage: {stage}")
                    continue
                
                # 获取Agent Actor
                actor = self.agent_pool.get_actor(agent_type)
                if not actor:
                    self.logger.warning(f"No actor for agent type: {agent_type}")
                    continue
                
                # 准备执行上下文
                context = [{
                    "session_id": session_id,
                    "stage": stage.value,
                    "global_context": await self.state_manager.get_global_context(session_id)
                }]
                
                # 执行Agent（使用执行管理器统一处理）
                _print(f"🔄 执行 {stage_name}...", flush=True)
                future = actor.execute.remote(
                    {"target": target, **(options or {})},
                    context
                )
                result = await self.execution_manager.run_ray_get(future)
                
                # 存储结果
                await self.state_manager.put_agent_result(session_id, agent_type.value, result)
                results.append({
                    "stage": stage.value,
                    "agent": agent_type.value,
                    "result": result
                })
                
                # 更新全局上下文
                if result.get("success") and result.get("data"):
                    await self._update_global_context(session_id, stage, result["data"])
                
                # 检查是否应该继续
                if not result.get("success") and not options.get("safe_mode", True):
                    self.logger.warning(f"Stage {stage_name} failed, stopping execution")
                    break
                
            except Exception as e:
                self.logger.error(f"Stage {stage_name} execution error: {e}")
                results.append({
                    "stage": stage.value,
                    "success": False,
                    "error": str(e)
                })
        
        return results
    
    async def _execute_kill_chain_parallel(
        self,
        session_id: str,
        target: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        并行执行Kill Chain（部分阶段可以并行）
        
        策略：
        1. 侦察阶段（串行）
        2. 武器化和投递（可以并行准备）
        3. 利用阶段（串行）
        4. 安装和C2建立（可以并行）
        5. 目标行为（串行）
        """
        results = []
        
        try:
            # 阶段1: 侦察（必须串行）
            recon_result = await self._execute_stage(
                session_id,
                target,
                options,
                KillChainState.RECONNAISSANCE,
                AgentType.RECON_AGENT
            )
            results.append(recon_result)
            
            if not recon_result["result"].get("success"):
                return results
            
            # 阶段2: 武器化和投递（并行）
            parallel_tasks = [
                {
                    "agent_type": AgentType.WEAPONIZE_AGENT,
                    "target_info": {"target": target, **(options or {})},
                    "context": [{"session_id": session_id, "stage": KillChainState.WEAPONIZATION.value}]
                },
                {
                    "agent_type": AgentType.DELIVERY_AGENT,
                    "target_info": {"target": target, **(options or {})},
                    "context": [{"session_id": session_id, "stage": KillChainState.DELIVERY.value}]
                }
            ]
            
            parallel_results = await self.agent_pool.execute_parallel(parallel_tasks)
            for r in parallel_results:
                results.append({"stage": "parallel", "result": r})
            
            # 阶段3: 利用（串行）
            exploit_result = await self._execute_stage(
                session_id,
                target,
                options,
                KillChainState.EXPLOITATION,
                AgentType.EXPLOIT_AGENT
            )
            results.append(exploit_result)
            
            # 继续其他阶段...
            
        except Exception as e:
            self.logger.error(f"Parallel execution error: {e}")
        
        return results
    
    async def _execute_stage(
        self,
        session_id: str,
        target: str,
        options: Dict[str, Any],
        stage: KillChainState,
        agent_type: AgentType
    ) -> Dict[str, Any]:
        """执行单个阶段"""
        actor = self.agent_pool.get_actor(agent_type)
        if not actor:
            return {
                "stage": stage.value,
                "agent": agent_type.value,
                "success": False,
                "error": "Actor not found"
            }
        
        context = [{
            "session_id": session_id,
            "stage": stage.value,
            "global_context": await self.state_manager.get_global_context(session_id)
        }]
        
        _print(f"🔄 执行阶段: {stage.value}...", flush=True)
        future = actor.execute.remote(
            {"target": target, **(options or {})},
            context
        )
        result = await self.execution_manager.run_ray_get(future)
        
        await self.state_manager.put_agent_result(session_id, agent_type.value, result)
        
        if result.get("success") and result.get("data"):
            await self._update_global_context(session_id, stage, result["data"])
        
        return {
            "stage": stage.value,
            "agent": agent_type.value,
            "result": result
        }
    
    async def _update_global_context(
        self,
        session_id: str,
        stage: KillChainState,
        data: Dict[str, Any]
    ):
        """更新全局上下文"""
        updates = {}
        
        if stage == KillChainState.RECONNAISSANCE:
            if "services" in data:
                updates["discovered_services"] = data["services"]
            if "vulnerabilities" in data:
                updates["identified_vulnerabilities"] = data["vulnerabilities"]
        elif stage == KillChainState.EXPLOITATION:
            if "exploitation_results" in data:
                updates["exploitation_results"] = data["exploitation_results"]
        
        if updates:
            await self.state_manager.update_global_context(session_id, updates)
    
    async def get_session_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取会话状态"""
        return await self.state_manager.get_session_state(session_id)
    
    async def list_sessions(self) -> List[str]:
        """列出所有会话"""
        return await self.state_manager.list_sessions()
    
    async def get_current_executing_task(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        获取当前正在执行的任务
        
        Args:
            session_id: 会话ID
            
        Returns:
            Dict[str, Any]: 当前执行的任务信息，如果没有则返回None
        """
        try:
            # 获取会话状态
            session_state = await self.state_manager.get_session_state(session_id)
            if not session_state:
                return None
            
            # 获取所有进行中的任务
            list_name = f"execution_plan_{session_id}"
            all_todos = await self.todo_manager.get_todo_list(list_name)
            in_progress_todos = [todo for todo in all_todos if todo.get("status") == "in_progress"]
            
            if in_progress_todos:
                # 返回第一个进行中的任务（通常只有一个）
                current_todo = in_progress_todos[0]
                return {
                    "todo_id": current_todo.get("id"),
                    "title": current_todo.get("title"),
                    "description": current_todo.get("description"),
                    "phase": current_todo.get("phase"),
                    "tool": current_todo.get("tool"),
                    "config": current_todo.get("config", {}),
                    "started_at": current_todo.get("updated_at")
                }
            
            return None
        except Exception as e:
            self.logger.error(f"获取当前执行任务失败: {e}")
            return None
    
    async def get_all_tasks(self, session_id: str) -> Dict[str, Any]:
        """
        获取所有任务列表
        
        Args:
            session_id: 会话ID
            
        Returns:
            Dict[str, Any]: 包含所有任务的状态信息
        """
        try:
            list_name = f"execution_plan_{session_id}"
            all_todos = await self.todo_manager.get_todo_list(list_name)
            progress = await self.todo_manager.get_progress(list_name)
            
            # 按状态分组
            tasks_by_status = {
                "pending": [],
                "in_progress": [],
                "completed": [],
                "failed": [],
                "cancelled": []
            }
            
            for todo in all_todos:
                status = todo.get("status", "pending")
                if status in tasks_by_status:
                    tasks_by_status[status].append({
                        "id": todo.get("id"),
                        "title": todo.get("title"),
                        "description": todo.get("description"),
                        "phase": todo.get("phase"),
                        "tool": todo.get("tool"),
                        "priority": todo.get("priority", 0)
                    })
            
            return {
                "progress": progress,
                "tasks_by_status": tasks_by_status,
                "total_tasks": len(all_todos)
            }
        except Exception as e:
            self.logger.error(f"获取任务列表失败: {e}")
            return {
                "progress": {},
                "tasks_by_status": {},
                "total_tasks": 0
            }
    
    async def interrupt_and_replan(
        self,
        session_id: str,
        additional_info: str
    ) -> Dict[str, Any]:
        """
        中断当前执行并重新规划
        
        Args:
            session_id: 会话ID
            additional_info: 用户补充的信息
            
        Returns:
            Dict[str, Any]: 重新规划的结果
        """
        try:
            # 1. 暂停当前会话
            await self.state_manager.update_session_state(session_id, {
                "status": "paused",
                "paused_at": datetime.now().isoformat(),
                "additional_info": additional_info
            })
            
            # 2. 获取当前会话状态
            session_state = await self.state_manager.get_session_state(session_id)
            original_target = session_state.get("target", "")
            original_options = session_state.get("options", {})
            
            # 3. 合并原始描述和补充信息
            original_description = original_options.get("raw_description", "")
            combined_description = f"{original_description}\n\n补充信息: {additional_info}"
            
            # 4. 更新选项
            new_options = {
                **original_options,
                "raw_description": combined_description
            }
            
            # 5. 重新生成执行计划
            _print(f"🔄 根据补充信息重新生成执行计划...", flush=True)
            new_execution_plan = await self._generate_execution_plan(
                "auto_extract",
                new_options,
                session_id
            )
            
            # 6. 更新TODO列表
            await self._save_execution_plan_to_todos(new_execution_plan, session_id)
            
            # 7. 更新会话状态
            await self.state_manager.update_session_state(session_id, {
                "status": "ready",
                "execution_plan": new_execution_plan,
                "options": new_options
            })
            
            _print(f"✅ 重新规划完成，共 {len(new_execution_plan.get('stages', []))} 个阶段", flush=True)
            
            return {
                "success": True,
                "execution_plan": new_execution_plan,
                "message": "重新规划完成"
            }
            
        except Exception as e:
            self.logger.error(f"中断和重新规划失败: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def shutdown(self):
        """关闭Ray和所有资源"""
        for session_id, task in list(self.running_sessions.items()):
            if not task.done():
                task.cancel()
            self.running_sessions.pop(session_id, None)
        self.agent_pool.shutdown()
        # Ray 关闭由执行管理器统一管理
        self.logger.info("Ray Master Controller shutdown")
