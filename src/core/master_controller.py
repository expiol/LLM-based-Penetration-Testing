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
            
            if not api_key:
                self.logger.warning("未配置主控LLM API Key")
                print("⚠️  警告：未配置主控LLM API Key", flush=True)
                return
            
            # 创建 ChatOpenAI 实例
            kwargs = {
                "model": model_name,
                "temperature": llm_config.get("temperature", 0.7),
                "max_tokens": llm_config.get("max_tokens", 4096),
                "api_key": api_key
            }
            
            if base_url:
                kwargs["base_url"] = base_url
            
            self.master_llm = ChatOpenAI(**kwargs)
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
                "available_tools": ["nmap", "dns_enum", "sql_injection", "cmd_executer"]
            }
            
            # 获取规划提示词
            _print(f"   📝 准备提示词...", flush=True)
            self.logger.info("准备规划提示词...")
            planning_prompt = MasterPrompts.get_planning_prompt(target, options, context)
            system_prompt = MasterPrompts.get_master_system_prompt()
            _print(f"   ✅ 提示词准备完成，系统提示词长度: {len(system_prompt)}, 规划提示词长度: {len(planning_prompt)}", flush=True)
            self.logger.info(f"提示词准备完成，系统提示词长度: {len(system_prompt)}, 规划提示词长度: {len(planning_prompt)}")
            
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
                # 添加超时控制（5分钟，因为某些LLM可能响应较慢）
                try:
                    _print(f"   📡 正在发送请求到LLM API...", flush=True)
                    self.logger.info("发送请求到LLM API...")
                    
                    # 确保输出立即刷新
                    import sys
                    sys.stdout.flush()
                    
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
                except KeyboardInterrupt:
                    error_msg = "用户中断LLM调用"
                    self.logger.warning(error_msg)
                    _print(f"   ⚠️  {error_msg}", flush=True)
                    raise
            except asyncio.TimeoutError:
                error_msg = "LLM调用超时（超过2分钟）"
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
        """从TodoManager读取任务并顺序执行"""
        results = []
        
        try:
            # 获取执行计划
            session_state = await self.state_manager.get_session_state(session_id)
            execution_plan = session_state.get("execution_plan", {})
            stages = execution_plan.get("stages", [])
            
            if not stages:
                self.logger.warning("执行计划中没有阶段，使用默认Kill Chain")
                return await self._execute_kill_chain_sequential(session_id, target, options)
            
            # 按顺序执行每个阶段
            for stage in stages:
                stage_id = stage.get("id", "")
                stage_type = stage.get("type", "")
                stage_name = stage.get("name", "")
                stage_config = stage.get("config", {})
                stage_todos = stage.get("todos", [])
                
                self.logger.info(f"执行阶段: {stage_name} ({stage_type})")
                _print(f"🔄 执行阶段: {stage_name}...", flush=True)
                
                # 获取对应的Agent类型
                kill_chain_state = self._map_stage_type_to_kill_chain(stage_type)
                if not kill_chain_state:
                    self.logger.warning(f"无法映射阶段类型: {stage_type}")
                    continue
                
                agent_type = self.kill_chain_mapping.get(kill_chain_state)
                if not agent_type:
                    self.logger.warning(f"没有对应的Agent类型: {kill_chain_state}")
                    continue
                
                # 获取Agent Actor
                actor = self.agent_pool.get_actor(agent_type)
                if not actor:
                    self.logger.warning(f"没有可用的Agent Actor: {agent_type}")
                    continue
                
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
                
                # 更新全局上下文
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
                
                # 检查阶段是否完成，如果信息不足，暂停并请求更多信息
                if not result.get("success"):
                    error_msg = result.get("error", "执行失败")
                    print(f"⚠️  阶段 {stage_name} 执行失败: {error_msg}", flush=True)
                    
                    # 如果是信息不足，暂停并等待用户补充
                    if "信息不足" in error_msg or "需要更多信息" in error_msg or "insufficient" in error_msg.lower():
                        print(f"⏸️  信息收集不足，暂停执行等待补充信息...", flush=True)
                        await self.state_manager.update_session_state(session_id, {
                            "status": "paused",
                            "error": error_msg,
                            "paused_at": datetime.now().isoformat()
                        })
                        # 不继续执行，等待用户补充信息
                        break
                    
                    # 如果安全模式，继续执行；否则停止
                    if not options.get("safe_mode", True):
                        self.logger.warning(f"阶段 {stage_name} 失败，停止执行")
                        break
                else:
                    _print(f"✅ 阶段 {stage_name} 执行完成，正在评估结果...", flush=True)
                    
                    # 使用主Agent LLM评估子Agent执行结果
                    evaluation = await self._evaluate_stage_result(
                        session_id=session_id,
                        stage_type=stage_type,
                        stage_name=stage_name,
                        result=result,
                        target=target
                    )
                    
                    if evaluation.get("need_more_info"):
                        # 主Agent认为信息不足，需要继续调用Agent
                        _print(f"🔄 主Agent评估：信息不足，需要补充执行", flush=True)
                        
                        # 动态添加新任务
                        new_tasks = evaluation.get("new_tasks", [])
                        if new_tasks:
                            await self._add_dynamic_tasks(session_id, stage_id, new_tasks)
                            _print(f"📋 已添加 {len(new_tasks)} 个新任务", flush=True)
                            
                            # 继续执行新任务（递归调用当前阶段）
                            continue
                    
                    elif evaluation.get("switch_agent"):
                        # 需要切换到其他Agent
                        new_agent_type = evaluation.get("switch_to_agent")
                        _print(f"🔀 主Agent决定切换到 {new_agent_type}", flush=True)
                        # 这里可以添加切换Agent的逻辑
                    
                    else:
                        # 阶段完成，继续下一阶段
                        _print(f"✅ 阶段 {stage_name} 评估通过", flush=True)
                    
        except Exception as e:
            self.logger.error(f"从TODO执行失败: {e}")
            results.append({
                "success": False,
                "error": str(e)
            })
        
        return results
    
    async def _evaluate_stage_result(
        self,
        session_id: str,
        stage_type: str,
        stage_name: str,
        result: Dict[str, Any],
        target: str
    ) -> Dict[str, Any]:
        """
        使用主Agent LLM评估子Agent执行结果
        决定是否需要更多信息或切换Agent
        """
        try:
            # 导入输出解析器
            from .output_parser import output_manager
            
            # 获取全局上下文
            global_context = await self.state_manager.get_global_context(session_id)
            
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
            
            # 构建评估提示
            evaluation_prompt = f"""你是渗透测试的主控Agent，负责评估子Agent的执行结果并决定下一步行动。

## 当前阶段
阶段类型: {stage_type}
阶段名称: {stage_name}
目标: {target}

## 子Agent执行结果
执行状态: {"成功" if result.get("success") else "失败"}
使用的工具: {', '.join(tools_used) if tools_used else '无'}

## 子Agent输出（已过滤）
{filtered_output_text}

## 当前已收集的信息
{json.dumps(global_context, ensure_ascii=False, indent=2)[:1500]}

## 请评估并返回JSON格式的决策：
{{
    "evaluation": "对执行结果的评估说明",
    "information_sufficient": true/false,  // 当前阶段收集的信息是否足够进入下一阶段
    "need_more_info": true/false,  // 是否需要继续收集信息
    "new_tasks": [  // 如果需要更多信息，列出新任务
        {{
            "name": "任务名称",
            "description": "任务描述",
            "tool": "建议使用的工具",
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

评估标准：
1. 侦察阶段：至少需要发现开放端口和服务信息
2. 武器化阶段：需要识别可利用的漏洞
3. 其他阶段：根据实际情况判断

请只返回JSON，不要有其他内容。"""

            # 调用主Agent LLM进行评估
            from langchain_core.messages import HumanMessage
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
                return {"need_more_info": False, "next_stage_ready": True}
                
        except Exception as e:
            self.logger.error(f"评估阶段结果失败: {e}")
            # 评估失败时默认继续
            return {"need_more_info": False, "next_stage_ready": True, "error": str(e)}
    
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
