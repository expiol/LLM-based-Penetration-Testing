"""
基于Ray的Master Controller
使用Ray进行分布式任务调度和状态管理
"""
import asyncio
import logging
import json
import re
from typing import Any, Dict, List, Optional
from datetime import datetime
import ray

from ..orchestrator.states import KillChainState, AgentType
from ..ray_integration.ray_agent_actor import RayAgentPool
from ..ray_integration.ray_state_manager import RayStateManager
from ..core.todo_manager import TodoManager
from ..prompts.master_prompts import MasterPrompts

logger = logging.getLogger(__name__)


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
        """初始化主控LLM"""
        try:
            from langchain_openai import ChatOpenAI
            import os
            from pathlib import Path
            
            # 从配置读取LLM设置
            llm_config = self.config.get("llm_models", {}).get("master_model", {})
            if not llm_config:
                llm_config = self.config.get("master_model", {})
            
            # 尝试从 llm_runtime.json 读取 API Key
            api_key = llm_config.get("api_key")
            base_url = llm_config.get("base_url")
            
            if not api_key:
                # 尝试从环境变量读取
                api_key = os.getenv("OPENAI_API_KEY")
            
            if not api_key:
                # 尝试从 llm_runtime.json 读取
                try:
                    runtime_config_path = Path(__file__).parent.parent.parent / "configs" / "llm_runtime.json"
                    if runtime_config_path.exists():
                        with open(runtime_config_path) as f:
                            runtime_config = json.load(f)
                            api_key = runtime_config.get("api_key")
                            
                            # 构建 base_url
                            if not base_url and runtime_config.get("host"):
                                protocol = runtime_config.get("protocol", "https")
                                host = runtime_config.get("host")
                                port = runtime_config.get("port", 443)
                                base_url = f"{protocol}://{host}:{port}/v1"
                            
                            # 如果配置中没有model_name，从runtime_config读取
                            if not llm_config.get("model_name") and not llm_config.get("model"):
                                model_name = runtime_config.get("model_name")
                                if model_name:
                                    llm_config["model_name"] = model_name
                except Exception as e:
                    self.logger.warning(f"Failed to read llm_runtime.json: {e}")
            
            if not api_key:
                self.logger.warning("未配置 OpenAI API Key，主控LLM将无法使用")
                print("⚠️  警告：未配置 OpenAI API Key，主控LLM将无法使用", flush=True)
                return
            
            # 创建 ChatOpenAI 实例
            model_name = llm_config.get("model_name") or llm_config.get("model", "gpt-4")
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
            print(f"✅ 主控LLM初始化成功 - Model: {model_name}", flush=True)
            
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
            
            print(f"\n{'=' * 72}", flush=True)
            print(f"🔄 创建会话: {session_id}", flush=True)
            self.logger.info(f"Creating session: {session_id}")
            
            # 初始化TODO管理器
            print(f"🔄 初始化TODO管理器...", flush=True)
            await self.todo_manager.initialize()
            print(f"✅ TODO管理器初始化完成", flush=True)
            
            # 如果target是"auto_extract"，使用原始描述
            raw_description = (options or {}).get("raw_description", "")
            if target == "auto_extract" and raw_description:
                print(f"📝 使用原始描述，让主控LLM自动提取目标: {raw_description[:50]}...", flush=True)
            
            # 初始化会话状态
            print(f"🔄 初始化会话状态...", flush=True)
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
            print(f"🔄 初始化全局上下文...", flush=True)
            await self.state_manager.put_global_context(session_id, {
                "target": target if target != "auto_extract" else "",
                "discovered_services": [],
                "identified_vulnerabilities": [],
                "exploitation_results": [],
                "current_access_level": "none"
            })
            
            # 步骤1: 生成完整的任务列表（LLM会提取目标并生成计划）
            print(f"🔄 正在调用主控LLM生成完整的任务列表...", flush=True)
            if target == "auto_extract":
                raw_desc = (options or {}).get("raw_description", "")
                print(f"   主控LLM将自动从描述中提取目标并生成执行计划", flush=True)
                if raw_desc:
                    print(f"   原始描述: {raw_desc[:100]}...", flush=True)
            print(f"   开始调用LLM API...", flush=True)
            try:
                execution_plan = await self._generate_execution_plan(target, options or {}, session_id)
                print(f"   ✅ 执行计划生成完成", flush=True)
            except Exception as e:
                print(f"   ❌ 执行计划生成失败: {e}", flush=True)
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
                    print(f"✅ 主控LLM已提取目标: {final_target}", flush=True)
                else:
                    print(f"ℹ️ 主控LLM规范化目标: {final_target}", flush=True)
            
            await self.state_manager.update_session_state(session_id, {
                "target": final_target
            })
            await self.state_manager.update_global_context(session_id, {
                "target": final_target
            })
            
            # 步骤2: 将任务列表保存到TodoManager
            print(f"🔄 正在保存任务列表到TodoManager...", flush=True)
            await self._save_execution_plan_to_todos(execution_plan, session_id)
            
            # 更新会话状态，保存执行计划
            await self.state_manager.update_session_state(session_id, {
                "status": "running",
                "execution_plan": execution_plan,
                "target": final_target
            })
            
            print(f"✅ 任务列表生成完成，共 {len(execution_plan.get('stages', []))} 个阶段", flush=True)
            self.logger.info(f"Execution plan generated - {len(execution_plan.get('stages', []))} stages, target: {final_target}")
            
            # 步骤3: 根据模式启动执行
            if async_mode:
                print("▶️ 会话进入异步执行模式，可实时查看执行状态", flush=True)
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
            print(f"🔄 开始执行任务列表...", flush=True)
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
            print(f"   📝 准备提示词...", flush=True)
            self.logger.info("准备规划提示词...")
            planning_prompt = MasterPrompts.get_planning_prompt(target, options, context)
            system_prompt = MasterPrompts.get_master_system_prompt()
            print(f"   ✅ 提示词准备完成，系统提示词长度: {len(system_prompt)}, 规划提示词长度: {len(planning_prompt)}", flush=True)
            self.logger.info(f"提示词准备完成，系统提示词长度: {len(system_prompt)}, 规划提示词长度: {len(planning_prompt)}")
            
            # 调用LLM生成计划
            from langchain_core.messages import SystemMessage, HumanMessage
            
            print(f"   📦 构建消息对象...", flush=True)
            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=planning_prompt)
            ]
            print(f"   ✅ 消息对象构建完成", flush=True)
            
            # 检查 master_llm 是否已初始化
            if not self.master_llm:
                error_msg = "主控LLM未初始化，无法生成执行计划"
                self.logger.error(error_msg)
                print(f"   ❌ {error_msg}", flush=True)
                raise ValueError(error_msg)
            
            self.logger.info("调用主控LLM生成执行计划...")
            print(f"🔄 正在调用主控LLM生成执行计划...", flush=True)
            print(f"   目标: {target}", flush=True)
            if target == "auto_extract":
                raw_desc = (options or {}).get("raw_description", "")
                if raw_desc:
                    print(f"   原始描述: {raw_desc[:100]}...", flush=True)
            
            print(f"   请稍候，LLM正在思考中...", flush=True)
            self.logger.info("开始调用LLM API...")
            
            try:
                # 添加超时控制（2分钟）
                try:
                    print(f"   📡 正在发送请求到LLM API...", flush=True)
                    self.logger.info("发送请求到LLM API...")
                    response = await asyncio.wait_for(
                        self.master_llm.ainvoke(messages),
                        timeout=120.0
                    )
                    print(f"   ✅ LLM API响应已接收", flush=True)
                    self.logger.info("LLM API响应已接收")
                    
                    content = response.content if hasattr(response, 'content') else str(response)
                    print(f"   ✅ LLM响应接收成功，长度: {len(content)} 字符", flush=True)
                    self.logger.info(f"LLM响应接收成功，长度: {len(content)} 字符")
                except KeyboardInterrupt:
                    error_msg = "用户中断LLM调用"
                    self.logger.warning(error_msg)
                    print(f"   ⚠️  {error_msg}", flush=True)
                    raise
            except asyncio.TimeoutError:
                error_msg = "LLM调用超时（超过2分钟）"
                self.logger.error(error_msg)
                print(f"   ❌ {error_msg}", flush=True)
                print(f"   提示: 可能是网络问题或LLM服务响应慢，请检查网络连接", flush=True)
                raise ValueError(error_msg)
            except Exception as e:
                error_msg = f"LLM调用失败: {e}"
                self.logger.error(error_msg, exc_info=True)
                print(f"   ❌ {error_msg}", flush=True)
                import traceback
                error_trace = traceback.format_exc()
                self.logger.error(error_trace)
                print(f"   详细错误信息已记录到日志", flush=True)
                print(f"   错误类型: {type(e).__name__}", flush=True)
                raise
            
            # 解析JSON响应
            # 尝试提取JSON（可能包含markdown代码块）
            print(f"🔄 正在解析LLM返回的JSON...", flush=True)
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
            else:
                json_str = content
            
            try:
                execution_plan = json.loads(json_str)
                print(f"✅ JSON解析成功", flush=True)
            except json.JSONDecodeError as e:
                self.logger.error(f"JSON解析失败，原始内容前500字符: {content[:500]}")
                print(f"❌ JSON解析失败，尝试提取JSON片段...", flush=True)
                # 尝试更宽松的JSON提取
                json_match = re.search(r'\{[\s\S]*"stages"[\s\S]*\}', content, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0)
                    execution_plan = json.loads(json_str)
                    print(f"✅ 使用备用方法解析JSON成功", flush=True)
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
                print(f"🔄 执行阶段: {stage_name}...", flush=True)
                
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
                print(f"🔄 将任务和目标发送给 {agent_type.value}...", flush=True)
                future = actor.execute.remote(target_info, context)
                result = await self.execution_manager.run_ray_get(future)
                
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
                
                # 更新TODO状态
                for todo in stage_todos:
                    todo_id = todo.get("id")
                    if todo_id:
                        if result.get("success"):
                            await self.todo_manager.mark_todo_completed(todo_id)
                        else:
                            await self.todo_manager.mark_todo_failed(todo_id, result.get("error", "执行失败"))
                
                # 检查是否应该继续
                if not result.get("success") and not options.get("safe_mode", True):
                    self.logger.warning(f"阶段 {stage_name} 失败，停止执行")
                    break
                    
        except Exception as e:
            self.logger.error(f"从TODO执行失败: {e}")
            results.append({
                "success": False,
                "error": str(e)
            })
        
        return results
    
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
                print(f"🔄 执行 {stage_name}...", flush=True)
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
        
        print(f"🔄 执行阶段: {stage.value}...", flush=True)
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
    
    def shutdown(self):
        """关闭Ray和所有资源"""
        for session_id, task in list(self.running_sessions.items()):
            if not task.done():
                task.cancel()
            self.running_sessions.pop(session_id, None)
        self.agent_pool.shutdown()
        # Ray 关闭由执行管理器统一管理
        self.logger.info("Ray Master Controller shutdown")
