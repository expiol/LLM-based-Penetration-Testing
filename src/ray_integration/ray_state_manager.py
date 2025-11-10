"""
Ray状态管理器
使用Ray的分布式存储管理全局状态
"""
import logging
from typing import Any, Dict, Optional
from datetime import datetime
import ray

logger = logging.getLogger(__name__)


@ray.remote
class RayStateStore:
    """
    Ray分布式状态存储
    使用Ray Actor实现全局状态管理
    """
    
    def __init__(self):
        self.states: Dict[str, Any] = {}
        self.logger = logging.getLogger("ray_state_store")
    
    def put(self, key: str, value: Any):
        """存储状态"""
        self.states[key] = {
            "value": value,
            "timestamp": datetime.now().isoformat()
        }
        self.logger.debug(f"Stored state: {key}")
    
    def get(self, key: str) -> Optional[Any]:
        """获取状态"""
        state = self.states.get(key)
        if state:
            return state["value"]
        return None
    
    def delete(self, key: str) -> bool:
        """删除状态"""
        if key in self.states:
            del self.states[key]
            self.logger.debug(f"Deleted state: {key}")
            return True
        return False
    
    def exists(self, key: str) -> bool:
        """检查状态是否存在"""
        return key in self.states
    
    def keys(self) -> list:
        """获取所有键"""
        return list(self.states.keys())
    
    def clear(self):
        """清空所有状态"""
        self.states.clear()
        self.logger.info("Cleared all states")
    
    def get_all(self) -> Dict[str, Any]:
        """获取所有状态"""
        return {k: v["value"] for k, v in self.states.items()}


class RayStateManager:
    """
    Ray状态管理器
    提供便捷的状态管理接口
    """
    
    def __init__(self):
        from ..core.execution_manager import get_execution_manager
        
        # 创建分布式状态存储Actor
        self.state_store = RayStateStore.remote()
        self.logger = logging.getLogger("ray_state_manager")
        self.execution_manager = get_execution_manager()
    
    async def put_session_state(self, session_id: str, state: Dict[str, Any]):
        """存储会话状态"""
        key = f"session_{session_id}"
        # 使用执行管理器统一处理
        future = self.state_store.put.remote(key, state)
        await self.execution_manager.run_ray_get(future)
        self.logger.info(f"Stored session state: {session_id}")
    
    async def get_session_state(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取会话状态"""
        key = f"session_{session_id}"
        future = self.state_store.get.remote(key)
        return await self.execution_manager.run_ray_get(future)
    
    async def update_session_state(self, session_id: str, updates: Dict[str, Any]):
        """更新会话状态"""
        current_state = await self.get_session_state(session_id)
        if current_state is None:
            current_state = {}
        
        current_state.update(updates)
        await self.put_session_state(session_id, current_state)
    
    async def delete_session_state(self, session_id: str):
        """删除会话状态"""
        key = f"session_{session_id}"
        future = self.state_store.delete.remote(key)
        await self.execution_manager.run_ray_get(future)
        self.logger.info(f"Deleted session state: {session_id}")
    
    async def put_agent_result(self, session_id: str, agent_type: str, result: Dict[str, Any]):
        """存储Agent执行结果"""
        key = f"result_{session_id}_{agent_type}"
        future = self.state_store.put.remote(key, result)
        await self.execution_manager.run_ray_get(future)
    
    async def get_agent_result(self, session_id: str, agent_type: str) -> Optional[Dict[str, Any]]:
        """获取Agent执行结果"""
        key = f"result_{session_id}_{agent_type}"
        future = self.state_store.get.remote(key)
        return await self.execution_manager.run_ray_get(future)
    
    async def put_global_context(self, session_id: str, context: Dict[str, Any]):
        """存储全局上下文"""
        key = f"context_{session_id}"
        future = self.state_store.put.remote(key, context)
        await self.execution_manager.run_ray_get(future)
    
    async def get_global_context(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取全局上下文"""
        key = f"context_{session_id}"
        future = self.state_store.get.remote(key)
        return await self.execution_manager.run_ray_get(future)
    
    async def update_global_context(self, session_id: str, updates: Dict[str, Any]):
        """更新全局上下文"""
        current_context = await self.get_global_context(session_id)
        if current_context is None:
            current_context = {}
        
        current_context.update(updates)
        await self.put_global_context(session_id, current_context)
    
    async def list_sessions(self) -> list:
        """列出所有会话"""
        future = self.state_store.keys.remote()
        all_keys = await self.execution_manager.run_ray_get(future)
        session_keys = [k for k in all_keys if k.startswith("session_")]
        return [k.replace("session_", "") for k in session_keys]
    
    async def get_all_states(self) -> Dict[str, Any]:
        """获取所有状态（用于调试）"""
        future = self.state_store.get_all.remote()
        return await self.execution_manager.run_ray_get(future)
    
    async def clear_all(self):
        """清空所有状态"""
        future = self.state_store.clear.remote()
        await self.execution_manager.run_ray_get(future)
        self.logger.warning("Cleared all states")

