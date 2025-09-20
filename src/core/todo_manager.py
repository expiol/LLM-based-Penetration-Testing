"""
TODO管理器
管理渗透测试过程中的任务列表
"""
import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class TodoItem:
    """TODO项目"""
    id: str
    title: str
    description: str
    status: str  # pending, in_progress, completed, failed, cancelled
    created_at: str
    updated_at: str
    phase: Optional[str] = None
    tool: Optional[str] = None
    priority: int = 0  # 0-5, 5为最高优先级
    dependencies: List[str] = None
    estimated_duration: int = 0  # 预估时长（秒）
    actual_duration: int = 0  # 实际时长（秒）
    error_message: Optional[str] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []


class TodoManager:
    """TODO管理器"""
    
    def __init__(self):
        self.todo_lists: Dict[str, List[TodoItem]] = {}
        self.lock = asyncio.Lock()
        
        # 统计信息
        self.stats = {
            "total_todos": 0,
            "completed_todos": 0,
            "failed_todos": 0,
            "cancelled_todos": 0,
            "start_time": datetime.now().isoformat()
        }
    
    async def create_todo_list(self, list_name: str, todos: List[Dict[str, Any]]) -> bool:
        """创建TODO列表"""
        async with self.lock:
            try:
                todo_items = []
                current_time = datetime.now().isoformat()
                
                for todo_data in todos:
                    todo_item = TodoItem(
                        id=todo_data["id"],
                        title=todo_data["title"],
                        description=todo_data.get("description", ""),
                        status=todo_data.get("status", "pending"),
                        created_at=current_time,
                        updated_at=current_time,
                        phase=todo_data.get("phase"),
                        tool=todo_data.get("tool"),
                        priority=todo_data.get("priority", 0),
                        dependencies=todo_data.get("dependencies", []),
                        estimated_duration=todo_data.get("estimated_duration", 0)
                    )
                    todo_items.append(todo_item)
                
                self.todo_lists[list_name] = todo_items
                self.stats["total_todos"] += len(todo_items)
                
                return True
                
            except Exception as e:
                print(f"创建TODO列表失败: {e}")
                return False
    
    async def update_todo_status(self, todo_id: str, status: str, error_message: str = None) -> bool:
        """更新TODO状态"""
        async with self.lock:
            try:
                # 在所有列表中查找TODO
                for list_name, todo_list in self.todo_lists.items():
                    for todo in todo_list:
                        if todo.id == todo_id:
                            old_status = todo.status
                            todo.status = status
                            todo.updated_at = datetime.now().isoformat()
                            
                            if error_message:
                                todo.error_message = error_message
                            
                            # 更新统计
                            self._update_stats(old_status, status)
                            
                            return True
                
                print(f"TODO项目不存在: {todo_id}")
                return False
                
            except Exception as e:
                print(f"更新TODO状态失败: {e}")
                return False
    
    def _update_stats(self, old_status: str, new_status: str):
        """更新统计信息"""
        # 减少旧状态计数
        if old_status == "completed":
            self.stats["completed_todos"] -= 1
        elif old_status == "failed":
            self.stats["failed_todos"] -= 1
        elif old_status == "cancelled":
            self.stats["cancelled_todos"] -= 1
        
        # 增加新状态计数
        if new_status == "completed":
            self.stats["completed_todos"] += 1
        elif new_status == "failed":
            self.stats["failed_todos"] += 1
        elif new_status == "cancelled":
            self.stats["cancelled_todos"] += 1
    
    async def get_todo_list(self, list_name: str) -> List[Dict[str, Any]]:
        """获取TODO列表"""
        async with self.lock:
            todo_list = self.todo_lists.get(list_name, [])
            return [asdict(todo) for todo in todo_list]
    
    async def get_all_todos(self) -> Dict[str, List[Dict[str, Any]]]:
        """获取所有TODO列表"""
        async with self.lock:
            result = {}
            for list_name, todo_list in self.todo_lists.items():
                result[list_name] = [asdict(todo) for todo in todo_list]
            return result
    
    async def get_pending_todos(self, list_name: str = None) -> List[Dict[str, Any]]:
        """获取待处理的TODOs"""
        async with self.lock:
            pending_todos = []
            
            if list_name:
                # 获取特定列表的待处理TODOs
                todo_list = self.todo_lists.get(list_name, [])
                pending_todos = [asdict(todo) for todo in todo_list if todo.status == "pending"]
            else:
                # 获取所有列表的待处理TODOs
                for todo_list in self.todo_lists.values():
                    pending_todos.extend([asdict(todo) for todo in todo_list if todo.status == "pending"])
            
            # 按优先级排序
            pending_todos.sort(key=lambda x: x["priority"], reverse=True)
            return pending_todos
    
    async def get_next_todo(self, list_name: str = None) -> Optional[Dict[str, Any]]:
        """获取下一个待处理的TODO"""
        pending_todos = await self.get_pending_todos(list_name)
        
        # 检查依赖关系
        for todo in pending_todos:
            if await self._check_dependencies_completed(todo["dependencies"]):
                return todo
        
        return None
    
    async def _check_dependencies_completed(self, dependencies: List[str]) -> bool:
        """检查依赖是否完成"""
        if not dependencies:
            return True
        
        for list_name, todo_list in self.todo_lists.items():
            for todo in todo_list:
                if todo.id in dependencies and todo.status != "completed":
                    return False
        
        return True
    
    async def get_progress(self, list_name: str = None) -> Dict[str, Any]:
        """获取进度信息"""
        async with self.lock:
            if list_name:
                # 特定列表的进度
                todo_list = self.todo_lists.get(list_name, [])
                total = len(todo_list)
                completed = len([t for t in todo_list if t.status == "completed"])
                failed = len([t for t in todo_list if t.status == "failed"])
                in_progress = len([t for t in todo_list if t.status == "in_progress"])
                
                return {
                    "list_name": list_name,
                    "total": total,
                    "completed": completed,
                    "failed": failed,
                    "in_progress": in_progress,
                    "progress_percentage": (completed / total * 100) if total > 0 else 0
                }
            else:
                # 全局进度
                return {
                    "total": self.stats["total_todos"],
                    "completed": self.stats["completed_todos"],
                    "failed": self.stats["failed_todos"],
                    "cancelled": self.stats["cancelled_todos"],
                    "in_progress": self._count_in_progress(),
                    "progress_percentage": (self.stats["completed_todos"] / self.stats["total_todos"] * 100) if self.stats["total_todos"] > 0 else 0
                }
    
    def _count_in_progress(self) -> int:
        """统计进行中的TODO数量"""
        count = 0
        for todo_list in self.todo_lists.values():
            count += len([t for t in todo_list if t.status == "in_progress"])
        return count
    
    async def get_summary(self) -> Dict[str, Any]:
        """获取总结信息"""
        async with self.lock:
            # 按阶段统计
            phase_stats = {}
            phase_todos = {}
            
            for list_name, todo_list in self.todo_lists.items():
                phase_stats[list_name] = {
                    "total": len(todo_list),
                    "completed": len([t for t in todo_list if t.status == "completed"]),
                    "failed": len([t for t in todo_list if t.status == "failed"]),
                    "in_progress": len([t for t in todo_list if t.status == "in_progress"])
                }
                
                phase_todos[list_name] = [
                    {
                        "id": todo.id,
                        "title": todo.title,
                        "status": todo.status,
                        "tool": todo.tool
                    }
                    for todo in todo_list
                ]
            
            # 时间统计
            start_time = datetime.fromisoformat(self.stats["start_time"])
            current_time = datetime.now()
            total_duration = (current_time - start_time).total_seconds()
            
            return {
                "global_stats": self.stats,
                "phase_stats": phase_stats,
                "phase_todos": phase_todos,
                "total_duration_seconds": total_duration,
                "average_todo_duration": self._calculate_average_duration()
            }
    
    def _calculate_average_duration(self) -> float:
        """计算平均TODO完成时长"""
        total_duration = 0
        completed_count = 0
        
        for todo_list in self.todo_lists.values():
            for todo in todo_list:
                if todo.status == "completed" and todo.actual_duration > 0:
                    total_duration += todo.actual_duration
                    completed_count += 1
        
        return total_duration / completed_count if completed_count > 0 else 0
    
    async def mark_todo_started(self, todo_id: str) -> bool:
        """标记TODO开始执行"""
        return await self.update_todo_status(todo_id, "in_progress")
    
    async def mark_todo_completed(self, todo_id: str, actual_duration: int = 0) -> bool:
        """标记TODO完成"""
        async with self.lock:
            # 查找并更新TODO
            for todo_list in self.todo_lists.values():
                for todo in todo_list:
                    if todo.id == todo_id:
                        todo.actual_duration = actual_duration
                        break
        
        return await self.update_todo_status(todo_id, "completed")
    
    async def mark_todo_failed(self, todo_id: str, error_message: str) -> bool:
        """标记TODO失败"""
        return await self.update_todo_status(todo_id, "failed", error_message)
    
    async def cancel_todo(self, todo_id: str, reason: str = "") -> bool:
        """取消TODO"""
        return await self.update_todo_status(todo_id, "cancelled", reason)
    
    async def add_todo(self, list_name: str, todo_data: Dict[str, Any]) -> bool:
        """添加单个TODO"""
        async with self.lock:
            try:
                current_time = datetime.now().isoformat()
                
                todo_item = TodoItem(
                    id=todo_data["id"],
                    title=todo_data["title"],
                    description=todo_data.get("description", ""),
                    status=todo_data.get("status", "pending"),
                    created_at=current_time,
                    updated_at=current_time,
                    phase=todo_data.get("phase"),
                    tool=todo_data.get("tool"),
                    priority=todo_data.get("priority", 0),
                    dependencies=todo_data.get("dependencies", []),
                    estimated_duration=todo_data.get("estimated_duration", 0)
                )
                
                if list_name not in self.todo_lists:
                    self.todo_lists[list_name] = []
                
                self.todo_lists[list_name].append(todo_item)
                self.stats["total_todos"] += 1
                
                return True
                
            except Exception as e:
                print(f"添加TODO失败: {e}")
                return False
    
    async def remove_todo(self, todo_id: str) -> bool:
        """删除TODO"""
        async with self.lock:
            try:
                for list_name, todo_list in self.todo_lists.items():
                    for i, todo in enumerate(todo_list):
                        if todo.id == todo_id:
                            removed_todo = todo_list.pop(i)
                            self.stats["total_todos"] -= 1
                            
                            # 更新统计
                            if removed_todo.status == "completed":
                                self.stats["completed_todos"] -= 1
                            elif removed_todo.status == "failed":
                                self.stats["failed_todos"] -= 1
                            elif removed_todo.status == "cancelled":
                                self.stats["cancelled_todos"] -= 1
                            
                            return True
                
                return False
                
            except Exception as e:
                print(f"删除TODO失败: {e}")
                return False
    
    async def get_todo_by_id(self, todo_id: str) -> Optional[Dict[str, Any]]:
        """根据ID获取TODO"""
        async with self.lock:
            for todo_list in self.todo_lists.values():
                for todo in todo_list:
                    if todo.id == todo_id:
                        return asdict(todo)
            return None
    
    async def get_todos_by_status(self, status: str, list_name: str = None) -> List[Dict[str, Any]]:
        """根据状态获取TODOs"""
        async with self.lock:
            result = []
            
            if list_name:
                todo_list = self.todo_lists.get(list_name, [])
                result = [asdict(todo) for todo in todo_list if todo.status == status]
            else:
                for todo_list in self.todo_lists.values():
                    result.extend([asdict(todo) for todo in todo_list if todo.status == status])
            
            return result
    
    async def get_todos_by_phase(self, phase: str) -> List[Dict[str, Any]]:
        """根据阶段获取TODOs"""
        async with self.lock:
            result = []
            
            for todo_list in self.todo_lists.values():
                result.extend([asdict(todo) for todo in todo_list if todo.phase == phase])
            
            return result
    
    async def export_todos(self, filename: str) -> bool:
        """导出TODO列表到文件"""
        try:
            todos_data = await self.get_all_todos()
            summary_data = await self.get_summary()
            
            export_data = {
                "todos": todos_data,
                "summary": summary_data,
                "exported_at": datetime.now().isoformat()
            }
            
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
            
            return True
            
        except Exception as e:
            print(f"导出TODO列表失败: {e}")
            return False
    
    async def clear_completed_todos(self, list_name: str = None) -> int:
        """清除已完成的TODOs"""
        async with self.lock:
            cleared_count = 0
            
            if list_name:
                todo_list = self.todo_lists.get(list_name, [])
                original_length = len(todo_list)
                self.todo_lists[list_name] = [todo for todo in todo_list if todo.status != "completed"]
                cleared_count = original_length - len(self.todo_lists[list_name])
            else:
                for list_name, todo_list in self.todo_lists.items():
                    original_length = len(todo_list)
                    self.todo_lists[list_name] = [todo for todo in todo_list if todo.status != "completed"]
                    cleared_count += original_length - len(self.todo_lists[list_name])
            
            # 更新统计
            self.stats["total_todos"] -= cleared_count
            self.stats["completed_todos"] = max(0, self.stats["completed_todos"] - cleared_count)
            
            return cleared_count
