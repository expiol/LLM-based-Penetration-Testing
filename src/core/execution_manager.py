"""
统一的线程和异步执行管理器
负责协调所有线程、异步和 Ray 相关的操作，避免冲突
"""
import asyncio
import logging
import threading
from typing import Any, Callable, Optional, TypeVar, Coroutine, Dict
from concurrent.futures import ThreadPoolExecutor, Future
import ray

logger = logging.getLogger(__name__)

T = TypeVar('T')


class ExecutionManager:
    """
    统一的执行管理器
    管理所有线程、异步和 Ray 相关的操作
    """
    
    _instance: Optional['ExecutionManager'] = None
    _lock = threading.Lock()
    
    def __init__(self):
        """初始化执行管理器"""
        self._main_event_loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread_pool: Optional[ThreadPoolExecutor] = None
        self._ray_initialized = False
        self._ray_lock = threading.Lock()
        self._initialized = False
        self._shutdown_event = threading.Event()
        self.logger = logging.getLogger("execution_manager")
        
    @classmethod
    def get_instance(cls) -> 'ExecutionManager':
        """获取单例实例"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
    
    def initialize(self, max_workers: int = 10):
        """
        初始化执行管理器
        
        Args:
            max_workers: 线程池最大工作线程数
        """
        if self._initialized:
            return
        
        self.logger.info("Initializing ExecutionManager...")
        
        # 创建线程池
        self._thread_pool = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="execution_manager"
        )
        
        # 尝试获取主事件循环
        try:
            self._main_event_loop = asyncio.get_running_loop()
            self.logger.info("Main event loop detected")
        except RuntimeError:
            # 如果没有运行的事件循环，将在第一次使用时创建
            self.logger.info("No running event loop, will create on first use")
        
        self._initialized = True
        self.logger.info("ExecutionManager initialized")
    
    async def run_in_thread(
        self,
        func: Callable[..., T],
        *args,
        timeout: Optional[float] = None,
        **kwargs
    ) -> T:
        """
        在后台线程中运行同步函数
        
        Args:
            func: 要执行的函数
            *args: 函数参数
            timeout: 超时时间（秒）
            **kwargs: 函数关键字参数
            
        Returns:
            函数执行结果
        """
        if not self._initialized:
            self.initialize()
        
        if self._thread_pool is None:
            raise RuntimeError("Thread pool not initialized")
        
        def _run():
            return func(*args, **kwargs)
        
        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(self._thread_pool, _run)
        
        if timeout is not None:
            return await asyncio.wait_for(future, timeout=timeout)
        else:
            return await future
    
    async def run_ray_get(
        self,
        ray_future: Any,
        timeout: Optional[float] = None
    ) -> Any:
        """
        在后台线程中执行 ray.get()，避免阻塞事件循环
        
        Args:
            ray_future: Ray future 对象
            timeout: 超时时间（秒）
            
        Returns:
            Ray 任务的执行结果
        """
        if not self._ray_initialized:
            raise RuntimeError("Ray not initialized")
        
        def _get():
            return ray.get(ray_future)
        
        return await self.run_in_thread(_get, timeout=timeout)
    
    def initialize_ray(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化 Ray（线程安全）
        
        Args:
            config: Ray 配置字典
        """
        with self._ray_lock:
            if self._ray_initialized:
                self.logger.info("Ray already initialized")
                return
            
            if ray.is_initialized():
                self.logger.info("Ray already initialized externally")
                self._ray_initialized = True
                return
            
            config = config or {}
            try:
                ray.init(
                    num_cpus=config.get("num_cpus", 8),
                    num_gpus=config.get("num_gpus", 0),
                    object_store_memory=config.get("object_store_memory", 2000000000),
                    ignore_reinit_error=True
                )
                self._ray_initialized = True
                self.logger.info("Ray initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize Ray: {e}")
                raise
    
    def shutdown_ray(self):
        """
        关闭 Ray（线程安全）
        """
        with self._ray_lock:
            if not self._ray_initialized:
                return
            
            if ray.is_initialized():
                try:
                    ray.shutdown()
                    self.logger.info("Ray shut down successfully")
                except Exception as e:
                    self.logger.error(f"Error shutting down Ray: {e}")
            
            self._ray_initialized = False
    
    def run_in_new_loop(
        self,
        coro: Coroutine[Any, Any, T],
        timeout: Optional[float] = None
    ) -> T:
        """
        在新的事件循环中运行协程（用于同步函数中调用异步代码）
        
        Args:
            coro: 要执行的协程
            timeout: 超时时间（秒）
            
        Returns:
            协程的执行结果
        """
        def _run_in_loop():
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            try:
                if timeout is not None:
                    return new_loop.run_until_complete(
                        asyncio.wait_for(coro, timeout=timeout)
                    )
                else:
                    return new_loop.run_until_complete(coro)
            finally:
                new_loop.close()
        
        # 在后台线程中运行
        if not self._initialized:
            self.initialize()
        
        if self._thread_pool is None:
            raise RuntimeError("Thread pool not initialized")
        
        future: Future = self._thread_pool.submit(_run_in_loop)
        return future.result()
    
    def get_event_loop(self) -> Optional[asyncio.AbstractEventLoop]:
        """获取主事件循环"""
        return self._main_event_loop
    
    def is_ray_initialized(self) -> bool:
        """检查 Ray 是否已初始化"""
        return self._ray_initialized
    
    def shutdown(self, wait: bool = True):
        """
        关闭执行管理器
        
        Args:
            wait: 是否等待所有任务完成
        """
        if not self._initialized:
            return
        
        self.logger.info("Shutting down ExecutionManager...")
        
        # 关闭 Ray
        self.shutdown_ray()
        
        # 关闭线程池
        if self._thread_pool is not None:
            self._thread_pool.shutdown(wait=wait)
            self._thread_pool = None
        
        self._initialized = False
        self.logger.info("ExecutionManager shut down")
    
    def __del__(self):
        """析构函数，确保资源清理"""
        if self._initialized:
            try:
                self.shutdown(wait=False)
            except:
                pass


# 全局单例实例
_execution_manager: Optional[ExecutionManager] = None


def get_execution_manager() -> ExecutionManager:
    """获取全局执行管理器实例"""
    global _execution_manager
    if _execution_manager is None:
        _execution_manager = ExecutionManager.get_instance()
    return _execution_manager

