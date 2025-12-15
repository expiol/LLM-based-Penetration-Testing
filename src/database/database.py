"""
数据库连接和管理
"""
import os
import logging
from typing import Optional, Dict, Any
from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from contextlib import contextmanager

from .models import Base, PenetrationTestSession, StageExecution, AgentLog

logger = logging.getLogger(__name__)


class DatabaseManager:
    """数据库管理器"""
    
    def __init__(self, database_url: Optional[str] = None):
        """
        初始化数据库管理器
        
        Args:
            database_url: 数据库连接URL，如果为空则使用环境变量或SQLite
        """
        if database_url is None:
            database_url = os.getenv(
                "DATABASE_URL", 
                "sqlite:///./pentest_events/pentest.db"
            )
        
        self.database_url = database_url
        self.engine = None
        self.SessionLocal = None
        
        # 确保数据库目录存在
        if database_url.startswith("sqlite"):
            db_path = database_url.replace("sqlite:///", "")
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    def initialize(self) -> bool:
        """
        初始化数据库连接
        
        Returns:
            bool: 初始化是否成功
        """
        try:
            # 创建数据库引擎
            if self.database_url.startswith("sqlite"):
                self.engine = create_engine(
                    self.database_url,
                    connect_args={"check_same_thread": False},
                    poolclass=StaticPool,
                    echo=False  # 设置为True可以看到SQL语句
                )
            else:
                self.engine = create_engine(
                    self.database_url,
                    pool_pre_ping=True,
                    echo=False
                )
            
            # 创建会话工厂
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )
            
            # 创建所有表
            Base.metadata.create_all(bind=self.engine)
            
            logger.info(t("db.init_success", url=self.database_url))
            return True
            
        except Exception as e:
            logger.error(t("db.init_failed", error=str(e)))
            return False
    
    @contextmanager
    def get_session(self):
        """
        获取数据库会话上下文管理器
        
        Yields:
            Session: 数据库会话
        """
        if self.SessionLocal is None:
            raise RuntimeError("数据库未初始化，请先调用initialize()")
        
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(t("db.operation_failed", error=str(e)))
            raise
        finally:
            session.close()
    
    def create_session(self) -> Session:
        """
        创建数据库会话
        
        Returns:
            Session: 数据库会话
        """
        if self.SessionLocal is None:
            raise RuntimeError("数据库未初始化，请先调用initialize()")
        
        return self.SessionLocal()
    
    def close(self):
        """关闭数据库连接"""
        if self.engine:
            self.engine.dispose()
            logger.info(t("db.closed"))


# 全局数据库管理器实例
db_manager = DatabaseManager()


def get_db_session():
    """获取数据库会话（用于依赖注入）"""
    session = db_manager.create_session()
    try:
        yield session
    finally:
        session.close()
