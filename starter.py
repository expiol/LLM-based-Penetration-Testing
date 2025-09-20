import _thread
import argparse
import os
import socket
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse

from configs import settings
from configs.settings import SERVICE_UUID, SERVICE_NAME
from utils.hot_swap_watcher import start_hot_swap_watcher
from utils.logger import SingleLogger

from src.service.scan_api import scan_api_v1
from src.service.exploit_api import exploit_api_v1
from src.service.report_api import report_api_v1
from src.service.payload_api import payload_api_v1
from src.service.master_controller_api import master_controller_api_v1


def get_host_ip() -> str | None:
    """获取本机 IP，用于服务对外暴露"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("114.114.114.114", 80))
            ip = s.getsockname()[0]
        return ip
    except Exception as e:
        logger.error(f"获取容器 IP 失败: {e}，请配置默认 SERVICE_ADDRESS 环境变量")
        return None


@asynccontextmanager
async def on_start_up(app: FastAPI):
    """
    FastAPI 启动回调：
    - 初始化模型服务
    - 启动配置热更
    """
    model_name = os.getenv("MODEL_NAME")
    # 初始化 LLM 渗透测试引擎
    from src.service.model_manager import init_model_serve
    init_model_serve(model_name)

    # 启动配置热更后台线程
    _thread.start_new_thread(start_hot_swap_watcher, (settings.HOT_SWAP_POLL_INTERVAL,))
    yield


# === 基础服务信息 ===
SERVICE_ADDRESS = get_host_ip() or os.environ.get("SERVICE_ADDRESS", "127.0.0.1")
logger = SingleLogger.get_logger()

# === 初始化 FastAPI 应用 ===
app = FastAPI(lifespan=on_start_up)

# === 注册渗透测试相关 API ===
scan_api_v1(app)       # 漏洞扫描
exploit_api_v1(app)    # 漏洞利用
payload_api_v1(app)    # payload 生成与测试
report_api_v1(app)     # 渗透测试报告
master_controller_api_v1(app)  # 主控制器API


# === 可选 Agents (实验性模块) ===
try:
    from src.agents.risk_assessment_agent import risk_assessment_api
    risk_assessment_api(app)
except ImportError:
    logger.warning("risk_assessment_agent 模块不存在，跳过初始化")

try:
    from src.agents.attack_chain_agent import attack_chain_simulation_api
    attack_chain_simulation_api(app)
except ImportError:
    logger.warning("attack_chain_agent 模块不存在，跳过初始化")


# === 健康检查端点 ===
@app.get("/health")
async def health_check():
    """健康检查端点"""
    return {
        "status": "healthy",
        "service": SERVICE_NAME,
        "version": settings.APP_VERSION,
        "uuid": SERVICE_UUID,
        "timestamp": "2024-01-01T00:00:00Z"
    }


# === 全局异常处理 ===
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    fields = [err["loc"][1] for err in exc.errors()]
    return JSONResponse(
        content={
            "code": 400,
            "message": "参数校验错误，请检查输入字段：" + str(fields),
        }
    )


def check_docker_environment() -> bool:
    """检查Docker环境是否可用"""
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            logger.info(f"Docker版本: {result.stdout.strip()}")
            return True
        else:
            logger.error("Docker未安装或不可用")
            return False
    except FileNotFoundError:
        logger.error("Docker命令未找到，请确保Docker已安装")
        return False


def start_in_docker() -> None:
    """在Docker容器中启动服务"""
    try:
        logger.info("正在构建Docker镜像...")
        
        # 构建Docker镜像
        build_cmd = ["docker-compose", "build", "llm-pentest"]
        subprocess.run(build_cmd, check=True)
        
        logger.info("正在启动Docker容器...")
        
        # 启动Docker容器
        start_cmd = ["docker-compose", "up", "-d", "llm-pentest"]
        subprocess.run(start_cmd, check=True)
        
        logger.info("🚀 LLM-based Penetration Testing Platform 已在Docker中启动")
        logger.info("访问地址: http://localhost:8080")
        logger.info("健康检查: http://localhost:8080/health")
        
        # 显示日志
        logs_cmd = ["docker-compose", "logs", "-f", "llm-pentest"]
        subprocess.run(logs_cmd)
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Docker启动失败: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("正在停止Docker容器...")
        stop_cmd = ["docker-compose", "down"]
        subprocess.run(stop_cmd)


def start_local_development() -> None:
    """本地开发模式启动"""
    logger.warning("⚠️  本地开发模式启动，请确保在安全的隔离环境中运行")
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_name", default="PenTest-LLM", help="渗透测试模型名称")
    parser.add_argument("--service_port", default=8080, type=int, help="服务端口")
    args = parser.parse_args()

    os.environ["MODEL_NAME"] = args.model_name
    port = args.service_port

    logger.info(
        f"🚀 PenTest Service [{SERVICE_NAME}] (UUID={SERVICE_UUID}) 启动 "
        f"地址: {SERVICE_ADDRESS}, 端口: {port}",
        extra={"category": "system"},
    )
    uvicorn.run(
        "starter:app",
        host="0.0.0.0",
        port=port,
        workers=settings.MAX_THREAD,
    )


# === 启动入口 ===
if __name__ == "__main__":
    logger.info(f"Environment = {settings.APP_ENV}", extra={"category": "system"})
    
    # 检查是否强制本地开发模式
    force_local = os.environ.get("FORCE_LOCAL_DEV", "false").lower() == "true"
    
    if force_local:
        logger.warning("强制本地开发模式")
        start_local_development()
    elif check_docker_environment():
        logger.info("检测到Docker环境，使用Docker容器启动以确保安全性")
        start_in_docker()
    else:
        logger.warning("Docker环境不可用，切换到本地开发模式")
        logger.warning("请注意：本地模式下的安全性较低，建议仅用于开发测试")
        start_local_development()
