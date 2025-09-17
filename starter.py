import _thread
import argparse
import os
import socket
from contextlib import asynccontextmanager

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


# === 启动入口 ===
if __name__ == "__main__":
    logger.info(f"Environment = {settings.APP_ENV}", extra={"category": "system"})

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
