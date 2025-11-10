"""
主控制器API
提供启动全自动渗透测试框架的REST接口
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from pathlib import Path
import logging
import json

from ..framework import AutoPentestFramework

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/master", tags=["master"])

auto_framework: Optional[AutoPentestFramework] = None
DEFAULT_CONFIG_PATH = Path("configs/master_controller_config.json")


def _load_framework_config(config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if config:
        return config
    if DEFAULT_CONFIG_PATH.exists():
        try:
            return json.loads(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error("加载默认主控制器配置失败: %s", exc)
            raise HTTPException(status_code=500, detail=f"配置读取失败: {exc}") 
    return {}


def _require_framework() -> AutoPentestFramework:
    if auto_framework is None:
        raise HTTPException(status_code=400, detail="主控制器未初始化")
    return auto_framework


class PenetrationTestRequest(BaseModel):
    """渗透测试请求模型"""
    target: str = Field(..., description="目标地址")
    options: Dict[str, Any] = Field(default_factory=dict, description="测试选项")
    safe_mode: bool = Field(True, description="安全模式")
    human_intervention: bool = Field(True, description="是否允许人工干预")
    self_correction: bool = Field(True, description="是否启用自我纠错")


class InterventionFeedback(BaseModel):
    """人工干预反馈模型"""
    intervention_id: str = Field(..., description="干预ID")
    feedback: Dict[str, Any] = Field(..., description="反馈内容")


class ToolRegistrationRequest(BaseModel):
    """工具注册请求模型"""
    name: str = Field(..., description="工具名称")
    module: str = Field(..., description="工具模块")
    class_name: str = Field(..., description="工具类名")
    config: Dict[str, Any] = Field(default_factory=dict, description="工具配置")


class OperatorNoteRequest(BaseModel):
    """操作员补充情报"""
    note: str = Field(..., description="情报内容")


class ReplanRequest(BaseModel):
    """重新规划请求"""
    instruction: str = Field(..., description="重新规划提示信息")


class PauseRequest(BaseModel):
    """暂停请求"""
    reason: Optional[str] = Field(None, description="暂停原因")


@router.post("/initialize")
async def initialize_master_controller(config: Optional[Dict[str, Any]] = None):
    """
    初始化全自动渗透测试框架
    """
    try:
        global auto_framework

        if auto_framework is not None:
            return {"message": "主控制器已初始化", "status": "already_initialized"}

        framework_config = _load_framework_config(config)
        auto_framework = AutoPentestFramework(framework_config)
        await auto_framework.initialize()

        return {
            "message": "主控制器初始化成功",
            "status": "initialized",
            "config_loaded": bool(framework_config),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"主控制器初始化失败: {e}")
        raise HTTPException(status_code=500, detail=f"初始化失败: {str(e)}")


@router.post("/start-penetration-test")
async def start_penetration_test(request: PenetrationTestRequest):
    """
    启动渗透测试
    """
    try:
        framework = _require_framework()
        
        # 构建测试选项
        options = {
            "safe_mode": request.safe_mode,
            "human_intervention": request.human_intervention,
            "self_correction": request.self_correction,
            **request.options
        }

        result = await framework.start_automated_test(request.target, options)

        return {
            "success": True,
            "session_id": result.get("session_id"),
            "message": "渗透测试已进入全自动执行流水线",
            "result": result
        }
        
    except Exception as e:
        logger.error(f"渗透测试启动失败: {e}")
        raise HTTPException(status_code=500, detail=f"启动失败: {str(e)}")


@router.get("/status")
async def get_status():
    """
    获取主控制器状态
    """
    try:
        if auto_framework is None:
            return {"status": "not_initialized", "message": "主控制器未初始化"}
        
        status = auto_framework.describe()
        status["sessions"] = await auto_framework.get_all_sessions()
        return status
        
    except Exception as e:
        logger.error(f"获取状态失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取状态失败: {str(e)}")


@router.get("/sessions")
async def list_sessions():
    """
    获取所有渗透测试会话
    """
    framework = _require_framework()
    sessions = await framework.get_all_sessions()
    return {"sessions": sessions}


@router.get("/sessions/{session_id}")
async def get_session_detail(session_id: str):
    """
    获取指定会话详情
    """
    framework = _require_framework()
    session = await framework.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="会话不存在")
    return session


@router.get("/sessions/{session_id}/live-view")
async def get_session_live_view(session_id: str):
    """
    获取指定会话的实时视图（当前阶段 / 待执行阶段）
    """
    try:
        framework = _require_framework()
        view = await framework.get_live_view(session_id)
        if not view:
            raise HTTPException(status_code=404, detail="会话不存在或未运行")
        return view
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取实时视图失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取失败: {str(e)}")


@router.post("/sessions/{session_id}/pause")
async def pause_session(session_id: str, request: Optional[PauseRequest] = None):
    """
    暂停指定会话
    """
    try:
        framework = _require_framework()
        reason = request.reason if request else None
        await framework.request_pause(session_id, reason)
        return {"session_id": session_id, "state": "pausing"}
    except Exception as e:
        logger.error(f"暂停会话失败: {e}")
        raise HTTPException(status_code=500, detail=f"暂停失败: {str(e)}")


@router.post("/sessions/{session_id}/resume")
async def resume_session(session_id: str):
    """
    恢复暂停的会话
    """
    try:
        framework = _require_framework()
        result = await framework.resume_session(session_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"恢复会话失败: {e}")
        raise HTTPException(status_code=500, detail=f"恢复失败: {str(e)}")


@router.post("/sessions/{session_id}/notes")
async def add_operator_note(session_id: str, request: OperatorNoteRequest):
    """
    添加操作员情报备注
    """
    try:
        framework = _require_framework()
        result = await framework.add_operator_intel(session_id, request.note)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"添加情报失败: {e}")
        raise HTTPException(status_code=500, detail=f"添加失败: {str(e)}")


@router.post("/sessions/{session_id}/replan")
async def replan_session(session_id: str, request: ReplanRequest):
    """
    根据提示重新规划会话后续阶段
    """
    try:
        framework = _require_framework()
        result = await framework.replan_session(session_id, request.instruction)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"重新规划失败: {e}")
        raise HTTPException(status_code=500, detail=f"重新规划失败: {str(e)}")


@router.get("/pending-interventions")
async def get_pending_interventions():
    """
    获取待处理的人工干预请求
    """
    try:
        framework = _require_framework()
        interventions = framework.master_controller.human_intervention.get_pending_interventions()
        return {"interventions": interventions}
        
    except Exception as e:
        logger.error(f"获取待处理干预失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取失败: {str(e)}")


@router.post("/submit-intervention-feedback")
async def submit_intervention_feedback(feedback: InterventionFeedback):
    """
    提交人工干预反馈
    """
    try:
        framework = _require_framework()
        
        success = framework.master_controller.human_intervention.submit_feedback(
            feedback.intervention_id,
            feedback.feedback
        )
        
        if success:
            return {"message": "反馈提交成功", "success": True}
        else:
            raise HTTPException(status_code=400, detail="反馈提交失败")
            
    except Exception as e:
        logger.error(f"反馈提交失败: {e}")
        raise HTTPException(status_code=500, detail=f"提交失败: {str(e)}")


@router.get("/tools")
async def get_available_tools():
    """
    获取可用工具列表
    """
    try:
        framework = _require_framework()
        
        tools = framework.master_controller.tool_registry.get_available_tools()
        tool_info = {}
        
        for tool_name in tools:
            tool_info[tool_name] = framework.master_controller.tool_registry.get_tool_info(tool_name)
        
        return {"tools": tool_info}
        
    except Exception as e:
        logger.error(f"获取工具列表失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取失败: {str(e)}")


@router.post("/register-tool")
async def register_tool(request: ToolRegistrationRequest):
    """
    注册自定义工具
    """
    try:
        framework = _require_framework()
        
        # 动态导入工具类
        import importlib
        module = importlib.import_module(request.module)
        tool_class = getattr(module, request.class_name)
        
        # 注册工具
        success = await framework.master_controller.tool_registry.register_tool(
            request.name,
            tool_class,
            request.config
        )
        
        if success:
            return {"message": "工具注册成功", "success": True}
        else:
            raise HTTPException(status_code=400, detail="工具注册失败")
            
    except Exception as e:
        logger.error(f"工具注册失败: {e}")
        raise HTTPException(status_code=500, detail=f"注册失败: {str(e)}")


@router.post("/execute-tool")
async def execute_tool(tool_name: str, parameters: Dict[str, Any]):
    """
    执行工具
    """
    try:
        framework = _require_framework()
        result = await framework.master_controller.tool_registry.execute_tool(tool_name, parameters)
        return result
        
    except Exception as e:
        logger.error(f"工具执行失败: {e}")
        raise HTTPException(status_code=500, detail=f"执行失败: {str(e)}")


@router.get("/correction-history")
async def get_correction_history():
    """
    获取自我纠错历史
    """
    try:
        framework = _require_framework()
        history = framework.master_controller.self_correction.get_correction_history()
        return {"correction_history": history}
        
    except Exception as e:
        logger.error(f"获取纠错历史失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取失败: {str(e)}")


@router.get("/environment-state")
async def get_environment_state():
    """
    获取环境状态
    """
    try:
        framework = _require_framework()
        state = framework.master_controller.dynamic_env.get_environment_state()
        return state
        
    except Exception as e:
        logger.error(f"获取环境状态失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取失败: {str(e)}")


@router.post("/prepare-environment")
async def prepare_environment(stage_type: str, stage_config: Dict[str, Any]):
    """
    准备环境
    """
    try:
        framework = _require_framework()
        success = await framework.master_controller.dynamic_env.prepare_stage_environment(stage_type, stage_config)
        
        if success:
            return {"message": "环境准备成功", "success": True}
        else:
            raise HTTPException(status_code=400, detail="环境准备失败")
            
    except Exception as e:
        logger.error(f"环境准备失败: {e}")
        raise HTTPException(status_code=500, detail=f"准备失败: {str(e)}")


def master_controller_api_v1(app):
    """注册主控制器API到FastAPI应用"""
    app.include_router(router)
