"""
主控制器API
提供主控制器的REST API接口
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
import logging

from ..core.master_controller import MasterController

logger = logging.getLogger(__name__)

# 创建路由器
router = APIRouter(prefix="/api/v1/master", tags=["master"])

# 全局主控制器实例
master_controller: Optional[MasterController] = None


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


@router.post("/initialize")
async def initialize_master_controller(config: Dict[str, Any]):
    """
    初始化主控制器
    """
    try:
        global master_controller
        
        if master_controller is not None:
            return {"message": "主控制器已初始化", "status": "already_initialized"}
        
        master_controller = MasterController(config)
        success = await master_controller.initialize()
        
        if success:
            return {"message": "主控制器初始化成功", "status": "initialized"}
        else:
            raise HTTPException(status_code=500, detail="主控制器初始化失败")
            
    except Exception as e:
        logger.error(f"主控制器初始化失败: {e}")
        raise HTTPException(status_code=500, detail=f"初始化失败: {str(e)}")


@router.post("/start-penetration-test")
async def start_penetration_test(request: PenetrationTestRequest, background_tasks: BackgroundTasks):
    """
    启动渗透测试
    """
    try:
        if master_controller is None:
            raise HTTPException(status_code=400, detail="主控制器未初始化")
        
        # 构建测试选项
        options = {
            "safe_mode": request.safe_mode,
            "human_intervention": request.human_intervention,
            "self_correction": request.self_correction,
            **request.options
        }
        
        # 启动渗透测试
        result = await master_controller.start_penetration_test(request.target, options)
        
        return {
            "success": result.get("success", False),
            "session_id": result.get("session_id"),
            "message": "渗透测试已启动" if result.get("success", False) else "渗透测试启动失败",
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
        if master_controller is None:
            return {"status": "not_initialized", "message": "主控制器未初始化"}
        
        status = master_controller.get_status()
        return status
        
    except Exception as e:
        logger.error(f"获取状态失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取状态失败: {str(e)}")


@router.get("/pending-interventions")
async def get_pending_interventions():
    """
    获取待处理的人工干预请求
    """
    try:
        if master_controller is None:
            raise HTTPException(status_code=400, detail="主控制器未初始化")
        
        interventions = master_controller.human_intervention.get_pending_interventions()
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
        if master_controller is None:
            raise HTTPException(status_code=400, detail="主控制器未初始化")
        
        success = master_controller.human_intervention.submit_feedback(
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
        if master_controller is None:
            raise HTTPException(status_code=400, detail="主控制器未初始化")
        
        tools = master_controller.tool_registry.get_available_tools()
        tool_info = {}
        
        for tool_name in tools:
            tool_info[tool_name] = master_controller.tool_registry.get_tool_info(tool_name)
        
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
        if master_controller is None:
            raise HTTPException(status_code=400, detail="主控制器未初始化")
        
        # 动态导入工具类
        import importlib
        module = importlib.import_module(request.module)
        tool_class = getattr(module, request.class_name)
        
        # 注册工具
        success = await master_controller.tool_registry.register_tool(
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
        if master_controller is None:
            raise HTTPException(status_code=400, detail="主控制器未初始化")
        
        result = await master_controller.tool_registry.execute_tool(tool_name, parameters)
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
        if master_controller is None:
            raise HTTPException(status_code=400, detail="主控制器未初始化")
        
        history = master_controller.self_correction.get_correction_history()
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
        if master_controller is None:
            raise HTTPException(status_code=400, detail="主控制器未初始化")
        
        state = master_controller.dynamic_env.get_environment_state()
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
        if master_controller is None:
            raise HTTPException(status_code=400, detail="主控制器未初始化")
        
        success = await master_controller.dynamic_env.prepare_stage_environment(stage_type, stage_config)
        
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
