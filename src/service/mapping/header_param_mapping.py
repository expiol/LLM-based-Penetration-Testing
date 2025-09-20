"""
HTTP Header 参数映射
定义用于日志记录和请求追踪的header字段常量
"""

class HeaderParamMapping:
    """HTTP Header 参数映射常量"""
    
    # 会话ID
    SID = "X-Session-ID"
    
    # 用户ID
    UID = "X-User-ID"
    
    # 请求顺序号
    ORDER = "X-Request-Order"
    
    # 扩展信息
    EXT = "X-Ext-Info"
    
    # 组织信息
    ORG = "X-Org-ID"
    
    # 请求ID
    REQUEST_ID = "X-Request-ID"
    
    # 追踪ID
    TRACE_ID = "X-Trace-ID"
    
    # 模型名称
    MODEL_NAME = "X-Model-Name"
    
    # 安全模式
    SAFE_MODE = "X-Safe-Mode"
