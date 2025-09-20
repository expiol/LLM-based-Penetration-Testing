"""
侦察阶段提示词模板
"""
from typing import Dict, Any


class ReconPrompts:
    """侦察阶段提示词"""
    
    @staticmethod
    def get_port_scan_prompt(target: str, scan_results: Dict[str, Any]) -> str:
        """
        获取端口扫描分析提示词
        
        Args:
            target: 目标地址
            scan_results: 扫描结果
            
        Returns:
            str: 提示词
        """
        return f"""
你是一个专业的网络安全专家，正在分析端口扫描结果。

目标: {target}
扫描结果: {scan_results}

请分析以下内容：
1. 开放的端口和服务
2. 服务版本信息
3. 潜在的安全风险
4. 下一步的侦察建议

请以JSON格式返回分析结果，包含以下字段：
- open_ports: 开放端口列表
- services: 服务信息
- risks: 安全风险
- recommendations: 建议
"""

    @staticmethod
    def get_vulnerability_analysis_prompt(target: str, vulnerabilities: list) -> str:
        """
        获取漏洞分析提示词
        
        Args:
            target: 目标地址
            vulnerabilities: 漏洞列表
            
        Returns:
            str: 提示词
        """
        return f"""
你是一个专业的漏洞分析专家，正在分析发现的漏洞。

目标: {target}
发现的漏洞: {vulnerabilities}

请分析以下内容：
1. 漏洞的严重程度
2. 漏洞的利用难度
3. 漏洞的影响范围
4. 修复建议

请以JSON格式返回分析结果，包含以下字段：
- severity_assessment: 严重程度评估
- exploitability: 利用难度
- impact: 影响范围
- remediation: 修复建议
"""

    @staticmethod
    def get_recon_summary_prompt(target: str, recon_data: Dict[str, Any]) -> str:
        """
        获取侦察总结提示词
        
        Args:
            target: 目标地址
            recon_data: 侦察数据
            
        Returns:
            str: 提示词
        """
        return f"""
你是一个专业的渗透测试专家，正在总结侦察阶段的结果。

目标: {target}
侦察数据: {recon_data}

请提供以下内容：
1. 目标系统的整体安全状况
2. 发现的主要攻击面
3. 高风险漏洞的优先级排序
4. 进入下一阶段的建议

请以JSON格式返回总结，包含以下字段：
- security_overview: 安全状况概览
- attack_surface: 攻击面分析
- priority_vulnerabilities: 优先级漏洞
- next_steps: 下一步建议
"""
