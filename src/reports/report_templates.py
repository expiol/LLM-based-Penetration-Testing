"""
报告模板
定义不同类型报告的模板
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List


class ReportTemplate(ABC):
    """报告模板基类"""
    
    def __init__(self, name: str):
        self.name = name
    
    @abstractmethod
    def render(self, data: Dict[str, Any]) -> str:
        """渲染报告"""
        pass


class ExecutiveSummaryTemplate(ReportTemplate):
    """执行摘要模板"""
    
    def __init__(self):
        super().__init__("executive_summary")
    
    def render(self, data: Dict[str, Any]) -> str:
        """渲染执行摘要"""
        target = data.get("target", "未知目标")
        start_time = data.get("start_time", "未知")
        end_time = data.get("end_time", "进行中")
        
        hosts = data.get("hosts", [])
        services = data.get("services", [])
        vulnerabilities = data.get("vulnerabilities", [])
        credentials = data.get("credentials", [])
        
        # 统计漏洞严重程度
        critical = len([v for v in vulnerabilities if v.get("severity") == "CRITICAL"])
        high = len([v for v in vulnerabilities if v.get("severity") == "HIGH"])
        medium = len([v for v in vulnerabilities if v.get("severity") == "MEDIUM"])
        low = len([v for v in vulnerabilities if v.get("severity") == "LOW"])
        
        # 确定风险等级
        if critical > 0:
            risk_level = "严重"
            risk_color = "🔴"
        elif high > 0:
            risk_level = "高"
            risk_color = "🟠"
        elif medium > 0:
            risk_level = "中等"
            risk_color = "🟡"
        else:
            risk_level = "低"
            risk_color = "🟢"
        
        summary = f"""# 执行摘要

## 项目概述

| 项目 | 信息 |
|------|------|
| 目标 | {target} |
| 测试开始时间 | {start_time} |
| 测试结束时间 | {end_time} |
| 整体风险等级 | {risk_color} {risk_level} |

## 关键发现

本次渗透测试共发现:

- **{len(hosts)}** 个活跃主机
- **{len(services)}** 个开放服务
- **{len(vulnerabilities)}** 个安全漏洞
  - 严重: {critical} 🔴
  - 高危: {high} 🟠
  - 中危: {medium} 🟡
  - 低危: {low} 🟢
- **{len(credentials)}** 个凭证

## 主要建议

"""
        if critical > 0:
            summary += "1. **立即处理** 所有严重漏洞\n"
        if high > 0:
            summary += "2. **优先修复** 高危漏洞\n"
        if len(credentials) > 0:
            summary += "3. **更改** 所有泄露的凭证\n"
        summary += "4. **定期** 进行安全评估\n"
        
        return summary


class TechnicalReportTemplate(ReportTemplate):
    """技术报告模板"""
    
    def __init__(self):
        super().__init__("technical_report")
    
    def render(self, data: Dict[str, Any]) -> str:
        """渲染技术报告"""
        target = data.get("target", "未知目标")
        hosts = data.get("hosts", [])
        services = data.get("services", [])
        attacks = data.get("attacks", [])
        attack_path = data.get("attack_path", "")
        
        report = f"""# 技术报告

## 测试目标

{target}

## 信息收集结果

### 发现的主机

"""
        if hosts:
            report += "| IP地址 | 主机名 | 操作系统 | MAC地址 |\n"
            report += "|--------|--------|----------|----------|\n"
            for host in hosts:
                report += f"| {host.get('ip_address', 'N/A')} | {host.get('hostname', 'N/A')} | {host.get('os_name', 'N/A')} | {host.get('mac_address', 'N/A')} |\n"
        else:
            report += "*未发现主机*\n"
        
        report += "\n### 发现的服务\n\n"
        
        if services:
            report += "| 主机 | 端口 | 协议 | 服务 | 版本 | 状态 |\n"
            report += "|------|------|------|------|------|------|\n"
            for service in services:
                report += f"| {service.get('host', 'N/A')} | {service.get('port', 'N/A')} | {service.get('protocol', 'tcp')} | {service.get('service_name', 'N/A')} | {service.get('version', 'N/A')} | {service.get('state', 'N/A')} |\n"
        else:
            report += "*未发现服务*\n"
        
        report += "\n## 攻击执行\n\n"
        
        if attacks:
            report += "### 执行的攻击操作\n\n"
            for i, attack in enumerate(attacks, 1):
                report += f"**{i}. {attack.get('action_name', '未知操作')}**\n"
                report += f"- 类型: {attack.get('action_type', 'N/A')}\n"
                report += f"- 目标: {attack.get('target_host', 'N/A')}:{attack.get('target_port', 'N/A')}\n"
                report += f"- 状态: {'成功 ✓' if attack.get('success') else '失败 ✗'}\n"
                if attack.get('summary'):
                    report += f"- 摘要: {attack.get('summary')}\n"
                report += "\n"
        else:
            report += "*未记录攻击操作*\n"
        
        if attack_path:
            report += f"\n## 攻击路径\n\n{attack_path}\n"
        
        return report


class VulnerabilityReportTemplate(ReportTemplate):
    """漏洞报告模板"""
    
    def __init__(self):
        super().__init__("vulnerability_report")
    
    def render(self, data: Dict[str, Any]) -> str:
        """渲染漏洞报告"""
        target = data.get("target", "未知目标")
        vulnerabilities = data.get("vulnerabilities", [])
        
        report = f"""# 漏洞评估报告

## 测试目标

{target}

## 漏洞统计

"""
        # 统计
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        report += "| 严重程度 | 数量 | 图示 |\n"
        report += "|----------|------|------|\n"
        report += f"| 严重 | {severity_counts['CRITICAL']} | {'🔴' * severity_counts['CRITICAL']} |\n"
        report += f"| 高危 | {severity_counts['HIGH']} | {'🟠' * severity_counts['HIGH']} |\n"
        report += f"| 中危 | {severity_counts['MEDIUM']} | {'🟡' * severity_counts['MEDIUM']} |\n"
        report += f"| 低危 | {severity_counts['LOW']} | {'🟢' * severity_counts['LOW']} |\n"
        
        report += "\n## 漏洞详情\n\n"
        
        # 按严重程度排序
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order.get(v.get("severity", "UNKNOWN"), 4))
        
        for i, vuln in enumerate(sorted_vulns, 1):
            severity = vuln.get("severity", "UNKNOWN")
            severity_icon = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢",
            }.get(severity, "⚪")
            
            report += f"### {i}. {severity_icon} {vuln.get('vulnerability_type', '未知漏洞')}\n\n"
            report += f"**严重程度**: {severity}\n\n"
            
            if vuln.get("cve_id"):
                report += f"**CVE编号**: {vuln.get('cve_id')}\n\n"
            
            if vuln.get("cvss_score"):
                report += f"**CVSS评分**: {vuln.get('cvss_score')}\n\n"
            
            report += f"**目标组件**: {vuln.get('target_component', 'N/A')}\n\n"
            report += f"**发现方法**: {vuln.get('discovery_method', 'N/A')}\n\n"
            
            if vuln.get("vulnerability_details"):
                report += f"**详细信息**: {vuln.get('vulnerability_details')}\n\n"
            
            if vuln.get("proof_of_concept"):
                report += f"**概念验证**:\n```\n{vuln.get('proof_of_concept')}\n```\n\n"
            
            # 修复建议
            report += "**修复建议**: "
            vuln_type = vuln.get("vulnerability_type", "").lower()
            if "sql" in vuln_type:
                report += "使用参数化查询，实施输入验证\n"
            elif "xss" in vuln_type:
                report += "实施输出编码，使用内容安全策略(CSP)\n"
            elif "rce" in vuln_type or "command" in vuln_type:
                report += "更新受影响组件，限制系统权限\n"
            elif "auth" in vuln_type:
                report += "加强认证机制，实施多因素认证\n"
            else:
                report += "请根据具体漏洞类型制定修复方案\n"
            
            report += "\n---\n\n"
        
        if not vulnerabilities:
            report += "*未发现漏洞*\n"
        
        return report

