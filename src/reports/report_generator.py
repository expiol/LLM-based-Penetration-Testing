"""
报告生成器
生成渗透测试报告
"""
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..prompts.master_prompts import MasterPrompts


class ReportFormat(Enum):
    """报告格式"""
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    TEXT = "text"


@dataclass
class ReportSection:
    """报告章节"""
    title: str
    content: str
    level: int = 1
    subsections: List["ReportSection"] = field(default_factory=list)
    
    def to_markdown(self) -> str:
        """转换为Markdown格式"""
        lines = []
        header = "#" * self.level
        lines.append(f"{header} {self.title}\n")
        lines.append(self.content)
        lines.append("")
        
        for subsection in self.subsections:
            subsection.level = self.level + 1
            lines.append(subsection.to_markdown())
        
        return "\n".join(lines)


@dataclass
class ReportData:
    """报告数据"""
    # 基本信息
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    scope: str = "完整渗透测试"
    
    # 发现信息
    hosts: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    credentials: List[Dict[str, Any]] = field(default_factory=list)
    
    # 执行信息
    attacks: List[Dict[str, Any]] = field(default_factory=list)
    attack_path: str = ""
    
    # 统计信息
    statistics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "scope": self.scope,
            "hosts": self.hosts,
            "services": self.services,
            "vulnerabilities": self.vulnerabilities,
            "credentials": self.credentials,
            "attacks": self.attacks,
            "attack_path": self.attack_path,
            "statistics": self.statistics,
        }


class ReportGenerator:
    """
    报告生成器
    支持生成多种格式的渗透测试报告
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir) if output_dir else Path("./pentest_events/files/reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("report_generator")
    
    def generate(
        self,
        data: ReportData,
        format: ReportFormat = ReportFormat.MARKDOWN,
        template: Optional[str] = None
    ) -> str:
        """
        生成报告
        
        Args:
            data: 报告数据
            format: 报告格式
            template: 模板名称（可选）
            
        Returns:
            str: 报告内容
        """
        if format == ReportFormat.MARKDOWN:
            return self._generate_markdown(data)
        elif format == ReportFormat.HTML:
            return self._generate_html(data)
        elif format == ReportFormat.JSON:
            return self._generate_json(data)
        elif format == ReportFormat.TEXT:
            return self._generate_text(data)
        else:
            raise ValueError(f"不支持的报告格式: {format}")
    
    def _generate_markdown(self, data: ReportData) -> str:
        """生成Markdown格式报告"""
        sections = []
        
        # 标题
        sections.append("# 渗透测试报告\n")
        sections.append(f"**目标**: {data.target}\n")
        sections.append(f"**测试时间**: {data.start_time.strftime('%Y-%m-%d %H:%M:%S')} - {data.end_time.strftime('%Y-%m-%d %H:%M:%S') if data.end_time else '进行中'}\n")
        sections.append(f"**报告生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        sections.append("")
        
        # 目录
        sections.append("## 目录\n")
        sections.append("1. [执行摘要](#执行摘要)")
        sections.append("2. [测试范围与方法](#测试范围与方法)")
        sections.append("3. [发现的主机](#发现的主机)")
        sections.append("4. [发现的服务](#发现的服务)")
        sections.append("5. [漏洞发现](#漏洞发现)")
        sections.append("6. [凭证收集](#凭证收集)")
        sections.append("7. [攻击路径](#攻击路径)")
        sections.append("8. [统计信息](#统计信息)")
        sections.append("9. [修复建议](#修复建议)")
        sections.append("")
        
        # 执行摘要
        sections.append("## 执行摘要\n")
        sections.append(self._generate_executive_summary(data))
        sections.append("")
        
        # 测试范围与方法
        sections.append("## 测试范围与方法\n")
        sections.append(f"- **测试目标**: {data.target}")
        sections.append(f"- **测试范围**: {data.scope}")
        sections.append("- **测试方法**: 基于Cyber Kill Chain的自动化渗透测试")
        sections.append("")
        
        # 发现的主机
        sections.append("## 发现的主机\n")
        if data.hosts:
            sections.append("| IP地址 | 主机名 | 操作系统 | 状态 | 访问级别 |")
            sections.append("|--------|--------|----------|------|----------|")
            for host in data.hosts:
                sections.append(f"| {host.get('ip_address', 'N/A')} | {host.get('hostname', 'N/A')} | {host.get('os_name', 'N/A')} | {host.get('status', 'N/A')} | {host.get('access_level', 'N/A')} |")
        else:
            sections.append("*未发现主机*")
        sections.append("")
        
        # 发现的服务
        sections.append("## 发现的服务\n")
        if data.services:
            sections.append("| 主机 | 端口 | 服务 | 版本 |")
            sections.append("|------|------|------|------|")
            for service in data.services:
                sections.append(f"| {service.get('host', 'N/A')} | {service.get('port', 'N/A')}/{service.get('protocol', 'tcp')} | {service.get('service_name', 'N/A')} | {service.get('version', 'N/A')} |")
        else:
            sections.append("*未发现服务*")
        sections.append("")
        
        # 漏洞发现
        sections.append("## 漏洞发现\n")
        if data.vulnerabilities:
            # 按严重程度分组
            critical_vulns = [v for v in data.vulnerabilities if v.get('severity') == 'CRITICAL']
            high_vulns = [v for v in data.vulnerabilities if v.get('severity') == 'HIGH']
            medium_vulns = [v for v in data.vulnerabilities if v.get('severity') == 'MEDIUM']
            low_vulns = [v for v in data.vulnerabilities if v.get('severity') == 'LOW']
            
            if critical_vulns:
                sections.append("### 严重漏洞 🔴\n")
                for vuln in critical_vulns:
                    sections.append(self._format_vulnerability(vuln))
            
            if high_vulns:
                sections.append("### 高危漏洞 🟠\n")
                for vuln in high_vulns:
                    sections.append(self._format_vulnerability(vuln))
            
            if medium_vulns:
                sections.append("### 中危漏洞 🟡\n")
                for vuln in medium_vulns:
                    sections.append(self._format_vulnerability(vuln))
            
            if low_vulns:
                sections.append("### 低危漏洞 🟢\n")
                for vuln in low_vulns:
                    sections.append(self._format_vulnerability(vuln))
        else:
            sections.append("*未发现漏洞*")
        sections.append("")
        
        # 凭证收集
        sections.append("## 凭证收集\n")
        if data.credentials:
            sections.append("| 用户名 | 域 | 类型 | 来源 | 验证状态 |")
            sections.append("|--------|-----|------|------|----------|")
            for cred in data.credentials:
                sections.append(f"| {cred.get('username', 'N/A')} | {cred.get('domain', 'N/A')} | {cred.get('credential_type', 'N/A')} | {cred.get('source', 'N/A')} | {'✓' if cred.get('verified') else '✗'} |")
        else:
            sections.append("*未收集到凭证*")
        sections.append("")
        
        # 攻击路径
        sections.append("## 攻击路径\n")
        if data.attack_path:
            sections.append(data.attack_path)
        else:
            sections.append("*暂无攻击路径记录*")
        sections.append("")
        
        # 统计信息
        sections.append("## 统计信息\n")
        stats = data.statistics
        sections.append(f"- 发现主机: {stats.get('hosts_count', len(data.hosts))}")
        sections.append(f"- 发现服务: {stats.get('services_count', len(data.services))}")
        sections.append(f"- 发现漏洞: {stats.get('vulnerabilities_count', len(data.vulnerabilities))}")
        sections.append(f"- 收集凭证: {stats.get('credentials_count', len(data.credentials))}")
        sections.append(f"- 执行攻击: {stats.get('attacks_count', len(data.attacks))}")
        sections.append("")
        
        # 修复建议
        sections.append("## 修复建议\n")
        sections.append(self._generate_remediation_suggestions(data))
        sections.append("")
        
        # 免责声明
        sections.append("---\n")
        sections.append("## 免责声明\n")
        sections.append("本报告仅用于授权的安全评估目的。所有测试活动均在获得明确授权的前提下进行。")
        sections.append("报告中的发现和建议应由专业人员验证后实施。")
        
        return "\n".join(sections)
    
    def _generate_executive_summary(self, data: ReportData) -> str:
        """生成执行摘要"""
        summary_lines = []
        
        # 总体评估
        vuln_count = len(data.vulnerabilities)
        critical_count = len([v for v in data.vulnerabilities if v.get('severity') == 'CRITICAL'])
        high_count = len([v for v in data.vulnerabilities if v.get('severity') == 'HIGH'])
        
        if critical_count > 0:
            risk_level = "严重"
        elif high_count > 0:
            risk_level = "高"
        elif vuln_count > 0:
            risk_level = "中等"
        else:
            risk_level = "低"
        
        summary_lines.append(f"本次渗透测试针对目标 **{data.target}** 进行了全面的安全评估。")
        summary_lines.append(f"\n整体风险评级: **{risk_level}**")
        summary_lines.append(f"\n### 关键发现\n")
        summary_lines.append(f"- 发现 **{len(data.hosts)}** 个活跃主机")
        summary_lines.append(f"- 识别 **{len(data.services)}** 个服务")
        summary_lines.append(f"- 发现 **{vuln_count}** 个安全漏洞（严重: {critical_count}, 高危: {high_count}）")
        summary_lines.append(f"- 收集 **{len(data.credentials)}** 个凭证")
        
        return "\n".join(summary_lines)
    
    def _format_vulnerability(self, vuln: Dict[str, Any]) -> str:
        """格式化漏洞信息"""
        lines = []
        lines.append(f"**{vuln.get('vulnerability_type', '未知漏洞')}**")
        if vuln.get('cve_id'):
            lines.append(f"- CVE: {vuln.get('cve_id')}")
        if vuln.get('cvss_score'):
            lines.append(f"- CVSS: {vuln.get('cvss_score')}")
        lines.append(f"- 目标: {vuln.get('target_component', 'N/A')}")
        lines.append(f"- 发现方法: {vuln.get('discovery_method', 'N/A')}")
        if vuln.get('vulnerability_details'):
            details = vuln.get('vulnerability_details', {})
            if isinstance(details, dict):
                lines.append(f"- 详情: {json.dumps(details, ensure_ascii=False)}")
        lines.append("")
        return "\n".join(lines)
    
    def _generate_remediation_suggestions(self, data: ReportData) -> str:
        """生成修复建议"""
        suggestions = []
        
        # 根据漏洞生成建议
        for vuln in data.vulnerabilities:
            vuln_type = vuln.get('vulnerability_type', '')
            severity = vuln.get('severity', 'UNKNOWN')
            
            if severity in ('CRITICAL', 'HIGH'):
                suggestions.append(f"- **[紧急]** 修复 {vuln_type} 漏洞")
            elif severity == 'MEDIUM':
                suggestions.append(f"- **[重要]** 处理 {vuln_type} 问题")
            else:
                suggestions.append(f"- **[建议]** 关注 {vuln_type} 风险")
        
        if not suggestions:
            suggestions.append("- 继续保持当前的安全措施")
            suggestions.append("- 定期进行安全评估")
            suggestions.append("- 及时更新系统和软件")
        
        return "\n".join(suggestions)
    
    def _generate_html(self, data: ReportData) -> str:
        """生成HTML格式报告"""
        # 将Markdown转换为HTML
        import html
        md_content = self._generate_markdown(data)
        
        # 简单的Markdown到HTML转换
        html_content = md_content
        html_content = html.escape(html_content)
        
        # 转换标题
        for i in range(6, 0, -1):
            pattern = "#" * i + " "
            html_content = html_content.replace(f"\n{pattern}", f"\n<h{i}>")
            # 需要闭合标签
        
        # 生成完整HTML
        html_template = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>渗透测试报告 - {data.target}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{ color: #1a1a2e; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
        h2 {{ color: #16213e; margin-top: 30px; }}
        h3 {{ color: #0f3460; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #16213e; color: white; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .high {{ color: #fd7e14; font-weight: bold; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        pre {{ background-color: #f4f4f4; padding: 15px; border-radius: 4px; overflow-x: auto; }}
        code {{ background-color: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <pre>{html_content}</pre>
    </div>
</body>
</html>"""
        return html_template
    
    def _generate_json(self, data: ReportData) -> str:
        """生成JSON格式报告"""
        report = {
            "report_type": "penetration_test_report",
            "generated_at": datetime.now().isoformat(),
            "data": data.to_dict(),
        }
        return json.dumps(report, ensure_ascii=False, indent=2)
    
    def _generate_text(self, data: ReportData) -> str:
        """生成纯文本格式报告"""
        # 简单地从Markdown中移除格式标记
        md_content = self._generate_markdown(data)
        
        # 移除Markdown标记
        text_content = md_content
        text_content = text_content.replace("#", "")
        text_content = text_content.replace("**", "")
        text_content = text_content.replace("*", "")
        text_content = text_content.replace("|", "\t")
        
        return text_content
    
    def save_report(
        self,
        data: ReportData,
        filename: Optional[str] = None,
        format: ReportFormat = ReportFormat.MARKDOWN
    ) -> Path:
        """
        保存报告到文件
        
        Args:
            data: 报告数据
            filename: 文件名（可选）
            format: 报告格式
            
        Returns:
            Path: 保存的文件路径
        """
        # 生成报告内容
        content = self.generate(data, format)
        
        # 确定文件名和扩展名
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"pentest_report_{timestamp}"
        
        extensions = {
            ReportFormat.MARKDOWN: ".md",
            ReportFormat.HTML: ".html",
            ReportFormat.JSON: ".json",
            ReportFormat.TEXT: ".txt",
        }
        ext = extensions.get(format, ".txt")
        
        # 保存文件
        filepath = self.output_dir / f"{filename}{ext}"
        filepath.write_text(content, encoding="utf-8")
        
        self.logger.info(f"报告已保存: {filepath}")
        return filepath

