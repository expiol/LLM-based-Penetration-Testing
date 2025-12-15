"""
工具输出结构化解析器
负责过滤和提取不同工具输出中的有用信息
"""
import re
import json
import logging
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class ToolOutputParser(ABC):
    """工具输出解析器基类"""
    
    @abstractmethod
    def parse(self, raw_output: str) -> Dict[str, Any]:
        """解析原始输出，返回结构化数据"""
        pass
    
    @abstractmethod
    def get_summary(self, parsed_data: Dict[str, Any]) -> str:
        """获取简短摘要"""
        pass


class NmapOutputParser(ToolOutputParser):
    """Nmap输出解析器"""
    
    def parse(self, raw_output: str) -> Dict[str, Any]:
        """解析Nmap输出"""
        result = {
            "open_ports": [],
            "services": [],
            "os_info": None,
            "host_status": "unknown",
            "scan_stats": {}
        }
        
        try:
            # 解析开放端口
            port_pattern = r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?'
            for match in re.finditer(port_pattern, raw_output, re.IGNORECASE):
                port_info = {
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "state": match.group(3),
                    "service": match.group(4),
                    "version": match.group(5).strip() if match.group(5) else ""
                }
                if port_info["state"] == "open":
                    result["open_ports"].append(port_info["port"])
                    result["services"].append(port_info)
            
            # 从XML解析（如果有）
            if '<port ' in raw_output:
                result.update(self._parse_xml_output(raw_output))
            
            # 解析主机状态
            if 'Host is up' in raw_output:
                result["host_status"] = "up"
            elif 'Host seems down' in raw_output:
                result["host_status"] = "down"
            
            # 解析操作系统信息
            os_match = re.search(r'OS details?:\s*(.+)', raw_output)
            if os_match:
                result["os_info"] = os_match.group(1).strip()
            
        except Exception as e:
            logger.error(f"Nmap输出解析失败: {e}")
            result["parse_error"] = str(e)
        
        return result
    
    def _parse_xml_output(self, xml_output: str) -> Dict[str, Any]:
        """解析Nmap XML格式输出"""
        result = {"open_ports": [], "services": []}
        
        try:
            # 解析端口
            port_pattern = r'<port protocol="(\w+)" portid="(\d+)".*?<state state="(\w+)".*?(?:<service name="([^"]*)"[^>]*(?:product="([^"]*)")?[^>]*(?:version="([^"]*)")?)?'
            for match in re.finditer(port_pattern, xml_output, re.DOTALL):
                protocol, port, state = match.group(1), int(match.group(2)), match.group(3)
                service = match.group(4) or "unknown"
                product = match.group(5) or ""
                version = match.group(6) or ""
                
                if state == "open":
                    result["open_ports"].append(port)
                    result["services"].append({
                        "port": port,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "product": product,
                        "version": version
                    })
            
            # 解析主机名
            hostname_match = re.search(r'<hostname name="([^"]+)"', xml_output)
            if hostname_match:
                result["hostname"] = hostname_match.group(1)
                
        except Exception as e:
            logger.debug(f"XML解析错误: {e}")
        
        return result
    
    def get_summary(self, parsed_data: Dict[str, Any]) -> str:
        """获取Nmap扫描摘要"""
        open_ports = parsed_data.get("open_ports", [])
        services = parsed_data.get("services", [])
        host_status = parsed_data.get("host_status", "unknown")
        
        summary_parts = [f"主机状态: {host_status}"]
        
        if open_ports:
            summary_parts.append(f"开放端口: {len(open_ports)}个 ({', '.join(map(str, open_ports[:5]))}{'...' if len(open_ports) > 5 else ''})")
        
        if services:
            service_names = list(set(s.get("service", "unknown") for s in services))
            summary_parts.append(f"发现服务: {', '.join(service_names[:5])}")
        
        if parsed_data.get("os_info"):
            summary_parts.append(f"操作系统: {parsed_data['os_info'][:50]}")
        
        return " | ".join(summary_parts)


class CommandOutputParser(ToolOutputParser):
    """通用命令输出解析器"""
    
    def parse(self, raw_output: str) -> Dict[str, Any]:
        """解析命令输出"""
        return {
            "output": raw_output,
            "lines": raw_output.split('\n') if raw_output else [],
            "line_count": len(raw_output.split('\n')) if raw_output else 0,
            "has_error": any(err in raw_output.lower() for err in ['error', 'failed', 'denied', 'not found'])
        }
    
    def get_summary(self, parsed_data: Dict[str, Any]) -> str:
        """获取命令输出摘要"""
        line_count = parsed_data.get("line_count", 0)
        has_error = parsed_data.get("has_error", False)
        status = "有错误" if has_error else "正常"
        return f"输出 {line_count} 行 | 状态: {status}"


class SQLInjectionOutputParser(ToolOutputParser):
    """SQL注入测试输出解析器"""
    
    def parse(self, raw_output: str) -> Dict[str, Any]:
        """解析SQL注入测试输出"""
        result = {
            "vulnerable": False,
            "injection_points": [],
            "payloads_tested": 0,
            "databases_found": [],
            "tables_found": []
        }
        
        # 检测是否发现漏洞
        vuln_indicators = ['injectable', 'vulnerable', 'sql injection', 'database error']
        for indicator in vuln_indicators:
            if indicator in raw_output.lower():
                result["vulnerable"] = True
                break
        
        # 提取数据库信息
        db_pattern = r'database[:\s]+[\'"]?(\w+)[\'"]?'
        for match in re.finditer(db_pattern, raw_output, re.IGNORECASE):
            result["databases_found"].append(match.group(1))
        
        return result
    
    def get_summary(self, parsed_data: Dict[str, Any]) -> str:
        """获取SQL注入测试摘要"""
        vulnerable = parsed_data.get("vulnerable", False)
        status = "⚠️ 发现漏洞" if vulnerable else "✓ 未发现漏洞"
        dbs = parsed_data.get("databases_found", [])
        if dbs:
            return f"{status} | 发现数据库: {', '.join(dbs[:3])}"
        return status


class StructuredOutputManager:
    """结构化输出管理器 - 统一管理不同工具的输出解析"""
    
    def __init__(self):
        self.parsers: Dict[str, ToolOutputParser] = {
            "nmap": NmapOutputParser(),
            "nmap_scan": NmapOutputParser(),
            "cmd_exec": CommandOutputParser(),
            "execute_command": CommandOutputParser(),
            "sql_injection": SQLInjectionOutputParser(),
            "sql_injection_test": SQLInjectionOutputParser(),
        }
        self.default_parser = CommandOutputParser()
    
    def parse_output(self, tool_name: str, raw_output: str) -> Dict[str, Any]:
        """解析工具输出"""
        parser = self.parsers.get(tool_name, self.default_parser)
        parsed = parser.parse(raw_output)
        parsed["_tool"] = tool_name
        parsed["_summary"] = parser.get_summary(parsed)
        return parsed
    
    def get_summary(self, tool_name: str, parsed_data: Dict[str, Any]) -> str:
        """获取输出摘要"""
        parser = self.parsers.get(tool_name, self.default_parser)
        return parser.get_summary(parsed_data)
    
    def filter_for_llm(self, tool_name: str, raw_output: str, max_length: int = 4000) -> str:
        """
        过滤输出，只保留对LLM有用的信息
        用于返回给子Agent或主Agent
        
        Args:
            tool_name: 工具名称
            raw_output: 原始输出
            max_length: 最大长度（字符数），默认4000（约1000 tokens）
        """
        parsed = self.parse_output(tool_name, raw_output)
        
        # 构建精简的输出
        filtered_parts = []
        
        # 添加摘要
        summary = parsed.get("_summary", "")
        if summary:
            filtered_parts.append(f"【摘要】{summary}")
        
        # 根据工具类型添加关键信息
        if tool_name in ["nmap", "nmap_scan"]:
            if parsed.get("open_ports"):
                ports = parsed['open_ports']
                if isinstance(ports, list):
                    # 如果端口太多，只显示前20个
                    if len(ports) > 20:
                        ports_str = f"{ports[:20]}... (共{len(ports)}个端口)"
                    else:
                        ports_str = str(ports)
                else:
                    ports_str = str(ports)
                filtered_parts.append(f"【开放端口】{ports_str}")
            
            if parsed.get("services"):
                services = parsed["services"]
                # 限制服务数量，避免过长
                max_services = 15
                services_info = []
                for svc in services[:max_services]:
                    svc_str = f"{svc['port']}/{svc['protocol']}: {svc['service']}"
                    if svc.get('version'):
                        version = svc['version']
                        # 截断过长的版本信息
                        if len(version) > 50:
                            version = version[:50] + "..."
                        svc_str += f" ({version})"
                    services_info.append(svc_str)
                
                services_text = "\n".join(services_info)
                if len(services) > max_services:
                    services_text += f"\n... (共{len(services)}个服务，仅显示前{max_services}个)"
                
                filtered_parts.append(f"【服务详情】\n{services_text}")
            
            if parsed.get("os_info"):
                os_info = parsed['os_info']
                # 截断过长的OS信息
                if len(str(os_info)) > 200:
                    os_info = str(os_info)[:200] + "..."
                filtered_parts.append(f"【操作系统】{os_info}")
        
        elif tool_name in ["sql_injection", "sql_injection_test"]:
            if parsed.get("vulnerable"):
                filtered_parts.append("【漏洞状态】发现SQL注入漏洞！")
            if parsed.get("databases_found"):
                dbs = parsed['databases_found']
                if isinstance(dbs, list) and len(dbs) > 10:
                    dbs_str = f"{dbs[:10]}... (共{len(dbs)}个数据库)"
                else:
                    dbs_str = str(dbs)
                filtered_parts.append(f"【发现数据库】{dbs_str}")
        
        else:
            # 通用工具：取前N行有意义的输出
            lines = parsed.get("lines", [])
            meaningful_lines = [l for l in lines if l.strip() and not l.strip().startswith('#')]
            if meaningful_lines:
                # 限制行数，避免过长
                max_lines = 30
                display_lines = meaningful_lines[:max_lines]
                lines_text = "\n".join(display_lines)
                if len(meaningful_lines) > max_lines:
                    lines_text += f"\n... (共{len(meaningful_lines)}行，仅显示前{max_lines}行)"
                filtered_parts.append(f"【输出内容】\n{lines_text}")
        
        result = "\n\n".join(filtered_parts)
        
        # 智能截断过长内容（保留结构）
        if len(result) > max_length:
            # 尝试保留摘要和关键信息
            if summary and len(summary) < max_length // 2:
                # 保留摘要，截断其他部分
                remaining = max_length - len(summary) - 100  # 预留100字符给提示
                other_parts = "\n\n".join(filtered_parts[1:]) if len(filtered_parts) > 1 else ""
                if len(other_parts) > remaining:
                    other_parts = other_parts[:remaining] + "\n...[内容已截断]"
                result = f"【摘要】{summary}\n\n{other_parts}"
            else:
                # 简单截断
                result = result[:max_length] + "\n...[输出已截断]"
        
        return result


# 全局实例
output_manager = StructuredOutputManager()


