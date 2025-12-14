"""
Nmap输出解析器
解析Nmap扫描结果并提取服务、端口、主机信息
"""
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from .base_parser import BaseParser, ParseResult, ParseResultType, parser_registry


class NmapParser(BaseParser):
    """
    Nmap输出解析器
    支持解析XML和文本格式的Nmap输出
    """
    
    def __init__(self):
        super().__init__("nmap")
        
        # 编译常用的正则模式
        self._compile_pattern(
            "port_open",
            r'(\d+)/(tcp|udp)\s+(open)\s+(\S+)(?:\s+(.+))?'
        )
        self._compile_pattern(
            "port_filtered",
            r'(\d+)/(tcp|udp)\s+(filtered|closed)\s+(\S+)'
        )
        self._compile_pattern(
            "host_status",
            r'Host:\s+(\S+)\s+\(([^)]*)\)\s+Status:\s+(\w+)'
        )
        self._compile_pattern(
            "scan_target",
            r'Nmap scan report for\s+(\S+)(?:\s+\(([^)]+)\))?'
        )
        self._compile_pattern(
            "os_detection",
            r'OS details:\s+(.+)'
        )
        self._compile_pattern(
            "mac_address",
            r'MAC Address:\s+([0-9A-Fa-f:]+)(?:\s+\(([^)]+)\))?'
        )
        self._compile_pattern(
            "service_version",
            r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+)'
        )
    
    def can_parse(self, text: str) -> bool:
        """检查是否为Nmap输出"""
        # 检查XML格式
        if '<?xml' in text and '<nmaprun' in text:
            return True
        # 检查文本格式
        nmap_indicators = [
            'Nmap scan report',
            'Starting Nmap',
            'Host is up',
            'PORT\\s+STATE\\s+SERVICE',
            'Nmap done:',
        ]
        for indicator in nmap_indicators:
            if re.search(indicator, text, re.IGNORECASE):
                return True
        return False
    
    def parse(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[ParseResult]:
        """解析Nmap输出"""
        results = []
        
        # 清理文本
        text = self._clean_text(text)
        
        # 尝试XML解析
        if '<?xml' in text and '<nmaprun' in text:
            try:
                results.extend(self._parse_xml(text, context))
                return results
            except ET.ParseError:
                self.logger.warning("XML解析失败，尝试文本解析")
        
        # 文本解析
        results.extend(self._parse_text(text, context))
        
        return results
    
    def _parse_xml(self, xml_text: str, context: Optional[Dict[str, Any]] = None) -> List[ParseResult]:
        """解析XML格式的Nmap输出"""
        results = []
        
        try:
            root = ET.fromstring(xml_text)
            
            # 解析扫描信息
            scan_info = self._parse_scan_info_xml(root)
            if scan_info:
                results.append(ParseResult(
                    result_type=ParseResultType.UNKNOWN,
                    data=scan_info,
                    source="nmap",
                    metadata={"type": "scan_info"}
                ))
            
            # 解析每个主机
            for host in root.findall("host"):
                host_results = self._parse_host_xml(host)
                results.extend(host_results)
            
        except Exception as e:
            self.logger.error(f"XML解析错误: {e}")
        
        return results
    
    def _parse_scan_info_xml(self, root: ET.Element) -> Dict[str, Any]:
        """解析扫描信息"""
        scan_info = {}
        
        for scaninfo in root.findall("scaninfo"):
            scan_info["scan_type"] = scaninfo.get("type", "")
            scan_info["protocol"] = scaninfo.get("protocol", "")
            scan_info["num_services"] = scaninfo.get("numservices", "")
        
        for runstats in root.findall("runstats"):
            finished = runstats.find("finished")
            if finished is not None:
                scan_info["scan_time"] = finished.get("elapsed", "")
                scan_info["exit_status"] = finished.get("exit", "")
            
            hosts_elem = runstats.find("hosts")
            if hosts_elem is not None:
                scan_info["hosts_up"] = hosts_elem.get("up", "0")
                scan_info["hosts_down"] = hosts_elem.get("down", "0")
        
        return scan_info
    
    def _parse_host_xml(self, host_elem: ET.Element) -> List[ParseResult]:
        """解析主机信息"""
        results = []
        
        # 获取主机地址
        addresses = []
        hostnames = []
        
        for address in host_elem.findall("address"):
            addr_info = {
                "addr": address.get("addr", ""),
                "addrtype": address.get("addrtype", ""),
                "vendor": address.get("vendor", ""),
            }
            addresses.append(addr_info)
        
        for hostname in host_elem.findall("hostnames/hostname"):
            hostnames.append({
                "name": hostname.get("name", ""),
                "type": hostname.get("type", ""),
            })
        
        # 获取主机状态
        status_elem = host_elem.find("status")
        status = {
            "state": status_elem.get("state", "") if status_elem is not None else "",
            "reason": status_elem.get("reason", "") if status_elem is not None else "",
        }
        
        # 创建主机结果
        host_data = {
            "addresses": addresses,
            "hostnames": hostnames,
            "status": status,
        }
        
        # 获取主要IP
        primary_ip = ""
        for addr in addresses:
            if addr.get("addrtype") == "ipv4":
                primary_ip = addr.get("addr", "")
                break
        if not primary_ip and addresses:
            primary_ip = addresses[0].get("addr", "")
        
        results.append(ParseResult(
            result_type=ParseResultType.HOST,
            data=host_data,
            source="nmap",
            metadata={"ip": primary_ip}
        ))
        
        # 解析端口和服务
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                port_results = self._parse_port_xml(port, primary_ip)
                results.extend(port_results)
        
        # 解析操作系统信息
        os_elem = host_elem.find("os")
        if os_elem is not None:
            os_data = self._parse_os_xml(os_elem)
            if os_data:
                results.append(ParseResult(
                    result_type=ParseResultType.HOST,
                    data={"os_info": os_data, "ip": primary_ip},
                    source="nmap",
                    metadata={"type": "os_detection", "ip": primary_ip}
                ))
        
        return results
    
    def _parse_port_xml(self, port_elem: ET.Element, host_ip: str) -> List[ParseResult]:
        """解析端口信息"""
        results = []
        
        port_id = port_elem.get("portid", "")
        protocol = port_elem.get("protocol", "")
        
        # 端口状态
        state_elem = port_elem.find("state")
        state = {
            "state": state_elem.get("state", "") if state_elem is not None else "",
            "reason": state_elem.get("reason", "") if state_elem is not None else "",
        }
        
        # 服务信息
        service_elem = port_elem.find("service")
        service = {}
        if service_elem is not None:
            service = {
                "name": service_elem.get("name", ""),
                "product": service_elem.get("product", ""),
                "version": service_elem.get("version", ""),
                "extrainfo": service_elem.get("extrainfo", ""),
                "ostype": service_elem.get("ostype", ""),
                "method": service_elem.get("method", ""),
                "conf": service_elem.get("conf", ""),
            }
        
        port_data = {
            "port": port_id,
            "protocol": protocol,
            "state": state,
            "service": service,
            "host": host_ip,
        }
        
        # 添加端口结果
        results.append(ParseResult(
            result_type=ParseResultType.PORT,
            data=port_data,
            source="nmap",
            metadata={"host": host_ip}
        ))
        
        # 如果端口开放且有服务信息，添加服务结果
        if state.get("state") == "open" and service.get("name"):
            service_data = {
                "host": host_ip,
                "port": port_id,
                "protocol": protocol,
                "service_name": service.get("name", ""),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
                "extra_info": service.get("extrainfo", ""),
            }
            results.append(ParseResult(
                result_type=ParseResultType.SERVICE,
                data=service_data,
                source="nmap",
                metadata={"host": host_ip, "port": port_id}
            ))
        
        return results
    
    def _parse_os_xml(self, os_elem: ET.Element) -> Dict[str, Any]:
        """解析操作系统信息"""
        os_info = {
            "matches": [],
            "ports_used": [],
        }
        
        for portused in os_elem.findall("portused"):
            os_info["ports_used"].append({
                "state": portused.get("state", ""),
                "proto": portused.get("proto", ""),
                "portid": portused.get("portid", ""),
            })
        
        for osmatch in os_elem.findall("osmatch"):
            os_info["matches"].append({
                "name": osmatch.get("name", ""),
                "accuracy": osmatch.get("accuracy", ""),
            })
        
        return os_info
    
    def _parse_text(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[ParseResult]:
        """解析文本格式的Nmap输出"""
        results = []
        current_host = None
        
        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # 检测目标主机
            target_match = self._patterns["scan_target"].search(line)
            if target_match:
                hostname = target_match.group(1)
                ip = target_match.group(2) if target_match.lastindex >= 2 else hostname
                current_host = ip if ip else hostname
                
                results.append(ParseResult(
                    result_type=ParseResultType.HOST,
                    data={
                        "hostname": hostname,
                        "ip": current_host,
                        "status": "up",
                    },
                    source="nmap",
                    metadata={"ip": current_host}
                ))
                continue
            
            # 检测开放端口
            port_match = self._patterns["port_open"].search(line)
            if port_match:
                port = port_match.group(1)
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                version = port_match.group(5) if port_match.lastindex >= 5 else ""
                
                port_data = {
                    "port": port,
                    "protocol": protocol,
                    "state": {"state": state},
                    "service": {"name": service, "version": version},
                    "host": current_host or "unknown",
                }
                
                results.append(ParseResult(
                    result_type=ParseResultType.PORT,
                    data=port_data,
                    source="nmap",
                    metadata={"host": current_host}
                ))
                
                # 同时添加服务信息
                if state == "open":
                    service_data = {
                        "host": current_host or "unknown",
                        "port": port,
                        "protocol": protocol,
                        "service_name": service,
                        "version": version.strip() if version else "",
                    }
                    results.append(ParseResult(
                        result_type=ParseResultType.SERVICE,
                        data=service_data,
                        source="nmap",
                        metadata={"host": current_host, "port": port}
                    ))
                continue
            
            # 检测操作系统
            os_match = self._patterns["os_detection"].search(line)
            if os_match:
                os_details = os_match.group(1)
                results.append(ParseResult(
                    result_type=ParseResultType.HOST,
                    data={
                        "ip": current_host or "unknown",
                        "os_info": {"matches": [{"name": os_details}]},
                    },
                    source="nmap",
                    metadata={"type": "os_detection", "ip": current_host}
                ))
                continue
            
            # 检测MAC地址
            mac_match = self._patterns["mac_address"].search(line)
            if mac_match:
                mac = mac_match.group(1)
                vendor = mac_match.group(2) if mac_match.lastindex >= 2 else ""
                results.append(ParseResult(
                    result_type=ParseResultType.HOST,
                    data={
                        "ip": current_host or "unknown",
                        "mac_address": mac,
                        "mac_vendor": vendor,
                    },
                    source="nmap",
                    metadata={"type": "mac_address", "ip": current_host}
                ))
        
        return results
    
    def get_open_ports(self, results: List[ParseResult]) -> List[Dict[str, Any]]:
        """
        从解析结果中提取开放端口列表
        
        Args:
            results: 解析结果列表
            
        Returns:
            List[Dict[str, Any]]: 开放端口列表
        """
        open_ports = []
        for result in results:
            if result.result_type == ParseResultType.PORT:
                state = result.data.get("state", {})
                if state.get("state") == "open":
                    open_ports.append({
                        "host": result.data.get("host", ""),
                        "port": result.data.get("port", ""),
                        "protocol": result.data.get("protocol", ""),
                        "service": result.data.get("service", {}).get("name", ""),
                    })
        return open_ports
    
    def get_services(self, results: List[ParseResult]) -> List[Dict[str, Any]]:
        """
        从解析结果中提取服务列表
        
        Args:
            results: 解析结果列表
            
        Returns:
            List[Dict[str, Any]]: 服务列表
        """
        services = []
        for result in results:
            if result.result_type == ParseResultType.SERVICE:
                services.append(result.data)
        return services


# 注册解析器
parser_registry.register(NmapParser())

