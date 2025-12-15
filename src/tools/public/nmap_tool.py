"""
Nmap工具 - 公有工具
所有Agent都可以使用的网络扫描工具
"""
import asyncio
import subprocess
import json
import re
import os
import sys
from typing import Dict, Any, List
from ...core.agent_tool_manager import ToolInterface


class NmapTool(ToolInterface):
    """Nmap网络扫描工具"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("nmap", config)
        self.timeout = config.get("timeout", 300)  # 5分钟超时
        self._has_root_privileges = None  # 缓存root权限检查结果
        
    async def _check_root_privileges(self) -> bool:
        """检查是否有root权限"""
        if self._has_root_privileges is not None:
            return self._has_root_privileges
        
        try:
            # 检查是否是root用户（Unix系统）
            if sys.platform != "win32":
                self._has_root_privileges = os.geteuid() == 0
            else:
                # Windows系统检查管理员权限
                import ctypes
                self._has_root_privileges = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            self._has_root_privileges = False
        
        return self._has_root_privileges
        
    def _build_command_string(self, parameters: Dict[str, Any]) -> str:
        """构建命令字符串（供基类使用）"""
        target = parameters.get("target", "")
        ports = parameters.get("ports", "1-1000")
        scan_type = parameters.get("scan_type", "tcp_syn")
        service_detection = parameters.get("service_detection", True)
        os_detection = parameters.get("os_detection", False)
        
        cmd_parts = ["nmap"]
        
        # 扫描类型
        if scan_type == "tcp_syn":
            cmd_parts.append("-sS")
        elif scan_type == "tcp_connect":
            cmd_parts.append("-sT")
        elif scan_type == "udp":
            cmd_parts.append("-sU")
        
        # 服务检测
        if service_detection:
            cmd_parts.extend(["-sV", "--version-intensity", "5"])
        
        # 操作系统检测
        if os_detection:
            cmd_parts.append("-O")
        
        # 端口范围
        cmd_parts.extend(["-p", str(ports)])
        
        # 目标
        if target:
            cmd_parts.append(target)
        
        return " ".join(cmd_parts)
    
    async def execute(self, parameters: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """执行Nmap扫描"""
        try:
            target = parameters.get("target")
            ports = parameters.get("ports", "1-1000")
            scan_type = parameters.get("scan_type", "tcp_syn")
            service_detection = parameters.get("service_detection", True)
            os_detection = parameters.get("os_detection", False)
            
            # 从context中读取timeout，如果存在则使用它（LLM指定的超时时间）
            # 优先级：context.timeout > parameters.timeout > self.timeout（默认值）
            dynamic_timeout = None
            if context:
                dynamic_timeout = context.get("timeout")
            if not dynamic_timeout:
                dynamic_timeout = parameters.get("timeout")
            
            # 使用动态timeout或默认timeout
            scan_timeout = dynamic_timeout if dynamic_timeout else self.timeout
            if dynamic_timeout:
                self.logger.info(f"使用LLM指定的超时时间: {scan_timeout}秒")
            
            if not target:
                return {"success": False, "error": "未指定目标"}
                        # 检查 nmap 二进制是否可用；不可用则尝试自动安装或降级回退
                        if not self._is_nmap_available():
                            self.logger.warning("nmap 二进制未找到，尝试自动安装或降级回退")
                            install_ok = await self._auto_install_on_windows()
                            if not install_ok and sys.platform != "win32":
                                # 非 Windows 的简单提示；安装逻辑在 AgentToolManager 中处理（apt/brew/pip）
                                self._add_output_line("⚠️ nmap 未安装，建议使用系统包管理器安装后重试")
                            # 再次检查
                            if self._is_nmap_available():
                                self._add_output_line("✅ 已检测到 nmap，可继续执行扫描")
                            else:
                                self._add_output_line("↩️ 降级到基础TCP端口扫描（Python实现）")
                                basic = await self._fallback_tcp_scan(target, ports, timeout=scan_timeout)
                                return basic
            
            # 立即更新执行状态，让UI可以看到
            # agent类型会自动从thread-local context获取
            self._update_execution_status(
                f"nmap -p {ports} {target}",
                f"扫描目标 {target} 的端口 {ports}"
            )
            self._add_output_line(f"🔍 开始Nmap扫描: {target}")
            self._add_output_line(f"📌 端口范围: {ports}")
            self._add_output_line(f"📌 扫描类型: {scan_type}")
            
            # 检查root权限，如果使用tcp_syn但没有权限，自动降级到tcp_connect
            has_root = await self._check_root_privileges()
            if scan_type == "tcp_syn" and not has_root:
                self.logger.warning("tcp_syn扫描需要root权限，自动降级到tcp_connect扫描")
                scan_type = "tcp_connect"
            
            # UDP扫描也需要root权限
            if scan_type == "udp" and not has_root:
                self.logger.warning("UDP扫描需要root权限，自动降级到tcp_connect扫描")
                scan_type = "tcp_connect"
            
            # 操作系统检测也需要root权限
            if os_detection and not has_root:
                self.logger.warning("操作系统检测需要root权限，已禁用")
                os_detection = False
            
            # 构建Nmap命令
            cmd = ["nmap"]
            
            # 扫描类型
            if scan_type == "tcp_syn":
                cmd.append("-sS")
            elif scan_type == "tcp_connect":
                cmd.append("-sT")
            elif scan_type == "udp":
                cmd.append("-sU")
            
            # 服务检测
            if service_detection:
                cmd.extend(["-sV", "--version-intensity", "5"])
            
            # 操作系统检测
            if os_detection:
                cmd.append("-O")
            
            # 端口范围
            cmd.extend(["-p", str(ports)])
            
            # 输出格式
            cmd.extend(["-oX", "-"])  # XML输出到stdout
            
            # 目标
            cmd.append(target)
            
            # 构建完整命令字符串
            full_command = " ".join(cmd)
            self.logger.info(f"执行Nmap扫描: {full_command}")
            
            # 执行扫描
            result = await self._run_command(cmd, timeout=scan_timeout)
            
            # 如果失败且错误信息包含权限相关，尝试降级
            if not result.get("success", False):
                error_msg = result.get("stderr", "").lower()
                if ("root" in error_msg or "privileges" in error_msg or "permission" in error_msg) and scan_type != "tcp_connect":
                    self.logger.warning("检测到权限错误，尝试使用tcp_connect扫描")
                    # 移除-sS或-sU，添加-sT
                    cmd = [c for c in cmd if c not in ["-sS", "-sU"]]
                    if "-sT" not in cmd:
                        cmd.insert(1, "-sT")
                    # 移除-O（OS检测需要root）
                    if "-O" in cmd:
                        cmd.remove("-O")
                    
                    self.logger.info(f"重试Nmap扫描（降级模式）: {' '.join(cmd)}")
                    result = await self._run_command(cmd, timeout=scan_timeout)
                    scan_type = "tcp_connect"
            
            if result.get("success", False):
                # 解析XML结果
                stdout = result.get("stdout", "")
                parsed_result = self._parse_nmap_xml(stdout)
                
                # 返回结果（输出捕获由基类处理）
                return {
                    "success": True,
                    "tool": self.name,
                    "target": target,
                    "scan_type": scan_type,
                    "result": parsed_result,
                    "raw_output": stdout,
                    "command": full_command,  # 包含命令，供基类使用
                    "privilege_note": "使用tcp_connect扫描（无需root权限）" if scan_type == "tcp_connect" else None
                }
            else:
                # 返回错误（错误捕获由基类处理）
                return {
                    "success": False,
                    "error": result.get("stderr", "Nmap扫描失败"),
                    "command": full_command
                }
                
        except Exception as e:
            self.logger.error(f"Nmap工具执行失败: {e}")
            return {"success": False, "error": str(e)}
    
    def get_description(self) -> str:
        return "网络端口扫描和服务识别工具，支持TCP/UDP扫描、服务版本检测、操作系统识别"
    
    def get_parameters(self) -> Dict[str, Any]:
        return {
            "required": ["target"],
            "optional": {
                "ports": "扫描端口范围，默认1-1000，支持格式: 80,443,8080 或 1-1000",
                "scan_type": "扫描类型: tcp_syn(默认), tcp_connect, udp",
                "service_detection": "是否进行服务检测，默认True",
                "os_detection": "是否进行操作系统检测，默认False",
                "timeout": "扫描超时时间(秒)，默认300"
            }
        }
    
    def get_capabilities(self) -> List[str]:
        return [
            "port_scanning", 
            "service_detection", 
            "os_detection", 
            "network_discovery",
            "vulnerability_scanning",
            "tcp_scanning",
            "udp_scanning"
        ]
    
    async def _run_command(self, cmd: List[str], timeout: float = None) -> Dict[str, Any]:
        """运行命令 - 使用基类的通用流式执行方法"""
        scan_timeout = timeout if timeout else self.timeout
        
        # 使用基类的通用流式命令执行方法
        return await self.run_command_with_streaming(
            cmd=cmd,
            timeout=scan_timeout,
            description=f"Nmap扫描"
        )
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict[str, Any]:
        """解析Nmap XML输出"""
        try:
            import xml.etree.ElementTree as ET
            
            # 解析XML
            root = ET.fromstring(xml_output)
            
            result = {
                "scan_info": {},
                "hosts": [],
                "summary": {}
            }
            
            # 扫描信息
            for scaninfo in root.findall("scaninfo"):
                result["scan_info"] = {
                    "type": scaninfo.get("type"),
                    "protocol": scaninfo.get("protocol"),
                    "numservices": scaninfo.get("numservices")
                }
            
            # 主机信息
            for host in root.findall("host"):
                host_info = self._parse_host(host)
                if host_info:
                    result["hosts"].append(host_info)
            
            # 统计信息
            for runstats in root.findall("runstats"):
                finished = runstats.find("finished")
                if finished is not None:
                    result["summary"]["scan_time"] = finished.get("elapsed")
                    result["summary"]["exit_status"] = finished.get("exit")
            
            return result
            
        except Exception as e:
            self.logger.error(f"解析Nmap XML失败: {e}")
            return self._parse_nmap_text(xml_output)
    
    def _parse_host(self, host_elem) -> Dict[str, Any]:
        """解析单个主机信息"""
        host_info = {
            "addresses": [],
            "hostnames": [],
            "status": {},
            "ports": [],
            "os": {}
        }
        
        # 地址信息
        for address in host_elem.findall("address"):
            host_info["addresses"].append({
                "addr": address.get("addr"),
                "addrtype": address.get("addrtype")
            })
        
        # 主机名
        for hostname in host_elem.findall("hostnames/hostname"):
            host_info["hostnames"].append({
                "name": hostname.get("name"),
                "type": hostname.get("type")
            })
        
        # 状态
        status = host_elem.find("status")
        if status is not None:
            host_info["status"] = {
                "state": status.get("state"),
                "reason": status.get("reason")
            }
        
        # 端口信息
        ports = host_elem.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                port_info = self._parse_port(port)
                if port_info:
                    host_info["ports"].append(port_info)
        
        # 操作系统信息
        os_elem = host_elem.find("os")
        if os_elem is not None:
            host_info["os"] = self._parse_os(os_elem)
        
        return host_info
    
    def _parse_port(self, port_elem) -> Dict[str, Any]:
        """解析端口信息"""
        port_info = {
            "portid": port_elem.get("portid"),
            "protocol": port_elem.get("protocol"),
            "state": {},
            "service": {}
        }
        
        # 状态
        state = port_elem.find("state")
        if state is not None:
            port_info["state"] = {
                "state": state.get("state"),
                "reason": state.get("reason")
            }
        
        # 服务
        service = port_elem.find("service")
        if service is not None:
            port_info["service"] = {
                "name": service.get("name"),
                "product": service.get("product"),
                "version": service.get("version"),
                "extrainfo": service.get("extrainfo"),
                "conf": service.get("conf")
            }
        
        return port_info
    
    def _parse_os(self, os_elem) -> Dict[str, Any]:
        """解析操作系统信息"""
        os_info = {
            "portused": [],
            "osmatch": []
        }
        
        for portused in os_elem.findall("portused"):
            os_info["portused"].append({
                "state": portused.get("state"),
                "proto": portused.get("proto"),
                "portid": portused.get("portid")
            })
        
        for osmatch in os_elem.findall("osmatch"):
            os_info["osmatch"].append({
                "name": osmatch.get("name"),
                "accuracy": osmatch.get("accuracy"),
                "line": osmatch.get("line")
            })
        
        return os_info
    
    def _parse_nmap_text(self, text_output: str) -> Dict[str, Any]:
        """简单文本解析作为备选方案"""
        result = {
            "open_ports": [],
            "services": [],
            "os_info": {},
            "raw_output": text_output
        }
        
        # 提取开放端口
        port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)'
        for match in re.finditer(port_pattern, text_output):
            port, protocol, service = match.groups()
            result["open_ports"].append({
                "port": int(port),
                "protocol": protocol,
                "service": service,
                "state": "open"
            })
        
        return result
