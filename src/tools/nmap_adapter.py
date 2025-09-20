"""
Nmap适配器
提供端口扫描、服务识别等功能
"""
import logging
import subprocess
import json
from typing import Dict, Any, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class NmapAdapter:
    """Nmap适配器"""
    
    def __init__(self, safe_mode: bool = True):
        self.safe_mode = safe_mode
        self.nmap_path = self._find_nmap()
        
    def _find_nmap(self) -> Optional[str]:
        """
        查找nmap可执行文件路径
        
        Returns:
            Optional[str]: nmap路径
        """
        try:
            result = subprocess.run(['which', 'nmap'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            logger.warning(f"查找nmap失败: {e}")
        
        return None
    
    async def port_scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        scan_type: str = "tcp",
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        执行端口扫描
        
        Args:
            target: 目标地址
            ports: 端口列表
            scan_type: 扫描类型
            timeout: 超时时间
            
        Returns:
            Dict[str, Any]: 扫描结果
        """
        try:
            if not self.nmap_path:
                raise RuntimeError("nmap未找到，请确保已安装nmap")
            
            # 构建nmap命令
            cmd = [self.nmap_path, "-sS", "-sV", "-O", "--script=vuln", "-oX", "-"]
            
            if ports:
                port_str = ",".join(map(str, ports))
                cmd.extend(["-p", port_str])
            
            cmd.append(target)
            
            logger.info(f"执行nmap扫描: {' '.join(cmd)}")
            
            # 执行扫描
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"nmap扫描失败: {result.stderr}")
            
            # 解析XML结果
            scan_result = self._parse_nmap_xml(result.stdout)
            
            return {
                "success": True,
                "target": target,
                "scan_result": scan_result
            }
            
        except Exception as e:
            logger.error(f"端口扫描失败: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict[str, Any]:
        """
        解析nmap XML输出
        
        Args:
            xml_output: XML输出字符串
            
        Returns:
            Dict[str, Any]: 解析结果
        """
        try:
            # TODO: 实现XML解析逻辑
            # 这里应该使用xml.etree.ElementTree或lxml来解析XML
            
            return {
                "hosts": [],
                "services": [],
                "vulnerabilities": []
            }
            
        except Exception as e:
            logger.error(f"XML解析失败: {e}")
            return {}
    
    async def service_scan(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """
        执行服务扫描
        
        Args:
            target: 目标地址
            ports: 端口列表
            
        Returns:
            Dict[str, Any]: 扫描结果
        """
        try:
            # 使用端口扫描结果进行服务识别
            result = await self.port_scan(target, ports)
            
            if result["success"]:
                # 提取服务信息
                services = self._extract_services(result["scan_result"])
                result["services"] = services
            
            return result
            
        except Exception as e:
            logger.error(f"服务扫描失败: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _extract_services(self, scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        从扫描结果中提取服务信息
        
        Args:
            scan_result: 扫描结果
            
        Returns:
            List[Dict[str, Any]]: 服务信息列表
        """
        # TODO: 实现服务信息提取逻辑
        return []
    
    def is_available(self) -> bool:
        """
        检查nmap是否可用
        
        Returns:
            bool: 是否可用
        """
        return self.nmap_path is not None
