"""
服务解析器
解析和识别服务信息
"""
import re
from typing import Any, Dict, List, Optional

from .base_parser import BaseParser, ParseResult, ParseResultType, parser_registry


# 常见服务和默认端口映射
SERVICE_PORT_MAPPING = {
    "ftp": [20, 21],
    "ssh": [22],
    "telnet": [23],
    "smtp": [25, 587],
    "dns": [53],
    "http": [80, 8080, 8000, 8888],
    "pop3": [110],
    "imap": [143],
    "https": [443, 8443],
    "smb": [139, 445],
    "ldap": [389],
    "ldaps": [636],
    "mssql": [1433],
    "mysql": [3306],
    "rdp": [3389],
    "postgresql": [5432],
    "vnc": [5900, 5901, 5902],
    "redis": [6379],
    "elasticsearch": [9200, 9300],
    "mongodb": [27017],
    "docker": [2375, 2376],
    "kubernetes": [6443, 10250],
    "jenkins": [8080],
    "tomcat": [8080, 8005],
    "weblogic": [7001, 7002],
    "jboss": [8080, 9990],
}

# 服务指纹和潜在漏洞映射
SERVICE_VULNERABILITIES = {
    "ftp": ["匿名登录", "弱密码", "目录遍历"],
    "ssh": ["弱密码", "过时版本", "密钥泄露"],
    "telnet": ["明文传输", "弱密码"],
    "smtp": ["开放中继", "用户枚举"],
    "http": ["SQL注入", "XSS", "目录遍历", "敏感信息泄露"],
    "https": ["SSL/TLS漏洞", "证书问题"],
    "smb": ["EternalBlue", "匿名共享", "弱密码"],
    "ldap": ["匿名绑定", "信息泄露"],
    "mssql": ["xp_cmdshell", "弱密码", "SQL注入"],
    "mysql": ["弱密码", "远程代码执行", "信息泄露"],
    "rdp": ["BlueKeep", "弱密码", "NLA绕过"],
    "postgresql": ["弱密码", "配置错误"],
    "redis": ["未授权访问", "主从复制RCE"],
    "elasticsearch": ["未授权访问", "远程代码执行"],
    "mongodb": ["未授权访问", "弱密码"],
    "jenkins": ["弱密码", "脚本控制台RCE"],
    "tomcat": ["默认凭证", "管理器漏洞"],
    "weblogic": ["反序列化", "SSRF", "RCE"],
    "jboss": ["反序列化", "管理控制台漏洞"],
    "docker": ["未授权访问", "容器逃逸"],
    "kubernetes": ["未授权访问", "RBAC配置错误"],
}


class ServiceParser(BaseParser):
    """
    服务解析器
    识别和分析服务信息
    """
    
    def __init__(self):
        super().__init__("service")
        
        # 服务版本模式
        self._compile_pattern(
            "apache_version",
            r'Apache[/ ]?([\d.]+)',
            re.IGNORECASE
        )
        self._compile_pattern(
            "nginx_version",
            r'nginx[/ ]?([\d.]+)',
            re.IGNORECASE
        )
        self._compile_pattern(
            "openssh_version",
            r'OpenSSH[_/ ]?([\d.p]+)',
            re.IGNORECASE
        )
        self._compile_pattern(
            "mysql_version",
            r'MySQL[/ ]?([\d.]+)',
            re.IGNORECASE
        )
        self._compile_pattern(
            "postgresql_version",
            r'PostgreSQL[/ ]?([\d.]+)',
            re.IGNORECASE
        )
        self._compile_pattern(
            "microsoft_iis",
            r'Microsoft[- ]IIS[/ ]?([\d.]+)?',
            re.IGNORECASE
        )
        self._compile_pattern(
            "tomcat_version",
            r'Apache Tomcat[/ ]?([\d.]+)',
            re.IGNORECASE
        )
        self._compile_pattern(
            "php_version",
            r'PHP[/ ]?([\d.]+)',
            re.IGNORECASE
        )
        
        # HTTP响应头模式
        self._compile_pattern(
            "server_header",
            r'Server:\s*(.+)',
            re.IGNORECASE
        )
        self._compile_pattern(
            "powered_by",
            r'X-Powered-By:\s*(.+)',
            re.IGNORECASE
        )
    
    def can_parse(self, text: str) -> bool:
        """检查是否包含服务信息"""
        service_indicators = [
            r'Server:',
            r'X-Powered-By:',
            r'Apache',
            r'nginx',
            r'OpenSSH',
            r'MySQL',
            r'PostgreSQL',
            r'Microsoft-IIS',
            r'Tomcat',
            r'php',
            r'open\s+\w+',  # nmap格式的开放端口
        ]
        for indicator in service_indicators:
            if re.search(indicator, text, re.IGNORECASE):
                return True
        return False
    
    def parse(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[ParseResult]:
        """解析服务信息"""
        results = []
        
        # 清理文本
        text = self._clean_text(text)
        
        # 解析HTTP响应头中的服务信息
        results.extend(self._parse_http_headers(text))
        
        # 解析服务版本
        results.extend(self._parse_service_versions(text))
        
        return results
    
    def _parse_http_headers(self, text: str) -> List[ParseResult]:
        """解析HTTP响应头"""
        results = []
        
        # Server头
        for match in self._patterns["server_header"].finditer(text):
            server_info = match.group(1).strip()
            service_data = self._analyze_server_string(server_info)
            
            results.append(ParseResult(
                result_type=ParseResultType.SERVICE,
                data={
                    "raw_server": server_info,
                    **service_data,
                },
                source="service_parser",
                confidence=0.9,
                raw_text=match.group(0),
                metadata={"source": "http_header"}
            ))
        
        # X-Powered-By头
        for match in self._patterns["powered_by"].finditer(text):
            powered_by = match.group(1).strip()
            
            results.append(ParseResult(
                result_type=ParseResultType.SERVICE,
                data={
                    "framework": powered_by,
                    "header_type": "x-powered-by",
                },
                source="service_parser",
                confidence=0.85,
                raw_text=match.group(0),
                metadata={"source": "http_header"}
            ))
        
        return results
    
    def _parse_service_versions(self, text: str) -> List[ParseResult]:
        """解析服务版本信息"""
        results = []
        
        version_patterns = {
            "apache": self._patterns["apache_version"],
            "nginx": self._patterns["nginx_version"],
            "openssh": self._patterns["openssh_version"],
            "mysql": self._patterns["mysql_version"],
            "postgresql": self._patterns["postgresql_version"],
            "iis": self._patterns["microsoft_iis"],
            "tomcat": self._patterns["tomcat_version"],
            "php": self._patterns["php_version"],
        }
        
        for service_name, pattern in version_patterns.items():
            for match in pattern.finditer(text):
                version = match.group(1) if match.lastindex >= 1 else ""
                
                # 获取潜在漏洞
                potential_vulns = self._get_potential_vulnerabilities(service_name, version)
                
                results.append(ParseResult(
                    result_type=ParseResultType.SERVICE,
                    data={
                        "service_name": service_name,
                        "version": version,
                        "potential_vulnerabilities": potential_vulns,
                    },
                    source="service_parser",
                    confidence=0.95,
                    raw_text=match.group(0),
                    metadata={"type": "version_detection"}
                ))
        
        return results
    
    def _analyze_server_string(self, server_string: str) -> Dict[str, Any]:
        """分析Server字符串"""
        result = {
            "server_type": "unknown",
            "version": "",
            "modules": [],
            "os_hint": "",
        }
        
        # 检测服务器类型
        server_lower = server_string.lower()
        
        if "apache" in server_lower:
            result["server_type"] = "apache"
            match = re.search(r'Apache[/ ]?([\d.]+)', server_string, re.IGNORECASE)
            if match:
                result["version"] = match.group(1)
            
            # 检测模块
            modules = re.findall(r'\(([^)]+)\)', server_string)
            result["modules"] = modules
            
            # 检测OS
            if "unix" in server_lower:
                result["os_hint"] = "unix"
            elif "win" in server_lower:
                result["os_hint"] = "windows"
            elif "debian" in server_lower:
                result["os_hint"] = "debian"
            elif "ubuntu" in server_lower:
                result["os_hint"] = "ubuntu"
            elif "centos" in server_lower:
                result["os_hint"] = "centos"
            elif "red hat" in server_lower:
                result["os_hint"] = "redhat"
        
        elif "nginx" in server_lower:
            result["server_type"] = "nginx"
            match = re.search(r'nginx[/ ]?([\d.]+)', server_string, re.IGNORECASE)
            if match:
                result["version"] = match.group(1)
        
        elif "iis" in server_lower or "microsoft" in server_lower:
            result["server_type"] = "iis"
            result["os_hint"] = "windows"
            match = re.search(r'IIS[/ ]?([\d.]+)', server_string, re.IGNORECASE)
            if match:
                result["version"] = match.group(1)
        
        elif "lighttpd" in server_lower:
            result["server_type"] = "lighttpd"
        
        elif "tomcat" in server_lower:
            result["server_type"] = "tomcat"
            match = re.search(r'Tomcat[/ ]?([\d.]+)', server_string, re.IGNORECASE)
            if match:
                result["version"] = match.group(1)
        
        return result
    
    def _get_potential_vulnerabilities(self, service_name: str, version: str) -> List[str]:
        """获取潜在漏洞列表"""
        # 基本漏洞列表
        base_vulns = SERVICE_VULNERABILITIES.get(service_name, [])
        
        # 这里可以添加版本特定的漏洞检查
        # 例如，OpenSSH 7.x之前版本可能存在某些漏洞
        version_specific_vulns = []
        
        if service_name == "openssh" and version:
            try:
                major_version = int(version.split('.')[0])
                if major_version < 7:
                    version_specific_vulns.append("CVE-2016-0777/0778 (roaming)")
                if major_version < 8:
                    version_specific_vulns.append("可能存在用户枚举漏洞")
            except (ValueError, IndexError):
                pass
        
        elif service_name == "apache" and version:
            try:
                parts = version.split('.')
                major = int(parts[0])
                minor = int(parts[1]) if len(parts) > 1 else 0
                
                if major == 2 and minor < 4:
                    version_specific_vulns.append("Apache 2.2.x存在多个已知漏洞")
            except (ValueError, IndexError):
                pass
        
        return base_vulns + version_specific_vulns
    
    @staticmethod
    def identify_service_by_port(port: int) -> List[str]:
        """
        根据端口识别可能的服务
        
        Args:
            port: 端口号
            
        Returns:
            List[str]: 可能的服务列表
        """
        services = []
        for service, ports in SERVICE_PORT_MAPPING.items():
            if port in ports:
                services.append(service)
        return services
    
    @staticmethod
    def get_default_ports(service_name: str) -> List[int]:
        """
        获取服务的默认端口
        
        Args:
            service_name: 服务名称
            
        Returns:
            List[int]: 默认端口列表
        """
        return SERVICE_PORT_MAPPING.get(service_name.lower(), [])
    
    @staticmethod
    def get_known_vulnerabilities(service_name: str) -> List[str]:
        """
        获取服务的已知漏洞类型
        
        Args:
            service_name: 服务名称
            
        Returns:
            List[str]: 已知漏洞类型列表
        """
        return SERVICE_VULNERABILITIES.get(service_name.lower(), [])


# 注册解析器
parser_registry.register(ServiceParser())

