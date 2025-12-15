"""
子域名枚举工具 - 侦察Agent私有工具
"""
import asyncio
import subprocess
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    dns = None
import requests
from typing import Dict, Any, List, Set
from ....core.agent_tool_manager import ToolInterface
from ....utils.i18n import t


class SubdomainEnumerationTool(ToolInterface):
    """子域名枚举工具"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("subdomain_enum", config)
        self.wordlist = config.get("wordlist", self._get_default_wordlist())
        self.timeout = config.get("timeout", 60)
        self.max_threads = config.get("max_threads", 50)
        
    async def execute(self, parameters: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """执行子域名枚举"""
        try:
            domain = parameters.get("domain")
            methods = parameters.get("methods", ["dns_brute", "certificate_transparency"])
            
            if not domain:
                return {"success": False, "error": "未指定域名"}
            
            self.logger.info(t("tool.subdomain.start", domain=domain))
            
            # 更新执行状态（不传agent参数，让_update_execution_status从context自动获取并格式化）
            self._update_execution_status(
                f"subdomain_enum {domain}",
                f"枚举 {domain} 的子域名"
            )
            self._add_output_line(f"开始子域名枚举: {domain}")
            self._add_output_line(f"使用方法: {', '.join(methods)}")
            
            # 检查依赖
            if not DNS_AVAILABLE and "dns_brute" in methods:
                self.logger.warning("dnspython未安装，DNS暴力破解功能不可用")
                # 移除需要DNS的方法
                methods = [m for m in methods if m != "dns_brute"]
                if not methods:
                    return {
                        "success": False,
                        "error": "dnspython未安装，子域名枚举功能不可用。请运行: pip install dnspython"
                    }
            
            found_subdomains = set()
            results = {}
            
            # 执行不同的枚举方法
            for method in methods:
                try:
                    if method == "dns_brute":
                        if not DNS_AVAILABLE:
                            results["dns_brute"] = {"error": "dnspython未安装"}
                            continue
                        subdomains = await self._dns_bruteforce(domain)
                        results["dns_brute"] = list(subdomains)
                        found_subdomains.update(subdomains)
                        
                    elif method == "certificate_transparency":
                        subdomains = await self._cert_transparency(domain)
                        results["certificate_transparency"] = list(subdomains)
                        found_subdomains.update(subdomains)
                        
                    elif method == "search_engines":
                        subdomains = await self._search_engines(domain)
                        results["search_engines"] = list(subdomains)
                        found_subdomains.update(subdomains)
                        
                except Exception as e:
                    self.logger.error(t("tool.subdomain.method_failed", method=method, error=str(e)))
                    results[method] = {"error": str(e)}
            
            # 验证发现的子域名
            valid_subdomains = await self._validate_subdomains(list(found_subdomains))
            
            return {
                "success": True,
                "tool": self.name,
                "domain": domain,
                "total_found": len(found_subdomains),
                "valid_subdomains": len(valid_subdomains),
                "results": {
                    "all_subdomains": list(found_subdomains),
                    "valid_subdomains": valid_subdomains,
                    "method_results": results
                }
            }
            
        except Exception as e:
            self.logger.error(t("tool.subdomain.enum_failed", error=str(e)))
            return {"success": False, "error": str(e)}
    
    async def _dns_bruteforce(self, domain: str) -> Set[str]:
        """DNS暴力破解"""
        if not DNS_AVAILABLE:
            self.logger.warning("dnspython未安装，DNS暴力破解功能不可用")
            return set()
        
        found_subdomains = set()
        
        # 使用异步任务并发查询
        tasks = []
        for subdomain_prefix in self.wordlist:
            subdomain = f"{subdomain_prefix}.{domain}"
            task = self._check_dns_record(subdomain)
            tasks.append(task)
        
        # 分批执行以避免过多并发
        batch_size = self.max_threads
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            
            for subdomain, result in zip([f"{self.wordlist[i + j]}.{domain}" for j in range(len(batch))], results):
                if result is True:
                    found_subdomains.add(subdomain)
        
        return found_subdomains
    
    async def _check_dns_record(self, subdomain: str) -> bool:
        """检查DNS记录"""
        if not DNS_AVAILABLE:
            return False
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            # 尝试查询A记录
            await asyncio.get_event_loop().run_in_executor(
                None, resolver.resolve, subdomain, 'A'
            )
            return True
            
        except:
            return False
    
    async def _cert_transparency(self, domain: str) -> Set[str]:
        """证书透明度查询"""
        found_subdomains = set()
        
        try:
            # 使用crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            response = await asyncio.get_event_loop().run_in_executor(
                None, requests.get, url
            )
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    # 处理多行证书名称
                    for line in name_value.split('\n'):
                        line = line.strip()
                        if line and line.endswith(f".{domain}"):
                            # 移除通配符
                            if line.startswith("*."):
                                line = line[2:]
                            found_subdomains.add(line)
                            
        except Exception as e:
            self.logger.error(t("tool.subdomain.cert_failed", error=str(e)))
        
        return found_subdomains
    
    async def _search_engines(self, domain: str) -> Set[str]:
        """搜索引擎查询"""
        found_subdomains = set()
        
        try:
            # 使用Google搜索
            query = f"site:{domain}"
            # 注意：实现中需要处理搜索引擎的反爬虫机制
            
            # 可以添加其他搜索引擎的查询逻辑
            pass
            
        except Exception as e:
            self.logger.error(t("tool.subdomain.search_failed", error=str(e)))
        
        return found_subdomains
    
    async def _validate_subdomains(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """验证子域名的有效性"""
        valid_subdomains = []
        
        tasks = []
        for subdomain in subdomains:
            task = self._validate_single_subdomain(subdomain)
            tasks.append(task)
        
        # 分批验证
        batch_size = 20
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            
            for subdomain, result in zip(subdomains[i:i + len(batch)], results):
                if isinstance(result, dict) and result.get("valid"):
                    valid_subdomains.append({
                        "subdomain": subdomain,
                        **result
                    })
        
        return valid_subdomains
    
    async def _validate_single_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """验证单个子域名"""
        try:
            # DNS解析
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            
            result = {
                "valid": False,
                "ip_addresses": [],
                "cname": None,
                "http_status": None
            }
            
            # 查询A记录
            try:
                answers = await asyncio.get_event_loop().run_in_executor(
                    None, resolver.resolve, subdomain, 'A'
                )
                result["ip_addresses"] = [str(rdata) for rdata in answers]
                result["valid"] = True
            except:
                pass
            
            # 查询CNAME记录
            try:
                answers = await asyncio.get_event_loop().run_in_executor(
                    None, resolver.resolve, subdomain, 'CNAME'
                )
                if answers:
                    result["cname"] = str(answers[0])
                    result["valid"] = True
            except:
                pass
            
            # HTTP状态检查
            if result["valid"]:
                try:
                    response = await asyncio.get_event_loop().run_in_executor(
                        None, requests.head, f"http://{subdomain}", {"timeout": 5}
                    )
                    result["http_status"] = response.status_code
                except:
                    try:
                        response = await asyncio.get_event_loop().run_in_executor(
                            None, requests.head, f"https://{subdomain}", {"timeout": 5}
                        )
                        result["http_status"] = response.status_code
                    except:
                        pass
            
            return result
            
        except Exception as e:
            return {"valid": False, "error": str(e)}
    
    def _get_default_wordlist(self) -> List[str]:
        """获取默认子域名字典"""
        return [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
            "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
            "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
            "web", "media", "email", "images", "img", "www1", "intranet", "portal",
            "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3",
            "dns", "search", "staging", "server", "mx1", "chat", "wap", "my", "svn",
            "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2",
            "lyncdiscover", "info", "apps", "download", "remote", "db", "forums", "store",
            "relay", "files", "newsletter", "app", "live", "owa", "en", "start", "sms",
            "office", "exchange", "ipv4"
        ]
    
    def get_description(self) -> str:
        return "子域名枚举工具，支持DNS暴力破解、证书透明度查询等多种方法发现子域名"
    
    def get_parameters(self) -> Dict[str, Any]:
        return {
            "required": ["domain"],
            "optional": {
                "methods": "枚举方法列表，默认['dns_brute', 'certificate_transparency']",
                "wordlist": "自定义字典列表",
                "timeout": "超时时间(秒)，默认60",
                "max_threads": "最大并发数，默认50"
            }
        }
    
    def get_capabilities(self) -> List[str]:
        return [
            "subdomain_enumeration",
            "dns_bruteforce", 
            "certificate_transparency",
            "domain_reconnaissance",
            "passive_reconnaissance"
        ]


class DNSEnumerationTool(ToolInterface):
    """DNS枚举工具"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("dns_enum", config)
        self.timeout = config.get("timeout", 30)
        
    async def execute(self, parameters: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """执行DNS枚举"""
        try:
            if not DNS_AVAILABLE:
                return {
                    "success": False,
                    "error": "dnspython未安装，DNS枚举功能不可用。请运行: pip install dnspython"
                }
            
            domain = parameters.get("domain")
            record_types = parameters.get("record_types", ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"])
            
            if not domain:
                return {"success": False, "error": "未指定域名"}
            
            self.logger.info(t("tool.subdomain.start_dns", domain=domain))
            
            # 更新执行状态（不传agent参数，让_update_execution_status从context自动获取并格式化）
            self._update_execution_status(
                f"dns_enum {domain}",
                f"查询 {domain} 的DNS记录"
            )
            self._add_output_line(f"开始DNS枚举: {domain}")
            self._add_output_line(f"查询记录类型: {', '.join(record_types)}")
            
            results = {}
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            
            for record_type in record_types:
                try:
                    answers = await asyncio.get_event_loop().run_in_executor(
                        None, resolver.resolve, domain, record_type
                    )
                    results[record_type] = [str(rdata) for rdata in answers]
                except Exception as e:
                    results[record_type] = {"error": str(e)}
            
            return {
                "success": True,
                "tool": self.name,
                "domain": domain,
                "dns_records": results
            }
            
        except Exception as e:
            self.logger.error(f"DNS枚举失败: {e}")
            return {"success": False, "error": str(e)}
    
    def get_description(self) -> str:
        return "DNS记录枚举工具，查询域名的各种DNS记录类型"
    
    def get_parameters(self) -> Dict[str, Any]:
        return {
            "required": ["domain"],
            "optional": {
                "record_types": "DNS记录类型列表，默认['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']",
                "timeout": "查询超时时间(秒)，默认30"
            }
        }
    
    def get_capabilities(self) -> List[str]:
        return [
            "dns_enumeration",
            "dns_records_query",
            "domain_intelligence",
            "passive_reconnaissance"
        ]
