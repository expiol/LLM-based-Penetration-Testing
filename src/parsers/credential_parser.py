"""
凭证解析器
解析各种格式的凭证信息（参考 harbinger 的设计）
"""
import re
import base64
import json
from typing import Any, Dict, List, Optional

from .base_parser import BaseParser, ParseResult, ParseResultType, parser_registry


class CredentialParser(BaseParser):
    """
    凭证解析器
    支持解析多种格式的凭证：
    - 明文用户名/密码
    - NTLM哈希
    - Kerberos票据/哈希
    - Base64编码凭证
    - SecretsDump输出
    - PyPyKatz输出
    """
    
    def __init__(self):
        super().__init__("credential")
        
        # NTLM哈希模式 (用户名:RID:LM哈希:NTLM哈希:::)
        self._compile_pattern(
            "ntlm_hash",
            r'([^\s:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::'
        )
        
        # SecretsDump格式
        self._compile_pattern(
            "secretsdump",
            r'([^\s:]+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::'
        )
        
        # Kerberos TGS哈希 (hashcat模式13100)
        self._compile_pattern(
            "krb5tgs",
            r'\$krb5tgs\$(\d+)\$[^$]+\$([^$]+)\$[^$]+\$([a-fA-F0-9]+)',
            re.IGNORECASE
        )
        
        # AS-REP Roasting哈希 (hashcat模式18200)
        self._compile_pattern(
            "krb5asrep",
            r'\$krb5asrep\$(\d+)\$([^$@]+)@?([^$]*)?\$([a-fA-F0-9]+)',
            re.IGNORECASE
        )
        
        # 明文凭证模式
        self._compile_pattern(
            "plaintext_cred",
            r'(?:username|user|login|account)[\s:=]+([^\s,;]+)[\s,;]+(?:password|pass|pwd)[\s:=]+([^\s,;]+)',
            re.IGNORECASE
        )
        
        # 邮箱格式用户名
        self._compile_pattern(
            "email_cred",
            r'([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[\s:,;]+([^\s,;]+)'
        )
        
        # 域\用户名:密码格式
        self._compile_pattern(
            "domain_cred",
            r'([a-zA-Z0-9.-]+)\\([a-zA-Z0-9._-]+)[\s:,;]+([^\s,;]+)'
        )
        
        # Base64编码的凭证
        self._compile_pattern(
            "base64_cred",
            r'(?:auth|authorization|credential)[\s:=]+(?:Basic\s+)?([A-Za-z0-9+/]+=*)',
            re.IGNORECASE
        )
        
        # SSH私钥
        self._compile_pattern(
            "ssh_key",
            r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'
        )
        
        # AWS密钥
        self._compile_pattern(
            "aws_key",
            r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',
            re.IGNORECASE
        )
        
        # AWS Secret
        self._compile_pattern(
            "aws_secret",
            r'aws_secret_access_key[\s:=]+([A-Za-z0-9/+=]{40})',
            re.IGNORECASE
        )
    
    def can_parse(self, text: str) -> bool:
        """检查是否包含凭证信息"""
        credential_indicators = [
            r'[a-fA-F0-9]{32}:[a-fA-F0-9]{32}',  # NTLM哈希
            r'\$krb5tgs\$',  # Kerberos TGS
            r'\$krb5asrep\$',  # AS-REP
            r'username.*password',  # 明文凭证
            r'-----BEGIN.*PRIVATE KEY-----',  # SSH密钥
            r'AKIA[0-9A-Z]{16}',  # AWS密钥
            r'secretsdump',  # SecretsDump输出
            r'pypykatz',  # PyPyKatz输出
        ]
        for indicator in credential_indicators:
            if re.search(indicator, text, re.IGNORECASE):
                return True
        return False
    
    def parse(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[ParseResult]:
        """解析凭证信息"""
        results = []
        
        # 清理文本
        text = self._clean_text(text)
        
        # 尝试解析NTLM哈希
        results.extend(self._parse_ntlm_hashes(text))
        
        # 尝试解析Kerberos哈希
        results.extend(self._parse_kerberos_hashes(text))
        
        # 尝试解析明文凭证
        results.extend(self._parse_plaintext_credentials(text))
        
        # 尝试解析Base64凭证
        results.extend(self._parse_base64_credentials(text))
        
        # 尝试解析SSH密钥
        results.extend(self._parse_ssh_keys(text))
        
        # 尝试解析AWS凭证
        results.extend(self._parse_aws_credentials(text))
        
        return results
    
    def _parse_ntlm_hashes(self, text: str) -> List[ParseResult]:
        """解析NTLM哈希"""
        results = []
        
        for match in self._patterns["ntlm_hash"].finditer(text):
            username = match.group(1)
            rid = match.group(2)
            lm_hash = match.group(3)
            ntlm_hash = match.group(4)
            
            # 检查是否为空LM哈希
            is_lm_empty = lm_hash.lower() == "aad3b435b51404eeaad3b435b51404ee"
            
            results.append(ParseResult(
                result_type=ParseResultType.CREDENTIAL,
                data={
                    "username": username,
                    "credential_type": "ntlm_hash",
                    "rid": rid,
                    "lm_hash": lm_hash,
                    "ntlm_hash": ntlm_hash,
                    "lm_empty": is_lm_empty,
                },
                source="credential_parser",
                confidence=0.95,
                raw_text=match.group(0),
                metadata={"hash_type": "ntlm"}
            ))
        
        return results
    
    def _parse_kerberos_hashes(self, text: str) -> List[ParseResult]:
        """解析Kerberos哈希"""
        results = []
        
        # TGS哈希
        for match in self._patterns["krb5tgs"].finditer(text):
            results.append(ParseResult(
                result_type=ParseResultType.HASH,
                data={
                    "hash_type": "krb5tgs",
                    "etype": match.group(1),
                    "realm": match.group(2),
                    "hash": match.group(3),
                },
                source="credential_parser",
                confidence=0.9,
                raw_text=match.group(0)[:100],  # 截断长哈希
                metadata={"hash_type": "kerberos_tgs"}
            ))
        
        # AS-REP哈希
        for match in self._patterns["krb5asrep"].finditer(text):
            results.append(ParseResult(
                result_type=ParseResultType.HASH,
                data={
                    "hash_type": "krb5asrep",
                    "etype": match.group(1),
                    "username": match.group(2),
                    "realm": match.group(3) if match.lastindex >= 3 else "",
                    "hash": match.group(4) if match.lastindex >= 4 else match.group(3),
                },
                source="credential_parser",
                confidence=0.9,
                raw_text=match.group(0)[:100],
                metadata={"hash_type": "kerberos_asrep"}
            ))
        
        return results
    
    def _parse_plaintext_credentials(self, text: str) -> List[ParseResult]:
        """解析明文凭证"""
        results = []
        
        # 标准用户名密码格式
        for match in self._patterns["plaintext_cred"].finditer(text):
            username = match.group(1)
            password = match.group(2)
            
            results.append(ParseResult(
                result_type=ParseResultType.CREDENTIAL,
                data={
                    "username": username,
                    "password": password,
                    "credential_type": "plaintext",
                },
                source="credential_parser",
                confidence=0.8,
                raw_text=match.group(0),
                metadata={"format": "plaintext"}
            ))
        
        # 邮箱格式
        for match in self._patterns["email_cred"].finditer(text):
            username = match.group(1)
            domain = match.group(2)
            password = match.group(3)
            
            results.append(ParseResult(
                result_type=ParseResultType.CREDENTIAL,
                data={
                    "username": username,
                    "domain": domain,
                    "password": password,
                    "email": f"{username}@{domain}",
                    "credential_type": "plaintext",
                },
                source="credential_parser",
                confidence=0.75,
                raw_text=match.group(0),
                metadata={"format": "email"}
            ))
        
        # 域\用户名格式
        for match in self._patterns["domain_cred"].finditer(text):
            domain = match.group(1)
            username = match.group(2)
            password = match.group(3)
            
            results.append(ParseResult(
                result_type=ParseResultType.CREDENTIAL,
                data={
                    "domain": domain,
                    "username": username,
                    "password": password,
                    "credential_type": "plaintext",
                },
                source="credential_parser",
                confidence=0.85,
                raw_text=match.group(0),
                metadata={"format": "domain_user"}
            ))
        
        return results
    
    def _parse_base64_credentials(self, text: str) -> List[ParseResult]:
        """解析Base64编码的凭证"""
        results = []
        
        for match in self._patterns["base64_cred"].finditer(text):
            encoded = match.group(1)
            try:
                decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                # 检查是否为用户名:密码格式
                if ':' in decoded:
                    parts = decoded.split(':', 1)
                    if len(parts) == 2:
                        results.append(ParseResult(
                            result_type=ParseResultType.CREDENTIAL,
                            data={
                                "username": parts[0],
                                "password": parts[1],
                                "credential_type": "base64_decoded",
                                "original_encoded": encoded,
                            },
                            source="credential_parser",
                            confidence=0.9,
                            raw_text=match.group(0),
                            metadata={"format": "base64"}
                        ))
            except Exception:
                pass  # 解码失败，跳过
        
        return results
    
    def _parse_ssh_keys(self, text: str) -> List[ParseResult]:
        """解析SSH私钥"""
        results = []
        
        # 使用多行匹配查找完整的SSH密钥
        ssh_key_pattern = re.compile(
            r'(-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'
            r'[\s\S]*?'
            r'-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)',
            re.MULTILINE
        )
        
        for match in ssh_key_pattern.finditer(text):
            key_content = match.group(1)
            
            # 确定密钥类型
            key_type = "unknown"
            if "RSA" in key_content:
                key_type = "rsa"
            elif "DSA" in key_content:
                key_type = "dsa"
            elif "EC" in key_content:
                key_type = "ecdsa"
            elif "OPENSSH" in key_content:
                key_type = "openssh"
            
            results.append(ParseResult(
                result_type=ParseResultType.CREDENTIAL,
                data={
                    "credential_type": "ssh_private_key",
                    "key_type": key_type,
                    "key_content": key_content,
                },
                source="credential_parser",
                confidence=1.0,
                raw_text=key_content[:100] + "...",
                metadata={"format": "ssh_key"}
            ))
        
        return results
    
    def _parse_aws_credentials(self, text: str) -> List[ParseResult]:
        """解析AWS凭证"""
        results = []
        
        # AWS Access Key
        for match in self._patterns["aws_key"].finditer(text):
            access_key = match.group(0)
            
            # 查找对应的Secret Key
            secret_match = self._patterns["aws_secret"].search(text)
            secret_key = secret_match.group(1) if secret_match else None
            
            results.append(ParseResult(
                result_type=ParseResultType.CREDENTIAL,
                data={
                    "credential_type": "aws_credentials",
                    "access_key_id": access_key,
                    "secret_access_key": secret_key,
                },
                source="credential_parser",
                confidence=0.95 if secret_key else 0.7,
                raw_text=access_key,
                metadata={"format": "aws"}
            ))
        
        return results
    
    def get_credentials_summary(self, results: List[ParseResult]) -> Dict[str, Any]:
        """
        获取凭证摘要
        
        Args:
            results: 解析结果列表
            
        Returns:
            Dict[str, Any]: 凭证摘要
        """
        summary = {
            "total_credentials": 0,
            "by_type": {},
            "by_source": {},
        }
        
        for result in results:
            if result.result_type in (ParseResultType.CREDENTIAL, ParseResultType.HASH):
                summary["total_credentials"] += 1
                
                cred_type = result.data.get("credential_type", "unknown")
                summary["by_type"][cred_type] = summary["by_type"].get(cred_type, 0) + 1
                
                source = result.source
                summary["by_source"][source] = summary["by_source"].get(source, 0) + 1
        
        return summary


# 注册解析器
parser_registry.register(CredentialParser())

