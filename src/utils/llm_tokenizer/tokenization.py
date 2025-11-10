"""
兼容 transformers.AutoTokenizer.from_pretrained 的本地 tokenizer 入口。
Transformers 期望目录中存在 tokenization.py 并暴露相应的 Tokenizer 类。
"""
from .tokenization_llm import QWenTokenizer

__all__ = ["QWenTokenizer"]
