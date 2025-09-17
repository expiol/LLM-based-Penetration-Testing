from transformers import AutoTokenizer
from bs4 import BeautifulSoup
import re


class TokenManage:
    _instance_tokenManage = None

    def __new__(cls, *args, **kwargs):
        if cls._instance_tokenManage is None:
            cls._instance_tokenManage = super(TokenManage, cls).__new__(cls, *args, **kwargs)
            cls._instance_tokenManage.tokenizer = AutoTokenizer.from_pretrained("src/utils/qwen_tokenizer",
                                                                                trust_remote_code=True)
        return cls._instance_tokenManage

    def __init__(self):
        pass

    def reverse_cutting_prompt(self, content, token_limit_amount):
        cur_tokenizer = self.tokenizer(content)
        cur_token_amount = len(cur_tokenizer['input_ids'])
        if cur_token_amount > token_limit_amount:
            cut_prompt = cur_tokenizer['input_ids'][:token_limit_amount]
            return self.tokenizer.decode(cut_prompt)
        else:
            return content

    def sum_prompt(self, content):
        return len(self.tokenizer(content)['input_ids'])

    
    def response_extract_with_token_judge(self, text, token_limit_amount):
        if self.sum_prompt(text) <= token_limit_amount:
            return text
        else:
            return self.response_extract(text, token_limit_amount)
    def response_extract(self, text, token_limit_amount):
        if text:
            text = text.replace('<br/>', '\n')
            text = text.replace('\/', '/')
            text = text.replace(r'\x09', '')
            try:
                soup = BeautifulSoup(text, 'html.parser')
            except:
                return self.reverse_cutting_prompt(text, token_limit_amount).strip()
            text_content = soup.get_text(separator="\n", strip=True)
            if text_content.strip() == '' and (re.search('<\?xml .*?\?>|<\?php.*?\?>', text,re.DOTALL)):
                return self.reverse_cutting_prompt(text, token_limit_amount).strip()
            text_content = re.sub(r'\n+', '\n', text_content)
            text_content = re.sub(r'\.+', '.', text_content)
            text_content = re.sub(r'(\.\n)+', '.\n', text_content)
            if soup.title and text_content.count(soup.title.get_text()) > 1:
                title_text = soup.title.get_text()
                text_content = text_content.replace(title_text, '', 1)
            if text_content in ('\u200e', ''):
                text_content = '不存在文本内容'
            return self.reverse_cutting_prompt(text_content, token_limit_amount).strip()
        else:
            return '不存在文本内容'
