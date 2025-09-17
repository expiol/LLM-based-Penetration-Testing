import base64
import os
from urllib.parse import unquote, quote
import json
import re
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

class SmartDecodePro:
    def __init__(self):
        self.custom_base64_decoder = CustomBase64Decoder(b64_expr_head=r'(.?|\n)')

    def base64_decode_pro(self, text):
        return self.custom_base64_decoder.decode(text, True)

    def decode_unicode_escapes(self, text):
        try:
            pattern = re.compile(r'\\u\{([0-9a-fA-F]{4})}')
            return pattern.sub(lambda match: chr(int(match.group(1), 16)), text)
        except Exception as e:
            return text

    def decode_hex_escapes(self, text):
        try:
            # 注意这里的正则表达式匹配 \x 后跟两个十六进制数字
            pattern = re.compile(r'\\x([0-9a-fA-F]{2})')
            # 使用 lambda 表达式
            return pattern.sub(lambda match: chr(int(match.group(1), 16)), text)
        except Exception as e:
            return text

    #出现单个16进制0x,小于2个的不进行解码
    def judge_length_hex_decoder(self, text, expr):
        finditer_matches = re.finditer(expr, text)
        # 将迭代器转换为列表以计算长度
        matches_list = list(finditer_matches)
        # 检查匹配的数量
        if len(matches_list) > 1:
            return self.smart_decoder(text, expr, self.hex_decode, re.I, '0x')
        else:
            return text, None


    @staticmethod
    def smart_decoder(text, expr, operation, expr_flag=0, extra_string='', skip_flag=True):
        finditer_matches = re.finditer(expr, text, expr_flag)
        match_list, text_list, diff_list, last_match = [], [], [], None
        for match in finditer_matches:
            context = match.group(1)
            match_list.append({
                'context': operation(extra_string+context, skip_flag),
                'start_point': match.start(),
                'end_point': match.end()
            })
            if last_match:
                diff_list.append(match.start() - last_match.end())
            last_match = match
        diff_count = max(diff_list, key=diff_list.count) if diff_list else 0
        diff_count = diff_count if diff_list.count(diff_count) != 1 else 0
        last_index, upper_part_start_index, text_point, new_text = 0, 0, 0, ''
        for index, result in enumerate(match_list):
            if last_index != 0:
                diff = result['start_point'] - last_index
                if diff != diff_count or not skip_flag:
                    new_text += text[text_point:match_list[upper_part_start_index]['start_point']] + ''.join(
                        [d['context'] for d in match_list[upper_part_start_index:index]])
                    upper_part_start_index = index
                    text_point = match_list[index - 1]['end_point']
            last_index = result['end_point']
            if index == len(match_list) - 1:
                new_text += text[text_point:match_list[upper_part_start_index]['start_point']] + ''.join(
                    [d['context'] for d in match_list[upper_part_start_index:]]) + text[match_list[index]['end_point']:]
        return new_text if new_text != '' else text, match_list
        # return new_text

    @staticmethod
    def smart_combine(context, func):
        result_list = []
        if '0x' in str.lower(context):
            for i in range(2, len(context), 2):
                func(result_list, int(context[i:i+2], 16))
        elif context[0]+context[-1] =='{}':
            numbers = re.findall(r'\d{1,3}', context[1:-1])
            for num in numbers:
                func(result_list, int(num))
            result_list.insert(0, '"')
            result_list.append('"')
        else:
            func(result_list, int(context))
        return ''.join(result_list)

    def hex_decode(self, context, skip_flag):
        result = self.smart_combine(context, lambda res, text: res.append(chr(text)))
        if CustomBase64Decoder().is_readable(result, skip_flag):
            result = self.smart_combine(context, lambda res, text: res.append(chr(text)) if 32 <= text < 127 else res.append('.'))
            return result
        else:
            return context[2:] if '0x' in context else context

    def main(self, text):
        raw_match_list = []

        # 解码全部的base64
        text = self.base64_decode_pro(text)
        # 解码特殊的base64 '\"\\u{0070}\\u{0072}'
        text = self.decode_unicode_escapes(text)
        # 解码hex的数据 '\\x70\\x61\\x73\\x73'
        text = self.decode_hex_escapes(text)
        # 解码java数组格式的hex
        text, match = self.smart_decoder(text, "(?:new )?java\.lang\.String\(new\s+byte\[]({\s*((?:\d{1,3},\s*)*\d{1,3})\s*})\)", self.hex_decode, re.I)
        raw_match_list.append({'id': 5,'value': match})
        # 解码全部的chr函数的hex
        text, match = self.smart_decoder(text, "cha?r\((\d{1,3}|0x[0-9a-f]{2})\)", self.hex_decode, re.I)
        raw_match_list.append({'id': 4,'value': match})
        # 解码全部的0x开头的hex
        text, match = self.smart_decoder(text, "0x(([a-f0-9]{2}){2,}|([A-F0-9]{2}){2,})", self.hex_decode, 0, '0x')
        raw_match_list.append({'id': 3,'value': match})
        # 解码单个0x组合为list等的hex
        text, match = self.judge_length_hex_decoder(text, "0x([a-f0-9]{2})")
        raw_match_list.append({'id': 2, 'value': match})
        # 解码剩下的全部具有一定可读性的hex,bit长度超过20
        text, match = self.smart_decoder(text, "(([a-f0-9]{2}){20,}|([A-F0-9]{2}){20,})", self.hex_decode, 0, '0x', False)
        raw_match_list.append({'id': 1,'value': match})
        return text, raw_match_list


class CustomUrlDecoder:
    def __init__(self):
        self.pattern = r'(?:%[0-9A-Fa-f][0-9A-Fa-f])+'

    def custom_replace(self, m):
        decode_s = unquote(string=m.group(0), encoding="utf-8")
        replace_s = re.sub(r'[^(\u0020-\u007E\u4e00-\u9fa5|\uff5e)]', lambda t: quote(t.group(0)), decode_s)
        return replace_s

    def decode(self, content):
        new_content = re.sub(r'(?:%[0-9A-Fa-f][0-9A-Fa-f])+', self.custom_replace, content)
        if new_content != content:
            new_content = self.decode(new_content)
        return new_content


class CustomBase64Decoder:
    def __init__(self, b64_expr_head=r'((?:: )|=|\n|\?|\'|")|\$', min_check_chunk_num=2):
        self.base64_pattern = b64_expr_head + rf"((?:[A-Za-z0-9+/]{{4}}){{{min_check_chunk_num},}}(?:(?:[A-Za-z0-9+/]{{2}}==)|(?:[A-Za-z0-9+/]{{3}}=)|(?:[A-Za-z0-9+/]{{4}})))"
        self.base64_url_pattern = r'(/)((?:[A-Za-z0-9+]{4}){2,}(?:(?:[A-Za-z0-9+]{2}==)|(?:[A-Za-z0-9+]{3}=)|(?:[A-Za-z0-9+]{4})))'
        self.base64DecodeChars = [
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
            -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
            -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1]

    def base64_decode(self, org_str):
        try:
            i, len_str, out = 0, len(org_str), ""

            while i < len_str:
                # c1
                c1 = self.base64DecodeChars[ord(org_str[i]) & 0xff]
                i += 1
                while i < len_str and c1 == -1:
                    c1 = self.base64DecodeChars[ord(org_str[i]) & 0xff]
                    i += 1
                if c1 == -1:
                    break

                # c2
                c2 = self.base64DecodeChars[ord(org_str[i]) & 0xff]
                i += 1
                while i < len_str and c2 == -1:
                    c2 = self.base64DecodeChars[ord(org_str[i]) & 0xff]
                    i += 1
                if c2 == -1:
                    break

                charCode = (c1 << 2) | ((c2 & 0x30) >> 4)
                out += chr(charCode)

                # c3
                c3 = ord(org_str[i]) & 0xff
                i += 1
                if c3 == 61:
                    return out
                c3 = self.base64DecodeChars[c3]
                while i < len_str and c3 == -1:
                    c3 = ord(org_str[i]) & 0xff
                    i += 1
                    if c3 == 61:
                        return out
                    c3 = self.base64DecodeChars[c3]
                if c3 == -1:
                    break

                charCode = ((c2 & 0x0F) << 4) | ((c3 & 0x3C) >> 2)
                out += chr(charCode)

                c4 = ord(org_str[i]) & 0xff
                i += 1
                if c4 == 61:
                    return out
                c4 = self.base64DecodeChars[c4]
                while i < len_str and c4 == -1:
                    c4 = ord(org_str[i]) & 0xff
                    i += 1
                    if c4 == 61:
                        return out
                    c4 = self.base64DecodeChars[c4]
                if c4 == -1:
                    break

                charCode = ((c3 & 0x03) << 6) | c4
                out += chr(charCode)
            return out
        except Exception as e:
            return org_str

    @staticmethod
    def utf8_to_unicode(org_str):
        """
        用途:由于python的str类型会自动utf-8解码一次,该函数尝试手动将被乱码的字符串重新以utf-8的形式再次解码，然后再通过python自动解码
        效果:试图手动将org_str整体当作utf-8编码的字节序列重新解码为对应的unicode码位
        :param org_str:
        :return:
        """
        out, i, len_str = "", 0, len(org_str)
        while i < len_str:
            c = ord(org_str[i])
            i += 1
            d = c >> 4
            # c >> 4
            if d <= 7:
                # 0xxxxxxx
                out += org_str[i-1]
            elif d == 12 or d == 13:
                # 110x xxxx   10xx xxxx
                if i < len_str:
                    char2 = ord(org_str[i])
                    i += 1
                    out += chr(((c & 0x1F) << 6) | (char2 & 0x3F))
            elif d == 14:
                # 1110 xxxx 10xx xxxx 10xx xxxx
                if i < len_str-1:
                    char2 = ord(org_str[i])
                    char3 = ord(org_str[i+1])
                    out += chr(((c & 0x0F) << 12) | ((char2 & 0x3F) << 6) | (char3 & 0x3F))
                    i += 2
        return out

    @staticmethod
    def is_readable(text, skip):
        """
        判断解码出来的文本是否可读
        1、如果有长度超过 100 的连续文本，返回 True
        2、如果解出来的全部是常见字符，返回 True
        3、如果长度超过 6 的连续文本，总长度超过输入的 50%，返回 True
        4、如果长度超过 6 的连续文本，总数量超过50个，返回 True
        :param1 text:
        :param2 skip:
        :return:
        """
        # 为了给其他功能复用，新增一个skip flag,当不需要这个功能的时候直接跳过
        if skip:
            return True
        # pattern = r'[a-zA-Z0-9\s!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/]+'
        # 上面的正则，在这个文本判断时存在问题,解码后存在特殊字符，本应该不可读，但是被\s匹配了：Host: dgservicelib.swu.edu.cn
        pattern = r'[a-zA-Z0-9\u4e00-\u9fa5\n\t !@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/]+'
        matches = re.findall(pattern, text)
        # 匹配字符的长度
        m_lens = list(map(lambda m: len(m), matches))
        if len(m_lens) == 0:
            return False
        max_len = max(m_lens)
        if max_len > 100:
            return True
        if max_len == len(text):
            return True
        # 长度超过 6 的len
        effect_lens = list(filter(lambda x: x > 6, m_lens))
        effect_sum = sum(effect_lens)
        if effect_sum*2 > len(text):
            return True
        if len(effect_lens) > 50:
            return True
        return False

    @staticmethod
    def can_encode_utf8(s):
        try:
            s.encode('utf-8')
            return True
        except UnicodeEncodeError:
            return False

    @staticmethod
    def strict_mode_decode(text):
        try:
            return base64.b64decode(text).decode('utf-8')
        except UnicodeDecodeError:
            return None

    @staticmethod
    def check_tail_ok(sub_str, text):
        """
        检查 sub_str 后面一位是否为 base64 中的字母，用于判断是否满足其中一个解码替换条件
        是,不满足替换条件： 返回 False
        否，满足替换条件： 返回 True
        :param sub_str: 一定不长于 text
        :param text:
        :return:
        """
        idx = text.find(sub_str)
        if idx < 0:
            return False
        # 结尾处，不用继续验证
        if idx + len(sub_str) >= len(text):
            return True
        check_element = text[idx + len(sub_str)]
        if re.match("^[A-Za-z0-9+/=]$", check_element):
            return False
        return True

    def decode(self, text, skip_flag=False):
        """
        1、匹配 base64 字符串，仅对长度达到 12 且以`: `或 `=` 开头的部分尝试 base64 解码，并替换原文本
        2、尝试解码的逻辑：
            针对总长度不到50的原始文本，通过自带的解码方式解码，不报错则采纳
                base64.b64decode(base64_string).decode('utf-8')
            针对总长度达到100的原始文本，通过自己实现的解码方式来解码
                a、base64decode 和 utf8to16 两步获得尝试解除的字符串 s2
                b、仅当 can_encode_utf8(s2) 且 is_readable(s2) 的时候，才算解码成功
        :param text:
        :param skip_flag:
        :return:
        """
        matches = re.findall(self.base64_pattern, text)
        for m in matches:
            if not self.check_tail_ok(m[1], text):
                continue
            if len(m[1]) < 50:
                de_str = self.strict_mode_decode(m[1])
                if de_str:
                    text = text.replace(m[1], de_str)
                else:
                    continue
            else:
                s1 = self.base64_decode(m[1])
                s2 = self.utf8_to_unicode(s1)
                if not self.can_encode_utf8(s2):
                    s2 = s1
                if not self.is_readable(s2, skip_flag):
                    continue
                with open('tmp.txt', 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(s2)
                with open('tmp.txt', encoding="utf-8") as f:
                    s2 = f.read()
                text = text.replace(m[1], s2)
        # 针对 URL 上base64编码的情况，再通过严格解码模式解码一次
        url_matches = re.findall(self.base64_url_pattern, text)
        for url_m in url_matches:
            de_str = self.strict_mode_decode(url_m[1])
            if de_str:
                text = text.replace(url_m[1], de_str)
            else:
                continue
        return text

    def extract_and_calculate_base64_lengths(self, raw_string):
        """
        从原始字符串中提取所有 Base64 编码字符串，并计算它们的总长度。

        参数:
            raw_string (str): 包含 Base64 编码字符串的原始字符串。

        返回:
            tuple: (base64_strings, decoded_strings, total_length)
                - base64_strings: 所有找到的 Base64 编码字符串列表。
                - decoded_strings: 所有 Base64 编码字符串解码后的内容列表。
                - total_length: 所有 Base64 编码字符串的总长度。
        """
        # 正则表达式匹配 Base64 编码字符串
        base64_pattern = r'[A-Za-z0-9+/=]{8,}'  # Base64 字符集，且长度至少为 20
        base64_strings = re.findall(base64_pattern, raw_string)

        # 计算所有 Base64 编码字符串解码后内容的总长度
        total_length = 0
        decoded_strings = []
        for b64_str in base64_strings:
            try:
                decoded_bytes = base64.b64decode(b64_str)
                decoded_strings.append(decoded_bytes)
                total_length += len(b64_str)
            except (base64.binascii.Error, ValueError):
                # 如果解码失败，则跳过该字符串
                continue

        return base64_strings, decoded_strings, total_length

class AutoDecode:
    def __init__(self):
        self.custom_base64_decoder = CustomBase64Decoder()
        self.custom_url_decoder = CustomUrlDecoder()

    def url_decode(self, text):
        replace_url1, replace_url2 = lambda m: '%==' + m.group(0)[-2:], lambda m: '%' + m.group(0)[-2:]
        new_text1 = re.sub(r'%([0-18-9A-F][0-9a-fA-F]|7f|7F)', replace_url1, text)
        new_text2 = re.sub(r'%==[0-18-9A-F][0-9a-fA-F]', replace_url2, unquote(new_text1))
        return new_text2

    def unicode_decode(self, text):
        replace_unicode = lambda m: '\\u' + m.group(0)[-4:]
        new_text = re.sub(r'\\{1,}u[0-9A-Za-z]{4,4}', replace_unicode, text)
        return new_text

    def decode_main(self, input_file, output_file):
        with open(input_file, encoding='utf-8') as d, open(output_file, 'w+', encoding='utf-8') as f:
            uc_result = json.dumps(json.loads(self.unicode_decode(d.read())), ensure_ascii=False, indent=4)
            replacements = {'%22': '\\%22', '%5C': '\\%5C', '%5c': '\\%5c', '%u': '\\u'}
            for old, new in replacements.items():
                uc_result = uc_result.replace(old, new)
            # f.write(self.url_decode(uc_result))
            f.write(self.custom_url_decoder.decode(uc_result))

    def decode_main2(self, message):
        """
            1、对原始报文进行解码，主要是对报文中的base64进行大批量解码

        """
        message = re.sub(r'%5Cu[0-9a-fA-F]{4}', lambda match: f'\\u{match.group(0)[4:]}', message)
        BASE_DIR = "tmp_data"
        if not os.path.exists(BASE_DIR):
            os.makedirs(BASE_DIR)
        # 将message存入临时json文件
        tmp_json = [{"message": message}]
        with open(f"{BASE_DIR}/tmp.json", mode="w+", encoding="utf-8") as f:
            json.dump(tmp_json, f, ensure_ascii=False, indent=4)
        self.decode_main(f"{BASE_DIR}/tmp.json", f"{BASE_DIR}/tmp_decode.json")
        with open(f"{BASE_DIR}/tmp_decode.json", encoding="utf-8") as f:
            decoded_message = json.load(f)[0]["message"]
        final_result = self.custom_base64_decoder.decode(decoded_message)
        return final_result
        # return decoded_message

    def decode_unicode(self, message):
        """
            1、对原始报文进行解码，只解码unicode

        """
        message = re.sub(r'%5Cu[0-9a-fA-F]{4}', lambda match: f'\\u{match.group(0)[4:]}', message)
        BASE_DIR = "tmp_data"
        if not os.path.exists(BASE_DIR):
            os.makedirs(BASE_DIR)
        # 将message存入临时json文件
        tmp_json = [{"message": message}]
        with open(f"{BASE_DIR}/tmp.json", mode="w+", encoding="utf-8") as f:
            json.dump(tmp_json, f, ensure_ascii=False, indent=4)
        with open(f"{BASE_DIR}/tmp.json", encoding='utf-8') as d, open(f"{BASE_DIR}/tmp_decode.json", 'w+', encoding='utf-8') as f:
            uc_result = json.dumps(json.loads(self.unicode_decode(d.read())), ensure_ascii=False, indent=4)
            f.write(uc_result)
        with open(f"{BASE_DIR}/tmp_decode.json", encoding="utf-8") as f:
            decoded_message = json.load(f)[0]["message"]
        return decoded_message

    def decode_php_url(self, url_path):
        """
            对php特殊的url进行解码例如 arrs1[]=99&arrs1[]=102
            解码包含PHP数组参数的URL
        """
        parsed_url = urlparse(url_path)
        query_params = parse_qs(parsed_url.query, keep_blank_values=True)

        decoded_params = {}
        # 识别并处理所有数组参数
        for param_name in list(query_params.keys()):
            # 检查参数名是否以[]结尾
            is_php_array = re.match(r'^(.*)\[\]$', param_name)
            if not is_php_array:
                continue

            # 提取原始参数名（去除[]）
            base_name = is_php_array.group(1)
            try:
                # 转换所有数字值为字符
                char_codes = [int(v) for v in query_params[param_name] if v.isdigit()]
                decoded_str = ''.join(chr(c) for c in char_codes).rstrip('\x00')
                if decoded_str:
                    decoded_params[base_name] = [decoded_str]
                    del query_params[param_name]  # 移除原始参数
            except ValueError:
                continue

        # 合并解码后的参数
        query_params.update(decoded_params)

        # 重建URL
        new_query = urlencode(query_params, doseq=True)
        return urlunparse(parsed_url._replace(query=new_query))





