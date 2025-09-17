import subprocess
from typing import List

def java_exec(jar_path:str, params: List[str]):
    try:
        commands = ['java', '-jar', jar_path] + params
        process_rst = subprocess.run(commands, capture_output=True, text=True)
        stdout = process_rst.stdout
        return stdout or ''
    except:
        return ''