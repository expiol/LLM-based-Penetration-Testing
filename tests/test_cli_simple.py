#!/usr/bin/env python3
"""
简单的测试脚本 - 验证 collect_target_info 异步输入修复
这个脚本直接检查代码，确保使用了 asyncio.to_thread
"""
import sys
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_SCRIPT = REPO_ROOT / "scripts" / "pentest_cli.py"


def test_async_input_fix():
    """检查代码中是否正确使用了 asyncio.to_thread 来处理 input"""
    print("\n" + "=" * 72)
    print("🔍 检查异步输入修复")
    print("=" * 72)
    
    if not CLI_SCRIPT.exists():
        print(f"❌ 找不到文件: {CLI_SCRIPT}")
        return False
    
    content = CLI_SCRIPT.read_text(encoding="utf-8")
    
    # 检查 collect_target_info 函数
    issues = []
    
    # 1. 检查是否还有直接使用 input() 的地方（在异步函数中）
    # 查找 async def collect_target_info 函数体中的 input(
    async_func_pattern = r'async def collect_target_info\([^)]*\):.*?(?=\n\ndef |\nasync def |\Z)'
    match = re.search(async_func_pattern, content, re.DOTALL)
    
    if match:
        func_body = match.group(0)
        
        # 检查是否有直接的 input( 调用（不在 asyncio.to_thread 中）
        # 查找 input( 但不在 await asyncio.to_thread(input, 中
        direct_input_pattern = r'(?<!await asyncio\.to_thread\(input,)\s+input\('
        direct_inputs = re.findall(direct_input_pattern, func_body)
        
        if direct_inputs:
            issues.append("❌ 发现直接使用 input() 的调用，应该使用 await asyncio.to_thread(input, ...)")
        
        # 检查是否使用了 asyncio.to_thread
        if 'asyncio.to_thread' not in func_body:
            issues.append("❌ 未找到 asyncio.to_thread 的使用")
        else:
            print("✅ 找到 asyncio.to_thread 的使用")
        
        # 检查具体的 input 调用
        input_calls = re.findall(r'input\([^)]+\)', func_body)
        for call in input_calls:
            # 检查这个调用是否在 asyncio.to_thread 中
            # 通过检查前面的代码来确定
            call_pos = func_body.find(call)
            before_call = func_body[max(0, call_pos-100):call_pos]
            if 'asyncio.to_thread' not in before_call:
                issues.append(f"❌ 发现未包装的 input 调用: {call}")
            else:
                print(f"✅ input 调用已正确包装: {call[:50]}...")
    
    # 2. 检查其他异步函数中是否有直接使用 input 的情况
    async_functions = re.finditer(r'async def (\w+)\([^)]*\):.*?(?=\n\ndef |\nasync def |\Z)', content, re.DOTALL)
    for match in async_functions:
        func_name = match.group(1)
        func_body = match.group(0)
        
        # 跳过 collect_target_info，已经检查过了
        if func_name == 'collect_target_info':
            continue
        
        # 检查是否有直接的 input( 调用
        direct_inputs = re.findall(r'(?<!await asyncio\.to_thread\(input,)\s+input\(', func_body)
        if direct_inputs:
            # 检查是否在 asyncio.to_thread 中
            for input_call in direct_inputs:
                # 更仔细地检查
                input_pattern = r'input\([^)]+\)'
                input_matches = re.finditer(input_pattern, func_body)
                for im in input_matches:
                    call_pos = im.start()
                    before_call = func_body[max(0, call_pos-150):call_pos]
                    if 'asyncio.to_thread' in before_call:
                        continue  # 已经正确包装
                    else:
                        issues.append(f"⚠️  在 async def {func_name} 中发现可能的直接 input 调用")
    
    # 3. 验证修复后的代码结构
    print("\n📋 代码检查结果:")
    if not issues:
        print("✅ 所有检查通过！")
        print("\n修复验证:")
        print("  ✅ collect_target_info 使用 asyncio.to_thread 包装 input")
        print("  ✅ 其他异步函数中的 input 调用也已正确包装")
        print("\n代码修复成功，不会阻塞事件循环！")
        return True
    else:
        print("发现以下问题:")
        for issue in issues:
            print(f"  {issue}")
        return False


def show_fix_summary():
    """显示修复摘要"""
    print("\n" + "=" * 72)
    print("📝 修复摘要")
    print("=" * 72)
    print("""
修复内容：
1. 将 collect_target_info() 函数中的同步 input() 调用改为异步
2. 使用 await asyncio.to_thread(input, ...) 包装所有 input 调用
3. 确保事件循环不会被阻塞

修复位置：
- scripts/pentest_cli.py 第 143 行
- scripts/pentest_cli.py 第 157 行

验证方法：
- 运行此测试脚本检查代码
- 运行 test_pentest_cli.py 进行功能测试
- 实际运行 CLI 验证不会卡住
""")


if __name__ == "__main__":
    print("\n" + "=" * 72)
    print("🧪 CLI 异步输入修复验证测试")
    print("=" * 72)
    
    success = test_async_input_fix()
    show_fix_summary()
    
    if success:
        print("\n✅ 代码检查通过！")
        print("💡 建议：运行 python tests/test_pentest_cli.py 进行功能测试")
        sys.exit(0)
    else:
        print("\n❌ 代码检查发现问题，请检查修复")
        sys.exit(1)

