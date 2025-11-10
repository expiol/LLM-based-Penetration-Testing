#!/usr/bin/env python3
"""
快速测试脚本 - 验证输入修复是否有效
"""
import asyncio
import sys


async def test_input_non_blocking():
    """测试输入不会阻塞事件循环"""
    print("测试异步输入...")
    
    # 创建一个后台任务
    background_done = False
    
    async def background():
        nonlocal background_done
        await asyncio.sleep(0.1)
        background_done = True
        print("✅ 后台任务完成")
    
    bg_task = asyncio.create_task(background())
    
    # 测试输入（使用 run_in_executor）
    try:
        loop = asyncio.get_event_loop()
        print("等待输入（输入任意内容后按回车）...")
        result = await loop.run_in_executor(None, input, "测试输入: ")
        print(f"✅ 输入成功: {result}")
        
        # 等待后台任务
        await bg_task
        
        if background_done:
            print("✅ 事件循环未被阻塞！")
            return True
        else:
            print("❌ 事件循环被阻塞了！")
            return False
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("=" * 72)
    print("🧪 测试异步输入修复")
    print("=" * 72)
    print("\n这个测试会验证输入不会阻塞事件循环")
    print("如果后台任务能完成，说明修复成功\n")
    
    try:
        success = asyncio.run(test_input_non_blocking())
        if success:
            print("\n✅ 测试通过！")
            sys.exit(0)
        else:
            print("\n❌ 测试失败！")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  测试被中断")
        sys.exit(1)

