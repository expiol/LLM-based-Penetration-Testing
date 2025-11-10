# CLI 异步输入修复验证

## 问题描述

在 `scripts/pentest_cli.py` 的 `collect_target_info()` 函数中，直接使用了同步的 `input()` 函数，导致在异步上下文中阻塞事件循环，程序卡住无法继续执行。

## 修复内容

### 修复位置

1. **第 143 行** - 第一个用户输入
   ```python
   # 修复前
   description = input("\n请输入目标相关信息:\n> ").strip()
   
   # 修复后
   description = await asyncio.to_thread(input, "\n请输入目标相关信息:\n> ")
   description = description.strip()
   ```

2. **第 157 行** - 确认输入
   ```python
   # 修复前
   confirm = input("\n按回车键确认开始，或输入 'q' 取消: ").strip().lower()
   
   # 修复后
   confirm = await asyncio.to_thread(input, "\n按回车键确认开始，或输入 'q' 取消: ")
   confirm = confirm.strip().lower()
   ```

### 验证结果

✅ 所有异步函数中的 `input()` 调用都已正确使用 `asyncio.to_thread()` 包装：
- `collect_target_info()` - 2 处 ✅
- `handle_auto_pause()` - 1 处 ✅
- `interactive_console()` - 1 处 ✅

## 测试脚本

### 1. 代码检查测试
```bash
python tests/test_cli_simple.py
```
验证代码中所有 `input()` 调用都已正确包装。

### 2. 功能测试
```bash
python tests/test_pentest_cli.py
```
测试异步输入不会阻塞事件循环。

## 技术说明

### 为什么需要修复？

在异步函数中直接调用同步的 `input()` 会阻塞整个事件循环，因为：
1. `input()` 是同步阻塞函数，会等待用户输入
2. 在异步上下文中，这会阻止其他异步任务执行
3. 导致程序看起来"卡住"

### 解决方案

使用 `asyncio.to_thread()` 将同步的 `input()` 调用移到线程池中执行：
- 不会阻塞事件循环
- 其他异步任务可以继续执行
- 保持异步编程模型的一致性

### 代码模式

```python
# ❌ 错误：直接使用同步 input
description = input("提示: ").strip()

# ✅ 正确：使用 asyncio.to_thread
description = await asyncio.to_thread(input, "提示: ")
description = description.strip()
```

## 验证清单

- [x] 代码中不再有直接的 `input()` 调用（在异步函数中）
- [x] 所有 `input()` 调用都使用 `asyncio.to_thread()` 包装
- [x] 代码检查测试通过
- [x] 无 linter 错误
- [x] 与项目中其他异步输入处理方式一致

## 相关文件

- `scripts/pentest_cli.py` - 主 CLI 脚本
- `tests/test_cli_simple.py` - 代码检查测试
- `tests/test_pentest_cli.py` - 功能测试

## 使用建议

运行 CLI 时，如果遇到卡住的情况：
1. 检查是否使用了最新修复的代码
2. 确认所有 `input()` 调用都正确包装
3. 运行测试脚本验证修复

修复完成后，CLI 应该能够正常响应用户输入，不会阻塞事件循环。

