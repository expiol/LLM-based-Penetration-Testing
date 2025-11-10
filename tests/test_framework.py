"""
测试 AutoPentestFramework
"""
import asyncio
import pytest
import yaml
import sys
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.framework.auto_framework import AutoPentestFramework


def load_config():
    """加载配置文件"""
    config_path = Path(__file__).parent.parent / "configs" / "framework_config.yaml"
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


@pytest.mark.asyncio
async def test_framework_initialization():
    """测试框架初始化"""
    config = load_config()
    framework = AutoPentestFramework(config)
    
    await framework.initialize()
    
    assert framework._initialized
    assert framework.master_controller is not None
    assert len(framework.agents) > 0
    
    # 清理
    await framework.shutdown()


@pytest.mark.asyncio
async def test_simple_pentest():
    """测试简单的渗透测试"""
    config = load_config()
    framework = AutoPentestFramework(config)
    
    await framework.initialize()
    
    # 执行测试（使用本地测试目标）
    result = await framework.start_automated_test(
        target="127.0.0.1",
        options={
            "safe_mode": True,
            "parallel": False
        }
    )
    
    assert result is not None
    assert "session_id" in result
    
    # 检查会话状态
    if result.get("session_id"):
        status = await framework.get_session_status(result["session_id"])
        assert status is not None
    
    # 清理
    await framework.shutdown()


@pytest.mark.asyncio
async def test_parallel_execution():
    """测试并行执行"""
    config = load_config()
    config["execution"]["parallel"] = True
    
    framework = AutoPentestFramework(config)
    await framework.initialize()
    
    result = await framework.start_automated_test(
        target="127.0.0.1",
        options={
            "safe_mode": True,
            "parallel": True,
            "max_agents": 3
        }
    )
    
    assert result is not None
    
    # 清理
    await framework.shutdown()


def test_config_loading():
    """测试配置加载"""
    config = load_config()
    
    assert "langchain" in config
    assert "ray" in config
    assert "agents" in config
    assert "recon" in config["agents"]


if __name__ == "__main__":
    # 手动运行测试
    print("Testing Framework...")
    
    async def run_tests():
        print("\n1. Testing framework initialization...")
        await test_framework_initialization()
        print("✅ Initialization test passed")
        
        print("\n2. Testing simple penetration test...")
        await test_simple_pentest()
        print("✅ Simple pentest test passed")
        
        print("\n3. Testing parallel execution...")
        await test_parallel_execution()
        print("✅ Parallel execution test passed")
        
        print("\n✅ All tests passed!")
    
    asyncio.run(run_tests())

