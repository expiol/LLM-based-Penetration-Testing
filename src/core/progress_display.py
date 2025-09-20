"""
进度显示组件
在终端中显示渗透测试的进度信息
"""
import sys
import time
from typing import Dict, Any, List
from datetime import datetime
import threading


class ProgressDisplay:
    """进度显示器"""
    
    def __init__(self):
        self.current_phase = ""
        self.start_time = None
        self.phase_start_time = None
        self.completed_phases = 0
        self.total_phases = 7  # Kill Chain的7个阶段
        self.lock = threading.Lock()
        
        # 显示配置
        self.width = 80
        self.show_timestamps = True
        self.use_colors = True
        
        # 颜色码
        self.colors = {
            "reset": "\033[0m",
            "red": "\033[91m",
            "green": "\033[92m", 
            "yellow": "\033[93m",
            "blue": "\033[94m",
            "purple": "\033[95m",
            "cyan": "\033[96m",
            "white": "\033[97m",
            "bold": "\033[1m"
        } if self.use_colors else {k: "" for k in ["reset", "red", "green", "yellow", "blue", "purple", "cyan", "white", "bold"]}
    
    def _colorize(self, text: str, color: str) -> str:
        """给文本添加颜色"""
        return f"{self.colors.get(color, '')}{text}{self.colors['reset']}"
    
    def _get_timestamp(self) -> str:
        """获取时间戳"""
        if self.show_timestamps:
            return f"[{datetime.now().strftime('%H:%M:%S')}] "
        return ""
    
    def _print_separator(self, char: str = "="):
        """打印分隔线"""
        print(self._colorize(char * self.width, "blue"))
    
    def _print_header(self, text: str):
        """打印标题"""
        print(self._colorize(f"\n{text.center(self.width)}", "bold"))
        self._print_separator()
    
    def show_banner(self):
        """显示启动横幅"""
        banner = [
            "🔍 LLM-based Penetration Testing Platform",
            "   基于大语言模型的智能渗透测试平台",
            "",
            "⚠️  仅用于授权的安全测试！"
        ]
        
        self._print_separator("=")
        for line in banner:
            print(self._colorize(line.center(self.width), "cyan"))
        self._print_separator("=")
    
    def show_target_info(self, target_info: Dict[str, Any]):
        """显示目标信息"""
        self._print_header("🎯 目标信息")
        
        info_items = [
            ("目标", target_info.get("target", "N/A")),
            ("端口范围", target_info.get("port_range", "N/A")),
            ("安全模式", "✅ 启用" if target_info.get("safe_mode") else "❌ 禁用"),
            ("隐蔽模式", "✅ 启用" if target_info.get("stealth_mode") else "❌ 禁用")
        ]
        
        for label, value in info_items:
            print(f"{self._get_timestamp()}{label}: {self._colorize(str(value), 'white')}")
        
        # 显示已知信息
        known_info = target_info.get("known_info", {})
        if any(known_info.values()):
            print(f"\n{self._colorize('📋 已知信息:', 'yellow')}")
            for key, values in known_info.items():
                if values:
                    print(f"   {key}: {', '.join(values)}")
    
    def show_todo_list(self, todos: List[Dict[str, Any]]):
        """显示TODO列表"""
        self._print_header("📋 渗透测试计划")
        
        for i, todo in enumerate(todos, 1):
            status_icon = "⏳" if todo["status"] == "pending" else "✅" if todo["status"] == "completed" else "❌"
            title = todo["title"]
            print(f"{self._get_timestamp()}{i:2d}. {status_icon} {title}")
    
    def show_status(self, message: str):
        """显示状态信息"""
        with self.lock:
            print(f"{self._get_timestamp()}{self._colorize('ℹ️', 'blue')} {message}")
    
    def show_success(self, message: str):
        """显示成功信息"""
        with self.lock:
            print(f"{self._get_timestamp()}{self._colorize('✅', 'green')} {message}")
    
    def show_error(self, message: str):
        """显示错误信息"""
        with self.lock:
            print(f"{self._get_timestamp()}{self._colorize('❌', 'red')} {message}")
    
    def show_warning(self, message: str):
        """显示警告信息"""
        with self.lock:
            print(f"{self._get_timestamp()}{self._colorize('⚠️', 'yellow')} {message}")
    
    def show_phase_start(self, phase_name: str):
        """显示阶段开始"""
        with self.lock:
            self.current_phase = phase_name
            self.phase_start_time = datetime.now()
            
            if self.start_time is None:
                self.start_time = self.phase_start_time
            
            progress_bar = self._generate_progress_bar()
            
            print(f"\n{self._colorize('🚀', 'cyan')} 开始 {self._colorize(phase_name, 'bold')} 阶段")
            print(f"{self._get_timestamp()}{progress_bar}")
    
    def show_phase_complete(self, phase_name: str, summary: str = ""):
        """显示阶段完成"""
        with self.lock:
            self.completed_phases += 1
            duration = ""
            
            if self.phase_start_time:
                elapsed = (datetime.now() - self.phase_start_time).total_seconds()
                duration = f" ({elapsed:.1f}s)"
            
            print(f"{self._get_timestamp()}{self._colorize('✅', 'green')} {phase_name}阶段完成{duration}")
            if summary:
                print(f"{self._get_timestamp()}   📝 {summary}")
    
    def show_phase_error(self, phase_name: str, error: str):
        """显示阶段错误"""
        with self.lock:
            print(f"{self._get_timestamp()}{self._colorize('❌', 'red')} {phase_name}阶段失败: {error}")
    
    def show_tool_execution(self, tool_name: str):
        """显示工具执行"""
        with self.lock:
            print(f"{self._get_timestamp()}   🔧 执行工具: {self._colorize(tool_name, 'cyan')}")
    
    def show_tool_success(self, tool_name: str, summary: str = ""):
        """显示工具成功"""
        with self.lock:
            print(f"{self._get_timestamp()}     ✅ {tool_name} 完成")
            if summary:
                print(f"{self._get_timestamp()}        {summary}")
    
    def show_tool_error(self, tool_name: str, error: str):
        """显示工具错误"""
        with self.lock:
            print(f"{self._get_timestamp()}     ❌ {tool_name} 失败: {error}")
    
    def show_discovery(self, discovery_type: str, item: str):
        """显示发现"""
        with self.lock:
            icons = {
                "service": "🛠️",
                "vulnerability": "🐛", 
                "credential": "🔑",
                "access_point": "🔓",
                "sensitive_data": "📁"
            }
            icon = icons.get(discovery_type, "🔍")
            print(f"{self._get_timestamp()}   {icon} 发现{discovery_type}: {self._colorize(item, 'yellow')}")
    
    def show_llm_thinking(self, model_name: str, task: str):
        """显示LLM思考状态"""
        with self.lock:
            print(f"{self._get_timestamp()}   🧠 {model_name} 正在分析: {task}")
    
    def show_llm_response(self, model_name: str, response_summary: str):
        """显示LLM响应"""
        with self.lock:
            print(f"{self._get_timestamp()}     💭 {model_name}: {response_summary}")
    
    def _generate_progress_bar(self) -> str:
        """生成进度条"""
        if self.total_phases == 0:
            return ""
        
        progress = self.completed_phases / self.total_phases
        bar_length = 40
        filled_length = int(bar_length * progress)
        
        bar = "█" * filled_length + "░" * (bar_length - filled_length)
        percentage = progress * 100
        
        elapsed_str = ""
        if self.start_time:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            elapsed_str = f" | {elapsed:.1f}s"
        
        return f"进度: {self._colorize(bar, 'green')} {percentage:.1f}% ({self.completed_phases}/{self.total_phases}){elapsed_str}"
    
    def show_progress_update(self):
        """显示进度更新"""
        with self.lock:
            progress_bar = self._generate_progress_bar()
            print(f"{self._get_timestamp()}{progress_bar}")
    
    def show_final_summary(self, summary: Dict[str, Any]):
        """显示最终摘要"""
        self._print_header("📊 渗透测试完成")
        
        # 基本统计
        stats = summary.get("discovery_stats", {})
        print(f"{self._get_timestamp()}📈 发现统计:")
        print(f"{self._get_timestamp()}   🛠️ 服务: {stats.get('services_found', 0)}")
        print(f"{self._get_timestamp()}   🐛 漏洞: {stats.get('vulnerabilities_found', 0)}")
        print(f"{self._get_timestamp()}   🔓 访问点: {stats.get('access_points', 0)}")
        print(f"{self._get_timestamp()}   📁 敏感数据: {stats.get('sensitive_data', 0)}")
        
        # 风险评估
        risk = summary.get("risk_assessment", {})
        if risk:
            risk_level = risk.get("level", "未知")
            risk_color = {
                "低": "green",
                "中": "yellow", 
                "高": "red",
                "严重": "red"
            }.get(risk_level, "white")
            
            print(f"\n{self._get_timestamp()}🛡️ 风险评估:")
            print(f"{self._get_timestamp()}   级别: {self._colorize(risk_level, risk_color)}")
            print(f"{self._get_timestamp()}   评分: {risk.get('score', 0)}/100")
        
        # 执行时间
        session_info = summary.get("session_info", {})
        duration = session_info.get("duration_seconds", 0)
        print(f"\n{self._get_timestamp()}⏱️ 总耗时: {duration:.1f} 秒")
        
        # 报告文件
        report_file = summary.get("report_file")
        if report_file:
            print(f"{self._get_timestamp()}📄 详细报告: {self._colorize(report_file, 'cyan')}")
    
    def show_interactive_prompt(self, prompt: str) -> str:
        """显示交互式提示"""
        with self.lock:
            try:
                response = input(f"{self._get_timestamp()}{self._colorize('❓', 'yellow')} {prompt}")
                return response.strip()
            except KeyboardInterrupt:
                print(f"\n{self._get_timestamp()}{self._colorize('⚠️', 'yellow')} 用户中断")
                return ""
    
    def show_thinking_animation(self, message: str, duration: float = 2.0):
        """显示思考动画"""
        animation_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        start_time = time.time()
        i = 0
        
        while time.time() - start_time < duration:
            with self.lock:
                char = animation_chars[i % len(animation_chars)]
                sys.stdout.write(f"\r{self._get_timestamp()}{char} {message}")
                sys.stdout.flush()
            
            time.sleep(0.1)
            i += 1
        
        # 清除动画行
        with self.lock:
            sys.stdout.write(f"\r{' ' * (len(message) + 20)}\r")
            sys.stdout.flush()
    
    def clear_screen(self):
        """清屏"""
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def pause(self, message: str = "按回车键继续..."):
        """暂停等待用户输入"""
        with self.lock:
            input(f"{self._get_timestamp()}{self._colorize('⏸️', 'yellow')} {message}")


# 全局进度显示实例
progress_display = ProgressDisplay()
