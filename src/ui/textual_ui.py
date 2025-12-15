"""
基于Textual的现代化GUI界面
解决rich库的抖动和滚动问题
"""
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, RichLog, Input
from textual.containers import Container, Horizontal, Vertical
from textual.binding import Binding
from textual.reactive import reactive
from datetime import datetime
from typing import Optional, Dict, Any, List
import asyncio
from ..utils.i18n import t


class TaskListWidget(Static):
    """任务列表组件 - 显示Kill Chain各阶段的任务"""
    
    @property
    def PHASE_NAMES(self):
        return {
            "reconnaissance": t("phase.reconnaissance"),
            "weaponization": t("phase.weaponization"),
            "delivery": t("phase.delivery"),
            "exploitation": t("phase.exploitation"),
            "installation": t("phase.installation"),
            "command_control": t("phase.command_control"),
            "actions_objectives": t("phase.actions_objectives")
        }
    
    PHASE_ORDER = [
        "reconnaissance", "weaponization", "delivery",
        "exploitation", "installation", "command_control", "actions_objectives"
    ]
    
    tasks_info: reactive[Dict[str, Any]] = reactive({})
    
    def render(self) -> str:
        """渲染任务列表"""
        lines = []
        lines.append(f"[bold cyan]{t('task_list.title')}[/bold cyan]")
        lines.append("")
        
        if not self.tasks_info or not isinstance(self.tasks_info, dict):
            lines.append(f"[dim]{t('task_list.waiting')}[/dim]")
            return "\n".join(lines)
        
        tasks_by_status = self.tasks_info.get("tasks_by_status", {})
        if not tasks_by_status:
            lines.append(f"[dim]{t('task_list.no_tasks')}[/dim]")
            return "\n".join(lines)
        
        all_tasks = []
        
        for status, task_list in tasks_by_status.items():
            for task in task_list:
                task["status"] = status
                all_tasks.append(task)
        
        # 按阶段分组
        phases = {}
        for task in all_tasks:
            phase = task.get("phase", "unknown")
            if phase not in phases:
                phases[phase] = []
            phases[phase].append(task)
        
        # 按顺序渲染每个阶段
        phase_names = self.PHASE_NAMES
        for phase_key in self.PHASE_ORDER:
            if phase_key not in phases:
                continue
            
            phase_tasks = phases[phase_key]
            phase_name = phase_names.get(phase_key, phase_key)
            
            # 计算阶段状态
            completed = sum(1 for t in phase_tasks if t.get("status") == "completed")
            in_progress = sum(1 for t in phase_tasks if t.get("status") == "in_progress")
            failed = sum(1 for t in phase_tasks if t.get("status") == "failed")
            total = len(phase_tasks)
            
            # 阶段状态
            if completed == total:
                phase_status = "✅"
                phase_style = "green"
            elif in_progress > 0:
                phase_status = "⏳"
                phase_style = "yellow bold"
            elif failed > 0:
                phase_status = "❌"
                phase_style = "red"
            else:
                phase_status = "⭕"
                phase_style = "dim"
            
            lines.append(f"[{phase_style}]{phase_status} {phase_name}[/{phase_style}] [dim]({completed}/{total})[/dim]")
            
            # 任务列表
            for task in phase_tasks:
                task_title = task.get("title", t("task_list.unnamed_task"))
                task_status = task.get("status", "pending")
                
                if task_status == "completed":
                    symbol = "  ✓"
                    style = "green dim"
                elif task_status == "in_progress":
                    symbol = "  ▶"
                    style = "yellow bold"
                elif task_status == "failed":
                    symbol = "  ✗"
                    style = "red"
                else:
                    symbol = "  ○"
                    style = "dim"
                
                status_text = f" {t('task_list.executing')}" if task_status == "in_progress" else ""
                lines.append(f"[{style}]{symbol} {task_title}{status_text}[/{style}]")
            
            lines.append("")  # 空行分隔
        
        return "\n".join(lines)


class StatusWidget(Static):
    """当前状态组件 - 显示正在执行的任务"""
    
    current_task: reactive[Optional[Dict[str, Any]]] = reactive(None)
    exec_state: reactive[Optional[Dict[str, Any]]] = reactive(None)
    target: reactive[str] = reactive("")
    session_id: reactive[str] = reactive("")
    
    def render(self) -> str:
        """渲染状态信息"""
        lines = []
        lines.append(f"[bold yellow]{t('status.current_status')}[/bold yellow]")
        lines.append("")
        lines.append(f"[cyan]{t('status.target')}[/cyan] [white]{self.target}[/white]")
        lines.append(f"[dim]{t('status.session')} {self.session_id[:8] if self.session_id else 'N/A'}...[/dim]")
        lines.append("")
        
        # 优先使用exec_state
        if self.exec_state and isinstance(self.exec_state, dict) and (self.exec_state.get("command") or self.exec_state.get("tool")):
            lines.append(f"[yellow bold]{t('status.current_execution')}[/yellow bold]")
            lines.append("")
            
            agent = self.exec_state.get("agent", "")
            if agent:
                lines.append(f"[cyan]{t('status.agent')}[/cyan] [white]{agent}[/white]")
            
            tool = self.exec_state.get("tool", "")
            if tool:
                lines.append(f"[green]{t('status.tool')}[/green] [bold white]{tool}[/bold white]")
            
            description = self.exec_state.get("description", "")
            if description:
                # 限制长度
                if len(description) > 50:
                    description = description[:50] + "..."
                lines.append(f"[dim]{t('status.description')} {description}[/dim]")
            
            # 显示命令
            command = self.exec_state.get("command", "")
            if command:
                lines.append("")
                lines.append(f"[green bold]{t('status.command')}[/green bold]")
                # 限制命令显示长度
                if len(command) > 60:
                    lines.append(f"[green]{command[:60]}[/green]")
                    lines.append(f"[green]   {command[60:120]}...[/green]")
                else:
                    lines.append(f"[green]$ {command}[/green]")
            
            # 显示最近输出（前3行）
            output_lines = self.exec_state.get("output_lines", [])
            if output_lines and isinstance(output_lines, list):
                lines.append("")
                lines.append(f"[blue dim]{t('status.recent_output')}[/blue dim]")
                for line in output_lines[-3:]:
                    if line:
                        display_line = str(line)[:55] + "..." if len(str(line)) > 55 else str(line)
                        lines.append(f"[dim]  {display_line}[/dim]")
        
        elif self.current_task and isinstance(self.current_task, dict):
            lines.append(f"[yellow bold]{t('status.current_task')}[/yellow bold]")
            lines.append("")
            title = self.current_task.get('title', 'N/A')
            lines.append(f"[white]{title}[/white]")
            
            tool = self.current_task.get("tool", "")
            if tool:
                lines.append(f"[green]{t('status.tool')}[/green] [white]{tool}[/white]")
            
            description = self.current_task.get("description", "")
            if description:
                if len(description) > 55:
                    description = description[:55] + "..."
                lines.append(f"[dim]{t('status.description')} {description}[/dim]")
        else:
            lines.append(f"[dim]{t('status.waiting')}[/dim]")
        
        return "\n".join(lines)


class PentestTUI(App):
    """基于Textual的渗透测试监控界面"""
    
    CSS = """
    Screen {
        layout: vertical;
    }
    
    #main_content {
        height: 18;
        layout: horizontal;
    }
    
    #tasks_panel {
        width: 60%;
        height: 100%;
        border: solid cyan;
    }
    
    #status_panel {
        width: 40%;
        height: 100%;
        border: solid yellow;
    }
    
    #task_list {
        height: 100%;
        padding: 1;
        overflow-y: auto;
    }
    
    #status_widget {
        height: 100%;
        padding: 1;
        overflow-y: auto;
    }
    
    #log_panel {
        height: 1fr;
        border: solid blue;
        padding: 0;
    }
    
    #log {
        height: 100%;
        border: none;
    }
    
    #input_container {
        height: 3;
        border: solid green;
    }
    
    #user_input {
        width: 100%;
        border: none;
    }
    
    RichLog {
        background: $surface;
    }
    
    Input {
        background: $surface;
    }
    """
    
    def __init__(self, framework, session_id: str, target: str):
        super().__init__()
        self.framework = framework
        self.session_id = session_id
        self.target = target
        self._monitoring = True
        self._update_task = None
        self._last_command = ""
        
        # 设置绑定（使用i18n）
        self.BINDINGS = [
            Binding("q", "quit", t("binding.quit"), priority=True),
            Binding("o", "toggle_output", t("binding.toggle_output")),
            Binding("r", "refresh", t("binding.refresh")),
            ("ctrl+c", "interrupt", t("binding.interrupt"))
        ]
    
    def compose(self) -> ComposeResult:
        """构建UI组件"""
        yield Header()
        
        # 主区域 - 任务列表和当前状态
        with Horizontal(id="main_content"):
            with Vertical(id="tasks_panel"):
                yield TaskListWidget(id="task_list")
            
            with Vertical(id="status_panel"):
                yield StatusWidget(id="status_widget")
        
        # 日志区（自动滚动）
        with Container(id="log_panel"):
            yield RichLog(id="log", auto_scroll=True, highlight=True, markup=True)
        
        # 输入区
        with Container(id="input_container"):
            yield Input(placeholder=t("app.input_placeholder"), id="user_input")
        
        yield Footer()
    
    async def on_mount(self) -> None:
        """挂载后初始化"""
        self.task_list_widget = self.query_one("#task_list", TaskListWidget)
        self.status_display = self.query_one("#status_widget", StatusWidget)
        self.rich_log = self.query_one("#log", RichLog)
        self.user_input = self.query_one("#user_input", Input)
        
        # 设置RichLog标题
        self.title = t("app.title")
        
        # 设置基本信息
        self.status_display.target = self.target
        self.status_display.session_id = self.session_id
        
        # 启动后台更新任务
        self._update_task = asyncio.create_task(self._update_loop())
        
        # 初始日志
        self.rich_log.write(f"[bold blue]{t('app.log_title')}[/bold blue]")
        self.rich_log.write("[dim]" + "─" * 60 + "[/dim]")
        self.rich_log.write(f"[green bold]{t('app.monitor_started')}[/green bold]")
        self.rich_log.write(f"[cyan]🎯 {t('status.target')} {self.target}[/cyan]")
        self.rich_log.write(f"[dim]📋 {t('status.session')} {self.session_id}[/dim]")
        self.rich_log.write(f"[dim]{t('app.tip')}[/dim]")
        self.rich_log.write("[dim]" + "─" * 60 + "[/dim]")
    
    async def _update_loop(self) -> None:
        """后台更新循环 - 定期刷新任务和状态"""
        last_log_count = 0
        update_counter = 0
        
        while self._monitoring:
            try:
                update_counter += 1
                
                # 每3次循环获取任务状态（减少API调用）
                if update_counter % 3 == 0:
                    try:
                        tasks_info = await self.framework.master_controller.get_all_tasks(
                            self.session_id
                        )
                        current_task = await self.framework.master_controller.get_current_executing_task(
                            self.session_id
                        )
                        
                        # 更新任务列表
                        self.task_list_widget.tasks_info = tasks_info
                        self.status_display.current_task = current_task
                        
                        # 检查是否完成
                        progress = tasks_info.get("progress", {})
                        completed = progress.get("completed", 0)
                        failed = progress.get("failed", 0)
                        total = progress.get("total", 0)
                        
                        if total > 0 and (completed + failed) >= total:
                            if completed == total:
                                self.rich_log.write(f"[green bold]{t('log.all_tasks_completed')}[/green bold]")
                            else:
                                self.rich_log.write(f"[yellow]{t('log.tasks_ended', completed=completed, failed=failed)}[/yellow]")
                            self.active = False
                            break
                        
                    except Exception as e:
                        self.rich_log.write(f"[red]{t('log.get_status_failed', error=str(e))}[/red]")
                
                # 每次循环都检查执行状态输出
                try:
                    from src.agents.base_agent import execution_state
                    exec_state = execution_state.get_state()
                    
                    # 更新显示
                    self.status_display.exec_state = exec_state
                    
                    # 检测新输出行
                    output_lines = exec_state.get("output_lines", [])
                    if output_lines and isinstance(output_lines, list) and len(output_lines) > last_log_count:
                        new_lines = output_lines[last_log_count:]
                        for line in new_lines:
                            if not line:
                                continue
                            line_clean = str(line).strip()
                            if line_clean and not self._should_filter_log(line_clean):
                                # Textual的RichLog会自动处理长行（换行）
                                timestamp = datetime.now().strftime("%H:%M:%S")
                                self.rich_log.write(f"[dim]{timestamp}[/dim] {line_clean}")
                        last_log_count = len(output_lines)
                    
                    # 检测命令变化
                    command = exec_state.get("command", "")
                    if command and command != getattr(self, '_last_command', ''):
                        self.rich_log.write(f"[green bold]{t('log.executing_command')}[/green bold] [green]{command}[/green]")
                        self._last_command = command
                    
                except Exception:
                    pass  # 静默处理
                
                # 平衡刷新间隔（既保证响应速度又不过度占用CPU）
                await asyncio.sleep(0.2)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.rich_log.write(f"[red]{t('log.update_loop_error', error=str(e))}[/red]")
                await asyncio.sleep(1)
    
    def _should_filter_log(self, line: str) -> bool:
        """过滤无用日志"""
        line_lower = line.lower()
        
        filter_patterns = [
            '<?xml', '<!doctype', '<taskprogress', '<verbose', '<debugging'
        ]
        
        for pattern in filter_patterns:
            if pattern in line_lower:
                return True
        
        # 纯闭合标签
        if line_lower.startswith('</') and line_lower.endswith('>'):
            return True
        
        return False
    
    def action_toggle_output(self) -> None:
        """切换输出显示"""
        try:
            from src.agents.base_agent import execution_state
            show = execution_state.toggle_output()
            icon = '✅' if show else '⏸️ '
            state = t("log.output_on") if show else t("log.output_off")
            self.rich_log.write(f"[cyan]{t('log.output_toggled', icon=icon, state=state)}[/cyan]")
        except Exception as e:
            self.rich_log.write(f"[red]{t('log.adjust_failed', error=str(e))}[/red]")
    
    def action_refresh(self) -> None:
        """手动刷新"""
        self.rich_log.write(f"[cyan]{t('log.manual_refresh')}[/cyan]")
    
    def action_cancel_input(self) -> None:
        """取消输入"""
        self.user_input.value = ""
        self.rich_log.write(f"[dim]{t('log.input_cancelled')}[/dim]")
    
    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """处理用户输入"""
        user_message = event.value.strip()
        if not user_message:
            return
        
        # 清空输入框
        self.user_input.value = ""
        
        # 特殊处理：用户输入q退出
        if user_message.lower() in ['q', 'quit', 'exit']:
            self.rich_log.write(f"[yellow bold]{t('log.user_exit')}[/yellow bold]")
            self._monitoring = False
            self.exit()
            return
        
        self.rich_log.write(f"[yellow bold]{t('log.user_info')}[/yellow bold] [white]{user_message}[/white]")
        self.rich_log.write(f"[cyan]{t('log.analyzing')}[/cyan]")
        
        try:
            # 调用handle_interrupt
            result = await self.framework.master_controller.handle_interrupt(
                self.session_id,
                user_message
            )
            
            if result.get("success"):
                action = result.get("action", "adjust_plan")
                reason = result.get("reason", "")
                restarted = result.get("restarted", False)
                
                if action == "restart_from_beginning":
                    self.rich_log.write(f"[yellow]{t('log.restart_from_beginning')}[/yellow]")
                elif action == "adjust_plan":
                    self.rich_log.write(f"[green]{t('log.plan_adjusted')}[/green]")
                else:
                    self.rich_log.write(f"[green]{t('log.new_task_added')}[/green]")
                
                self.rich_log.write(f"[dim]{t('log.reason', reason=reason)}[/dim]")
                
                if restarted:
                    self.rich_log.write(f"[green bold]{t('log.new_task_started')}[/green bold]")
                else:
                    self.rich_log.write(f"[dim]{t('log.system_ready')}[/dim]")
            else:
                error = result.get("error", t("common.unknown_error"))
                self.rich_log.write(f"[red]{t('log.adjust_failed', error=error)}[/red]")
        
        except Exception as e:
            self.rich_log.write(f"[red]{t('log.process_input_failed', error=str(e))}[/red]")
    
    async def on_unmount(self) -> None:
        """卸载时清理"""
        self._monitoring = False
        if self._update_task:
            self._update_task.cancel()
            try:
                await self._update_task
            except asyncio.CancelledError:
                pass


async def run_pentest_tui(framework, session_id: str, target: str):
    """运行Textual TUI"""
    app = PentestTUI(framework, session_id, target)
    await app.run_async()
