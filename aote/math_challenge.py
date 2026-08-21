"""
AOTE 管控系统 - 数学挑战模块（Math Challenge）
核心要求：
1. 题目为四位数加减乘除法运算
2. 结果必须是10位数
3. 做题期间通过浏览器沙盒拦截数学解题工具站点（纯浏览器层面，无进程操作）
"""
import random
import time
import threading
import sys
import hashlib
from typing import Tuple, Callable, Optional
from dataclasses import dataclass
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox

from .config import ConfigManager
from .logger import AOTELogger
from .browser_sandbox import BrowserSandbox, MODE_MATH_LOCKDOWN


@dataclass
class MathQuestion:
    """数学题目数据结构"""
    text: str
    answer: int
    unlock_seconds: int
    level: int


class QuestionGenerator:
    """
    题目生成器
    规则：使用四位数（1000-9999）进行加减乘除运算，结果必须是10位数（1,000,000,000 ~ 9,999,999,999）
    """

    def __init__(self, config: ConfigManager):
        self.config = config
        params = config.get("math_challenge.question_params", {})
        self.min_num = params.get("min_number", 1000)
        self.max_num = params.get("max_number", 9999)
        self.result_min = params.get("result_min", 1_000_000_000)
        self.result_max = params.get("result_max", 9_999_999_999)
        self.operations = params.get("operations", ["+", "-", "*", "/"])

    # ============ 辅助方法 ============
    def _rand_4digit(self) -> int:
        return random.randint(self.min_num, self.max_num)

    def _is_10digit(self, n: int) -> bool:
        return self.result_min <= n <= self.result_max

    # ============ 难度一：3个四位数连乘 ============
    def _generate_level1(self) -> Tuple[str, int]:
        """
        难度一：3个四位数连乘
        因为 2个四位数最大乘积 = 9999*9999 = 99980001 (8位，不够10位)
        所以至少需要3个四位数相乘才能得到10位数
        """
        for _ in range(2000):
            a = self._rand_4digit()
            b = self._rand_4digit()
            c = self._rand_4digit()
            result = a * b * c
            if self._is_10digit(result):
                return f"{a} × {b} × {c} = ?", result
        # Fallback: 直接构造
        a = random.randint(1000, 1500)
        b = random.randint(1000, 1500)
        c = random.randint(666, 9999)  # 允许第三个数略作调整
        # 调整至10位数
        target = random.randint(self.result_min, self.result_min + 999_999_999)
        c = max(self.min_num, min(self.max_num, target // (a * b)))
        result = a * b * c
        if not self._is_10digit(result):
            # 兜底：直接取一个已知10位数的组合
            a, b, c = 1024, 2048, 480  # 1024*2048=2,097,152; 2,097,152*480=1,006,632,960
            result = a * b * c
        return f"{a} × {b} × {c} = ?", result

    # ============ 难度二：混合运算 ============
    def _generate_level2(self) -> Tuple[str, int]:
        """
        难度二：混合运算（加减乘除组合）
        形式如：(a × b) + (c × d) = ?
        或：(a + b) × (c - d) = ?
        结果必须为10位数
        """
        generators = [
            self._gen_type1,  # (a×b) + (c×d)
            self._gen_type2,  # (a+b) × (c×d)
            self._gen_type3,  # a × b × c + d
            self._gen_type4,  # (a - b) × c × d
        ]
        random.shuffle(generators)
        for gen in generators:
            for _ in range(500):
                q, r = gen()
                if q and self._is_10digit(r):
                    return q, r
        # Fallback
        return self._generate_level1()

    def _gen_type1(self) -> Tuple[Optional[str], int]:
        """(a × b) + (c × d)"""
        # 两个乘积项，每乘积约5亿，加起来10亿
        target_each = 500_000_000
        # 构造 a×b ≈ 5亿
        a = self._rand_4digit()
        b = max(self.min_num, min(self.max_num, target_each // a))
        product1 = a * b
        # 构造 c×d = 10位数 - product1
        remaining = random.randint(self.result_min, self.result_max) - product1
        if remaining < self.min_num * self.min_num:
            return None, 0
        c = self._rand_4digit()
        d = max(self.min_num, min(self.max_num, remaining // c))
        product2 = c * d
        total = product1 + product2
        if not self._is_10digit(total):
            return None, 0
        return f"({a} × {b}) + ({c} × {d}) = ?", total

    def _gen_type2(self) -> Tuple[Optional[str], int]:
        """(a + b) × (c × d)"""
        a = self._rand_4digit()
        b = self._rand_4digit()
        sum_ab = a + b  # 2000 ~ 19998
        # 需要 c×d 在 10位数 / sum_ab 范围内
        min_cd = (self.result_min + sum_ab - 1) // sum_ab
        max_cd = self.result_max // sum_ab
        # 找 c×d 在此范围内的四位数
        c = self._rand_4digit()
        d_min = max(self.min_num, (min_cd + c - 1) // c)
        d_max = min(self.max_num, max_cd // c)
        if d_min > d_max or d_min > self.max_num or d_max < self.min_num:
            return None, 0
        d = random.randint(d_min, d_max)
        result = (a + b) * c * d
        if not self._is_10digit(result):
            return None, 0
        return f"({a} + {b}) × {c} × {d} = ?", result

    def _gen_type3(self) -> Tuple[Optional[str], int]:
        """a × b × c + d"""
        a = self._rand_4digit()
        b = self._rand_4digit()
        product_ab = a * b
        # a*b*c 大约 999,999,000 左右，再加一个四位数
        target_product = self.result_max - 5000
        c = max(self.min_num, min(self.max_num, target_product // product_ab))
        product_abc = a * b * c
        remaining = self.result_max - product_abc
        if remaining < self.min_num or remaining > self.max_num:
            return None, 0
        d = remaining
        result = product_abc + d
        if not self._is_10digit(result):
            return None, 0
        return f"{a} × {b} × {c} + {d} = ?", result

    def _gen_type4(self) -> Tuple[Optional[str], int]:
        """(a - b) × c × d"""
        a = self._rand_4digit()
        b = random.randint(self.min_num, a - 1)  # 保证结果为正
        diff_ab = a - b  # 1 ~ 8999
        if diff_ab < 100:
            return None, 0
        min_cd = (self.result_min + diff_ab - 1) // diff_ab
        max_cd = self.result_max // diff_ab
        c = self._rand_4digit()
        d_min = max(self.min_num, (min_cd + c - 1) // c)
        d_max = min(self.max_num, max_cd // c)
        if d_min > d_max or d_min > self.max_num or d_max < self.min_num:
            return None, 0
        d = random.randint(d_min, d_max)
        result = diff_ab * c * d
        if not self._is_10digit(result):
            return None, 0
        return f"({a} - {b}) × {c} × {d} = ?", result

    # ============ 公共接口 ============
    def generate_question(self, level: int) -> MathQuestion:
        """
        生成指定难度的数学题目
        :param level: 1=难度一(5分钟), 2=难度二(10分钟)
        :return: MathQuestion 对象
        """
        if level == 1:
            text, answer = self._generate_level1()
            unlock_seconds = self.config.get("math_challenge.level_1_reward_seconds", 300)
        else:
            text, answer = self._generate_level2()
            unlock_seconds = self.config.get("math_challenge.level_2_reward_seconds", 600)

        return MathQuestion(
            text=text,
            answer=answer,
            unlock_seconds=unlock_seconds,
            level=level
        )


class MathChallengeWindow:
    """
    数学挑战GUI窗口
    - 置顶显示，不可关闭
    - 显示期间通过浏览器沙盒拦截解题工具网站
    """

    def __init__(self, config: ConfigManager, logger: AOTELogger,
                 browser_sandbox: BrowserSandbox,
                 on_success: Callable[[int], None]):
        """
        :param browser_sandbox: 浏览器沙盒（做题期间切换为数学挑战拦截模式）
        :param on_success: 答题成功回调 on_success(unlock_seconds)
        """
        self.config = config
        self.logger = logger
        self.browser_sandbox = browser_sandbox
        self.on_success = on_success

        self.generator = QuestionGenerator(config)
        self.current_question: Optional[MathQuestion] = None
        self.question_start_time: float = 0

        self._result_event = threading.Event()
        self._success = False

        self.root: Optional[tk.Tk] = None
        self.question_label: Optional[tk.Label] = None
        self.answer_entry: Optional[tk.Entry] = None
        self.status_label: Optional[tk.Label] = None
        self.level_var: Optional[tk.IntVar] = None

        # 倒计时相关
        self._countdown_seconds: int = 120
        self._countdown_label: Optional[tk.Label] = None
        self._level_info_label: Optional[tk.Label] = None
        self._countdown_job = None

        # 线程相关
        self._thread: Optional[threading.Thread] = None

    # ============ 防作弊：浏览器内容拦截 ============
    def _enter_math_lockdown(self):
        """进入做题模式：浏览器沙盒切换到数学挑战拦截模式（拦截解题工具站点）"""
        if self.browser_sandbox is not None:
            try:
                self.browser_sandbox.set_control_mode(MODE_MATH_LOCKDOWN)
                self.logger.info("[MathChallenge] 数学题防作弊浏览器拦截已启用")
            except Exception as e:
                self.logger.error(f"[MathChallenge] 启用浏览器拦截失败: {e}")

    def _exit_math_lockdown(self):
        """退出做题模式：恢复严格管控"""
        if self.browser_sandbox is not None:
            try:
                self.browser_sandbox.restore_strict_mode()
                self.logger.info("[MathChallenge] 数学题防作弊浏览器拦截已解除")
            except Exception as e:
                self.logger.error(f"[MathChallenge] 解除浏览器拦截失败: {e}")

    # ============ 题目操作 ============
    def _new_question(self, level: int):
        """生成新题目"""
        self.current_question = self.generator.generate_question(level)
        self.question_start_time = time.time()
        self.question_label.config(text=self.current_question.text)
        self.answer_entry.delete(0, tk.END)
        self.status_label.config(text="请输入你的答案（10位整数）", foreground="#595959")
        # 重置倒计时
        self._countdown_seconds = int(self.config.get("math_challenge.question_timeout", 120))
        self._update_countdown_display()
        # 更新难度信息
        if self._level_info_label:
            self._level_info_label.config(
                text=f"当前难度: {'⭐ 基础' if self.current_question.level == 1 else '⭐⭐ 进阶'}   "
                     f"解锁时长: {self.current_question.unlock_seconds // 60} 分钟"
            )

    def _check_answer(self):
        """检查用户答案"""
        if not self.current_question:
            return

        user_input = self.answer_entry.get().strip()
        duration = time.time() - self.question_start_time

        # 记录答案
        try:
            user_answer = int(user_input)
        except ValueError:
            # 非数字：直接换题
            self.logger.log_math_attempt(
                self.current_question.text, user_input,
                str(self.current_question.answer), False, duration,
                self.current_question.level
            )
            self.status_label.config(text="⚠ 请输入有效的整数！新题已生成", foreground="red")
            self._new_question(self.current_question.level)
            return

        is_correct = (user_answer == self.current_question.answer)

        # 日志
        self.logger.log_math_attempt(
            self.current_question.text, user_input,
            str(self.current_question.answer), is_correct, duration,
            self.current_question.level
        )

        if is_correct:
            self._cancel_countdown()
            self._success = True
            unlock = self.current_question.unlock_seconds
            self.status_label.config(text=f"✓ 回答正确！系统将在 {unlock//60} 分钟内保持解锁", foreground="green")
            self.root.update()
            time.sleep(1.5)
            self._exit_math_lockdown()
            try:
                self.on_success(unlock)
            except Exception as e:
                self.logger.error(f"成功回调异常: {e}")
            self._result_event.set()
            try:
                self.root.destroy()
            except Exception:
                pass
        else:
            # 错误：换题，不提示正确答案
            self.status_label.config(text="✗ 回答错误！新题已生成，请继续努力", foreground="red")
            self._new_question(self.current_question.level)

    # ============ 窗口构建 ============
    def _build_window(self, level: int = 1):
        """构建tkinter窗口 - 现代化UI"""
        self.root = tk.Tk()
        self.root.title("实力主义至上一体机 - 数学挑战")

        # 窗口设置：非最大化，居中
        w, h = 860, 620
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.minsize(700, 500)
        self.root.resizable(True, True)
        self.root.attributes("-topmost", True)
        self.root.configure(bg="#f0f2f5")

        # 禁用关闭按钮
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)

        # 键盘绑定：禁用 Alt+F4 / Escape，Enter 提交
        def _on_key(event):
            if event.keysym == "F4" and (event.state & 0x20000):
                return "break"
            if event.keysym == "Escape":
                return "break"
            if event.keysym == "Return":
                self._check_answer()
                return "break"
        self.root.bind_all("<Key>", _on_key)

        # 字体定义
        TITLE_FONT = ("Microsoft YaHei", 20, "bold")
        QUESTION_FONT = ("Consolas", 32, "bold")
        TIMER_FONT = ("Consolas", 22, "bold")
        NORMAL_FONT = ("Microsoft YaHei", 13)
        BTN_FONT = ("Microsoft YaHei", 12, "bold")
        SMALL_FONT = ("Microsoft YaHei", 10)

        # === 顶部标题栏（含倒计时） ===
        header = tk.Frame(self.root, bg="#1a73e8", height=60)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)

        tk.Label(
            header, text="🎓 数学挑战解锁系统",
            font=TITLE_FONT, fg="white", bg="#1a73e8"
        ).pack(side=tk.LEFT, padx=20)

        self._countdown_label = tk.Label(
            header, text="⏱ 02:00",
            font=TIMER_FONT, fg="#ffec3d", bg="#1a73e8"
        )
        self._countdown_label.pack(side=tk.RIGHT, padx=20)

        # === 欢迎语 ===
        tk.Label(
            self.root,
            text="欢迎使用实力至上的一体机(All-in-One of the Elite)，如果你想用浏览器，那就向我证明你的实力吧",
            font=("Microsoft YaHei", 11),
            fg="#1a73e8", bg="#e8f0fe",
            pady=8
        ).pack(fill=tk.X, side=tk.TOP)

        # === 主体内容 ===
        main = tk.Frame(self.root, bg="#f0f2f5", padx=30, pady=20)
        main.pack(fill=tk.BOTH, expand=True)

        # 生成题目
        self.level_var = tk.IntVar(value=level)
        if not self.current_question:
            self.current_question = self.generator.generate_question(level)
            self.question_start_time = time.time()

        # 难度信息栏
        info_frame = tk.Frame(main, bg="#f0f2f5")
        info_frame.pack(fill=tk.X, pady=(0, 15))

        self._level_info_label = tk.Label(
            info_frame,
            text=f"当前难度: {'⭐ 基础' if self.current_question.level == 1 else '⭐⭐ 进阶'}   "
                 f"解锁时长: {self.current_question.unlock_seconds // 60} 分钟",
            font=NORMAL_FONT, fg="#595959", bg="#f0f2f5"
        )
        self._level_info_label.pack(side=tk.LEFT)

        # 难度切换按钮
        switch_frame = tk.Frame(info_frame, bg="#f0f2f5")
        switch_frame.pack(side=tk.RIGHT)
        tk.Button(
            switch_frame, text="难度一(5分钟)",
            font=SMALL_FONT, bg="#e8f0fe", fg="#1a73e8",
            relief=tk.FLAT, padx=10, pady=4, cursor="hand2",
            command=lambda: self._new_question(1)
        ).pack(side=tk.LEFT, padx=4)
        tk.Button(
            switch_frame, text="难度二(10分钟)",
            font=SMALL_FONT, bg="#e8f0fe", fg="#1a73e8",
            relief=tk.FLAT, padx=10, pady=4, cursor="hand2",
            command=lambda: self._new_question(2)
        ).pack(side=tk.LEFT, padx=4)

        # === 题目卡片 ===
        q_card = tk.Frame(
            main, bg="white",
            highlightbackground="#d9d9d9", highlightthickness=1
        )
        q_card.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        self.question_label = tk.Label(
            q_card,
            text=self.current_question.text,
            font=QUESTION_FONT,
            fg="#1a1a1a", bg="white",
            justify=tk.CENTER
        )
        self.question_label.pack(expand=True)

        # === 答案输入区 ===
        input_frame = tk.Frame(main, bg="#f0f2f5")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            input_frame, text="答案:", font=NORMAL_FONT,
            bg="#f0f2f5", fg="#595959"
        ).pack(side=tk.LEFT, padx=(0, 8))

        self.answer_entry = tk.Entry(
            input_frame,
            font=("Consolas", 22, "bold"),
            width=20, justify=tk.CENTER,
            relief=tk.FLAT, bg="white", fg="#1a1a1a",
            highlightbackground="#1a73e8", highlightthickness=2
        )
        self.answer_entry.pack(side=tk.LEFT, padx=5, ipady=10)
        self.answer_entry.focus_set()

        tk.Button(
            input_frame, text="✓ 提交答案 (Enter)",
            font=BTN_FONT, bg="#1a73e8", fg="white",
            activebackground="#1557b0", activeforeground="white",
            relief=tk.FLAT, padx=20, pady=10, cursor="hand2",
            command=self._check_answer
        ).pack(side=tk.LEFT, padx=10)

        tk.Button(
            input_frame, text="🔄 换一题",
            font=BTN_FONT, bg="#ffffff", fg="#595959",
            relief=tk.FLAT, padx=15, pady=10, cursor="hand2",
            highlightbackground="#d9d9d9", highlightthickness=1,
            command=lambda: self._new_question(self.current_question.level)
        ).pack(side=tk.LEFT, padx=5)

        # === 状态提示 ===
        self.status_label = tk.Label(
            main, text="请输入你的答案（10位整数）",
            font=("Microsoft YaHei", 12), fg="#595959", bg="#f0f2f5"
        )
        self.status_label.pack(pady=(5, 10))

        # === 底部操作栏（含退出按钮） ===
        bottom = tk.Frame(self.root, bg="#ffffff", height=55)
        bottom.pack(fill=tk.X, side=tk.BOTTOM)
        bottom.pack_propagate(False)

        tk.Label(
            bottom, text="💡 做题期间已拦截解题工具网站",
            font=SMALL_FONT, fg="#8c8c8c", bg="#ffffff"
        ).pack(side=tk.LEFT, padx=20)

        tk.Button(
            bottom, text="🚪 放弃挑战",
            font=BTN_FONT, bg="#ff4d4f", fg="white",
            activebackground="#cf1322", activeforeground="white",
            relief=tk.FLAT, padx=20, pady=8, cursor="hand2",
            command=self._on_exit_clicked
        ).pack(side=tk.RIGHT, padx=20)

        # 启动倒计时
        self._start_countdown()

    # ============ 倒计时 ============
    def _start_countdown(self):
        """启动倒计时"""
        self._countdown_seconds = int(self.config.get("math_challenge.question_timeout", 120))
        self._update_countdown_display()
        self._tick_countdown()

    def _tick_countdown(self):
        """每秒更新倒计时"""
        if not self.root:
            return
        self._countdown_seconds -= 1
        if self._countdown_seconds <= 0:
            self._new_question(self.current_question.level)
            self.status_label.config(text="⏰ 时间到！已自动切换下一题", foreground="#ff4d4f")
        self._update_countdown_display()
        try:
            self._countdown_job = self.root.after(1000, self._tick_countdown)
        except Exception:
            pass

    def _update_countdown_display(self):
        """更新倒计时显示"""
        if not self._countdown_label:
            return
        m = self._countdown_seconds // 60
        s = self._countdown_seconds % 60
        text = f"⏱ {m:02d}:{s:02d}"
        color = "#ff4d4f" if self._countdown_seconds <= 10 else "#ffec3d"
        try:
            self._countdown_label.config(text=text, fg=color)
        except Exception:
            pass

    def _cancel_countdown(self):
        """取消倒计时"""
        if self._countdown_job:
            try:
                self.root.after_cancel(self._countdown_job)
            except Exception:
                pass
            self._countdown_job = None

    # ============ 退出按钮 ============
    def _on_exit_clicked(self):
        """退出按钮：放弃挑战并关闭答题窗口（不涉及任何进程操作）"""
        self.logger.info("[MathChallenge] 用户点击退出按钮，放弃挑战")
        self._cancel_countdown()
        self._success = False
        try:
            if self.root:
                self.root.destroy()
        except Exception:
            pass

    # ============ 显示/等待 ============
    def show_and_wait(self, level: int = 1) -> bool:
        """
        显示数学挑战窗口并阻塞等待结果
        :return: True=用户答题成功，False=窗口被管理员关闭等
        """
        self._result_event.clear()
        self._success = False

        # 启动防作弊
        self._enter_math_lockdown()

        def _run():
            try:
                self._build_window(level)
                self.root.mainloop()
            except Exception as e:
                self.logger.error(f"数学挑战窗口异常: {e}")
            finally:
                try:
                    if self.root:
                        self.root.destroy()
                except Exception:
                    pass
                self.root = None
                self._exit_math_lockdown()
                if not self._success:
                    self._result_event.set()

        self._thread = threading.Thread(target=_run, daemon=True, name="MathChallengeUI")
        self._thread.start()

        # 等待完成
        self._result_event.wait()
        return self._success

    def force_close(self):
        """强制关闭窗口（管理员退出等场景）"""
        try:
            if self.root:
                self.root.after(0, lambda: self.root.destroy())
        except Exception:
            pass
        self._exit_math_lockdown()
        self._result_event.set()
