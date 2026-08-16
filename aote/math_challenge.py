"""
AOTE 管控系统 - 数学挑战模块（Math Challenge）
核心要求：
1. 题目为四位数加减乘除法运算
2. 结果必须是10位数
3. 做题期间冻结计算器、浏览器等能解数学题的工具
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
from .process_hunter import ProcessHunter


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
    - 显示期间冻结计算器、浏览器等工具
    """

    def __init__(self, config: ConfigManager, logger: AOTELogger,
                 process_hunter: ProcessHunter,
                 on_success: Callable[[int], None]):
        """
        :param on_success: 答题成功回调 on_success(unlock_seconds)
        """
        self.config = config
        self.logger = logger
        self.process_hunter = process_hunter
        self.on_success = on_success

        self.generator = QuestionGenerator(config)
        self.current_question: Optional[MathQuestion] = None
        self.question_start_time: float = 0

        self._result_event = threading.Event()
        self._success = False

        self.root: Optional[tk.Tk] = None
        self.question_label: Optional[ttk.Label] = None
        self.answer_entry: Optional[ttk.Entry] = None
        self.status_label: Optional[ttk.Label] = None
        self.level_var: Optional[tk.IntVar] = None

        # 线程相关
        self._thread: Optional[threading.Thread] = None

    # ============ 防作弊：冻结数学工具 ============
    def _enter_math_lockdown(self):
        """进入做题模式：冻结所有计算器、浏览器等"""
        targets = self.config.math_lockdown_processes
        self.process_hunter.set_extra_targets(targets)
        self.logger.info("[MathChallenge] 数学题防作弊锁定已启用")

    def _exit_math_lockdown(self):
        """退出做题模式：恢复计算器等"""
        self.process_hunter.clear_extra_targets()
        self.logger.info("[MathChallenge] 数学题防作弊锁定已解除")

    # ============ 题目操作 ============
    def _new_question(self, level: int):
        """生成新题目"""
        self.current_question = self.generator.generate_question(level)
        self.question_start_time = time.time()
        self.question_label.config(
            text=f"题目 (难度{level}):\n\n{self.current_question.text}",
        )
        self.answer_entry.delete(0, tk.END)
        self.status_label.config(text="请输入你的答案（10位整数）", foreground="#1a1a1a")

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
        """构建tkinter窗口"""
        self.root = tk.Tk()
        self.root.title("实力主义至上一体机 - 数学挑战")

        # 窗口设置：置顶、居中、大尺寸
        w, h = 720, 520
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.minsize(600, 400)
        self.root.attributes("-topmost", True)  # 置顶
        try:
            self.root.state("zoomed")  # Windows 最大化
        except tk.TclError:
            pass
        self.root.configure(bg="#004d8c")

        # 禁用关闭按钮
        def _dummy_close():
            pass
        self.root.protocol("WM_DELETE_WINDOW", _dummy_close)

        # 全局快捷键：禁用 Alt+F4, Win 等
        def _on_key(event):
            # 防止 Alt+F4
            if event.keysym == "F4" and (event.state & 0x20000):
                return "break"
            # 防止 Escape 关闭
            if event.keysym == "Escape":
                return "break"
            # 提交答案 Enter
            if event.keysym == "Return":
                self._check_answer()
                return "break"
        self.root.bind_all("<Key>", _on_key)

        # 样式
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        # 大字体
        BIG_FONT = ("Microsoft YaHei", 28, "bold")
        NORMAL_FONT = ("Microsoft YaHei", 14)
        BTN_FONT = ("Microsoft YaHei", 12, "bold")

        # 顶部标题
        header = tk.Frame(self.root, bg="#003366", height=70)
        header.pack(fill=tk.X, side=tk.TOP)
        title_label = tk.Label(
            header, text="🎓 数学挑战解锁系统",
            font=("Microsoft YaHei", 22, "bold"),
            fg="white", bg="#003366"
        )
        title_label.pack(pady=15)

        # 主体内容框
        main = tk.Frame(self.root, bg="white", padx=40, pady=30)
        main.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # 难度选择（第一次选择）
        self.level_var = tk.IntVar(value=level)
        if not self.current_question:
            self._new_question(level)

        # 难度信息栏
        level_frame = tk.Frame(main, bg="white")
        level_frame.pack(fill=tk.X, pady=(0, 20))
        tk.Label(
            level_frame,
            text=f"当前难度: {'⭐ 基础' if self.current_question.level == 1 else '⭐⭐ 进阶'}   "
                 f"解锁时长: {self.current_question.unlock_seconds // 60} 分钟",
            font=("Microsoft YaHei", 12),
            fg="#555", bg="white"
        ).pack(side=tk.LEFT)

        # 切换难度按钮
        switch_frame = tk.Frame(level_frame, bg="white")
        switch_frame.pack(side=tk.RIGHT)
        ttk.Button(
            switch_frame, text="换难度一(5分钟)",
            command=lambda: self._new_question(1),
            style="Accent.TButton"
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            switch_frame, text="换难度二(10分钟)",
            command=lambda: self._new_question(2),
            style="Accent.TButton"
        ).pack(side=tk.LEFT, padx=4)

        # 题目显示
        q_frame = tk.Frame(main, bg="#f0f7ff", padx=20, pady=30, relief=tk.RIDGE, bd=2)
        q_frame.pack(fill=tk.X, pady=10)
        self.question_label = tk.Label(
            q_frame,
            text=f"题目:\n\n{self.current_question.text}",
            font=BIG_FONT,
            fg="#001f3f",
            bg="#f0f7ff",
            justify=tk.CENTER,
            wraplength=600
        )
        self.question_label.pack()

        # 输入框
        input_frame = tk.Frame(main, bg="white")
        input_frame.pack(fill=tk.X, pady=25)
        tk.Label(input_frame, text="答案: ", font=NORMAL_FONT, bg="white").pack(side=tk.LEFT)
        self.answer_entry = ttk.Entry(
            input_frame,
            font=("Consolas", 20, "bold"),
            width=18,
            justify=tk.CENTER
        )
        self.answer_entry.pack(side=tk.LEFT, padx=10, ipady=8)
        self.answer_entry.focus_set()

        # 提交按钮
        submit_btn = tk.Button(
            input_frame, text="提交答案 (Enter)",
            font=BTN_FONT,
            bg="#0078d7", fg="white",
            activebackground="#005a9e", activeforeground="white",
            relief=tk.FLAT, padx=20, pady=10,
            cursor="hand2",
            command=self._check_answer
        )
        submit_btn.pack(side=tk.LEFT, padx=10)

        # 换一题按钮
        new_btn = tk.Button(
            input_frame, text="换一题",
            font=BTN_FONT,
            bg="#e1e1e1", fg="#333",
            relief=tk.FLAT, padx=15, pady=10,
            cursor="hand2",
            command=lambda: self._new_question(self.current_question.level)
        )
        new_btn.pack(side=tk.LEFT, padx=5)

        # 状态提示
        self.status_label = tk.Label(
            main, text="请输入你的答案（10位整数）",
            font=("Microsoft YaHei", 12, "bold"),
            fg="#1a1a1a", bg="white"
        )
        self.status_label.pack(pady=10)

        # 底部提示
        footer = tk.Frame(self.root, bg="#004d8c", height=50)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(
            footer,
            text="💡 提示：答案必须为整数（可正可负）。答对即可获得临时解锁权限。做题期间计算器和浏览器已禁用。",
            font=("Microsoft YaHei", 10),
            fg="#cce4ff", bg="#004d8c"
        ).pack(pady=12)

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
