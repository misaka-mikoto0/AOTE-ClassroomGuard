"""
AOTE 管控系统 - 快速测试脚本
重点验证：
1. 数学题生成（四位数运算，结果10位数）
2. 配置加载
3. 模块可导入性
"""
import os
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)


def test_config():
    print("=" * 60)
    print("[1/4] 测试配置加载模块...")
    try:
        from aote.config import ConfigManager
        cfg = ConfigManager()
        targets = cfg.all_target_processes
        print(f"  ✔ 目标进程数量: {len(targets)}")
        assert len(targets) > 0, "目标进程为空"
        math_targets = cfg.math_lockdown_processes
        print(f"  ✔ 数学题冻结进程数量: {len(math_targets)}")
        print(f"    -> {math_targets[:8]}..." if len(math_targets) > 8 else f"    -> {math_targets}")
        params = cfg.get("math_challenge.question_params", {})
        print(f"  ✔ 数学题参数: 数字范围 [{params['min_number']}, {params['max_number']}]")
        print(f"            结果范围 [{params['result_min']}, {params['result_max']}]")
        print(f"            运算: {params['operations']}")
        print("  ✔ 配置加载通过")
        return True
    except AssertionError as e:
        print(f"  ✗ 断言失败: {e}")
        return False
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  ✗ 配置加载失败: {e}")
        return False


def test_logger():
    print("\n" + "=" * 60)
    print("[2/4] 测试日志模块...")
    try:
        from aote.logger import AOTELogger
        log = AOTELogger(log_path=os.path.join(BASE_DIR, "logs"), retention_days=7)
        log.info("测试消息 - info")
        log.warning("测试消息 - warning")
        log.log_mode_change("strict", "relaxed", "test")
        log.log_math_attempt("1+1=?", "2", "2", True, 5.0, 1)
        log.log_usb_event("insert", "E:\\", "ABC123", True)
        print("  ✔ 日志模块通过（检查logs/目录）")
        return True
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  ✗ 日志模块失败: {e}")
        return False


def test_math_question_generator():
    """
    核心用户需求测试：
    - 所有运算数必须是四位数（1000-9999）
    - 结果必须是10位数（1,000,000,000 ~ 9,999,999,999）
    """
    print("\n" + "=" * 60)
    print("[3/4] 测试数学题目生成（核心需求！）")
    print("  要求：")
    print("    ① 运算数 = 四位数 [1000, 9999]")
    print("    ② 结果 = 十位数 [1,000,000,000, 9,999,999,999]")
    try:
        from aote.config import ConfigManager
        from aote.math_challenge import QuestionGenerator

        cfg = ConfigManager()
        gen = QuestionGenerator(cfg)
        params = cfg.get("math_challenge.question_params", {})
        min_n = params.get("min_number", 1000)
        max_n = params.get("max_number", 9999)
        min_r = params.get("result_min", 1_000_000_000)
        max_r = params.get("result_max", 9_999_999_999)

        total_tests = 100
        pass_count = 0
        error_details = []

        for level in (1, 2):
            print(f"\n  --- 难度 {level}（每题解锁 {cfg.get(f'math_challenge.level_{level}_reward_seconds')//60} 分钟） ---")
            for i in range(total_tests // 2):
                q = gen.generate_question(level)
                # 验证结果范围
                is_10digit = min_r <= q.answer <= max_r
                # 验证题目中所有数字（简单正则提取）
                import re
                nums = [int(x) for x in re.findall(r"\b\d{4,}\b", q.text)]
                all_4digit = all(min_n <= n <= max_n for n in nums)

                status = "✓" if (is_10digit and all_4digit) else "✗"
                if status == "✓":
                    pass_count += 1
                else:
                    error_details.append(
                        f"  L{level} #{i}: {q.text} -> {q.answer} "
                        f"(nums_ok={all_4digit}, result_ok={is_10digit})"
                    )

                # 展示前3题
                if i < 3:
                    print(f"    {status} 题目: {q.text}")
                    print(f"       答案: {q.answer} (10位数={is_10digit}, 四位数运算数={all_4digit})")

        print(f"\n  通过率: {pass_count}/{total_tests} = {pass_count*100//total_tests}%")
        if error_details:
            print(f"  失败样例（前5条）:")
            for e in error_details[:5]:
                print(e)
        assert pass_count == total_tests, f"有 {total_tests - pass_count} 题不满足要求"
        print("  ✔ 数学题生成通过（所有题均满足：四位数运算 + 结果10位数）")
        return True
    except AssertionError as e:
        print(f"  ✗ 断言失败: {e}")
        return False
    except ImportError as e:
        print(f"  ✗ 导入失败: {e}")
        print("    请先安装依赖: pip install -r requirements.txt")
        return False
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  ✗ 数学题生成失败: {e}")
        return False


def test_time_guard_logic():
    """测试时间调度逻辑（不启动线程）"""
    print("\n" + "=" * 60)
    print("[4/4] 测试时间调度逻辑（静态判断）")
    try:
        from aote.config import ConfigManager
        from aote.logger import AOTELogger
        from aote.time_guard import TimeGuard

        cfg = ConfigManager()
        log = AOTELogger(log_path=os.path.join(BASE_DIR, "logs"))
        tg = TimeGuard(cfg, log)

        # 执行一次检查
        tg.do_check()
        mode_cn = {
            TimeGuard.MODE_STRICT: "严格模式",
            TimeGuard.MODE_RELAXED: "宽松模式",
            TimeGuard.MODE_EMERGENCY: "紧急模式",
        }
        print(f"  当前时间判断: {mode_cn.get(tg.current_mode, tg.current_mode)}")
        print(f"  is_strict_mode = {tg.is_strict_mode}")
        print(f"  is_relaxed_mode = {tg.is_relaxed_mode}")
        print("  ✔ 时间调度通过")
        return True
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  ✗ 时间调度失败: {e}")
        return False


def main():
    print("\n" + "#" * 60)
    print("#  AOTE 管控系统 - 功能验证")
    print("#" * 60)

    results = []
    results.append(("配置加载", test_config()))
    results.append(("日志模块", test_logger()))
    results.append(("数学题生成", test_math_question_generator()))
    results.append(("时间调度逻辑", test_time_guard_logic()))

    print("\n" + "=" * 60)
    print("📋 测试结果汇总:")
    print("=" * 60)
    all_pass = True
    for name, ok in results:
        icon = "✅ PASS" if ok else "❌ FAIL"
        print(f"  {icon:8s}  {name}")
        all_pass = all_pass and ok

    print()
    if all_pass:
        print("🎉 所有测试通过！系统已就绪。")
        print()
        print("启动方式:")
        print("  python main.py           # 主进程（带UI + 守护子进程）")
        print("  python main.py --watchdog   # 仅守护进程模式")
        print("  python uninstall.py      # 完整卸载清理")
        print()
        print("下一步:")
        print("  1. 安装依赖: pip install -r requirements.txt")
        print("  2. 修改配置: config/config.yaml (密码、U盘白名单等)")
        print("  3. 管理员运行: python main.py")
    else:
        print("⚠ 部分测试失败，请根据以上错误排查。")
        print("  最常见原因是未安装依赖，请执行: pip install -r requirements.txt")


if __name__ == "__main__":
    main()
