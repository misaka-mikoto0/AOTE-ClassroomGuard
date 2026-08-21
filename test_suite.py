"""
AOTE 管控系统 - 快速测试脚本
重点验证：
1. 配置加载（含弱网管控参数）
2. 日志模块
3. 弱网管控逻辑（域名匹配 / 弱网状态 / 参数调整）
4. 时间调度逻辑
"""
import os
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# 兼容 GBK 控制台：确保 ✔ ✗ 🎉 等 Unicode 字符可输出（Windows 默认 cp936）
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def test_config():
    print("=" * 60)
    print("[1/4] 测试配置加载模块...")
    try:
        from aote.config import ConfigManager
        cfg = ConfigManager()
        blocks = cfg.browser_block_domains
        print(f"  ✔ 拦截域名数量: {len(blocks)}")
        assert len(blocks) > 0, "拦截域名列表为空"
        allowed = cfg.browser_allowed_domains
        print(f"  ✔ 白名单域名数量: {len(allowed)}")
        # 弱网管控配置
        wn = cfg.weak_network
        print(f"  ✔ 弱网管控配置: enabled={wn['enabled']} "
              f"delay={wn['delay_ms']}ms latency={wn['latency_ms']}ms "
              f"download={wn['download_kbps']}KB/s upload={wn['upload_kbps']}KB/s")
        assert "delay_ms" in wn and "download_kbps" in wn, "弱网配置缺少关键字段"
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
        log.log_usb_event("insert", "E:\\", "ABC123", True)
        log.log_browser_intercept("https://www.bilibili.com/video/1", "blocked_domain", "strict")
        print("  ✔ 日志模块通过（检查logs/目录）")
        return True
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  ✗ 日志模块失败: {e}")
        return False


def test_weak_network_logic():
    """
    弱网管控核心逻辑测试（不启动浏览器）：
    - 弱网状态接口返回完整字段
    - 参数可动态调整
    - 黑名单域名匹配正确
    """
    print("\n" + "=" * 60)
    print("[3/4] 测试弱网管控逻辑（核心需求！）")
    print("  要求：")
    print("    ① 命中黑名单域名即时切换弱网（状态可见）")
    print("    ② 弱网参数可动态调整")
    print("    ③ 域名匹配支持 example.com 与 *.example.com")
    try:
        from aote.config import ConfigManager
        from aote.logger import AOTELogger
        from aote.browser_sandbox import BrowserSandbox

        cfg = ConfigManager()
        log = AOTELogger(log_path=os.path.join(BASE_DIR, "logs"))
        sandbox = BrowserSandbox(cfg, log)

        # ① 弱网状态接口
        status = sandbox.weak_network_status()
        for key in ("enabled", "active", "delay_ms", "latency_ms",
                    "download_kbps", "upload_kbps", "since", "host"):
            assert key in status, f"弱网状态缺少字段: {key}"
        print(f"  ✔ 弱网状态接口完整: {status}")
        assert "delay_ms" in status and status["delay_ms"] >= 0

        # ② 弱网配置已同步到沙盒（enabled / 各参数与 config 一致）
        wn_cfg = cfg.weak_network
        assert sandbox._weak_network_enabled == wn_cfg["enabled"], "弱网开关未同步到沙盒"
        assert sandbox._weak_network_delay_ms == wn_cfg["delay_ms"], "弱网延迟参数未同步"
        assert sandbox._weak_network_latency_ms == wn_cfg["latency_ms"], "弱网延迟参数未同步"
        assert sandbox._weak_network_download_kbps == wn_cfg["download_kbps"], "下载限速未同步"
        assert sandbox._weak_network_upload_kbps == wn_cfg["upload_kbps"], "上传限速未同步"
        print(f"  ✔ 弱网配置已同步到沙盒（enabled={sandbox._weak_network_enabled}, "
              f"delay={sandbox._weak_network_delay_ms}ms, "
              f"dl={sandbox._weak_network_download_kbps}KB/s, "
              f"ul={sandbox._weak_network_upload_kbps}KB/s）")

        # ③ 动态调整弱网参数
        sandbox.set_weak_network_params(delay_ms=1500, download_kbps=64, upload_kbps=32)
        status2 = sandbox.weak_network_status()
        assert status2["delay_ms"] == 1500, "delay_ms 更新失败"
        assert status2["download_kbps"] == 64, "download_kbps 更新失败"
        assert status2["upload_kbps"] == 32, "upload_kbps 更新失败"
        print(f"  ✔ 弱网参数动态调整生效: delay={status2['delay_ms']}ms "
              f"dl={status2['download_kbps']}KB/s ul={status2['upload_kbps']}KB/s")

        # ④ 域名匹配（黑名单命中判定）
        # 语义：'example.com' 与 '*.example.com' 均覆盖 裸域+所有子域（宽松匹配，对拦截更安全）
        matches = [
            ("https://www.bilibili.com/video/av1", ["bilibili.com", "youtube.com"], True),
            ("https://bilibili.com", ["bilibili.com"], True),
            ("https://sub.video.youtube.com/watch", ["*.youtube.com"], True),
            ("https://youtube.com", ["*.youtube.com"], True),      # 通配符同样覆盖裸域
            ("https://www.baidu.com", ["bilibili.com", "youtube.com"], False),
            ("https://edu.cn/lesson", ["edu.cn"], True),
            ("http://evil.evil.com/x", ["*.youtube.com"], False),  # 完全无关域名不误伤
        ]
        for url, patterns, expect in matches:
            from urllib.parse import urlparse
            host = (urlparse(url).hostname or "").lower()
            got = sandbox._domain_match(host, patterns)
            assert got == expect, f"匹配错误: {url} vs {patterns} -> {got} (期望 {expect})"
        print("  ✔ 域名匹配正确（含通配符 *.example.com）")

        # 说明：弱网触发（active=True）依赖真实浏览器请求，由 _route_handler
        # 持续监控并在命中黑名单时自动切换，此处通过状态接口与参数接口验证逻辑正确。
        print("  ✔ 弱网管控逻辑通过")
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
        print(f"  ✗ 弱网管控逻辑失败: {e}")
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
    results.append(("弱网管控逻辑", test_weak_network_logic()))
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
        print("启动方式（单进程，纯浏览器内容管控）:")
        print("  python main.py           # 启动主进程 + 浏览器沙盒")
        print("  python uninstall.py      # 清理数据文件")
        print()
        print("下一步:")
        print("  1. 安装依赖: pip install -r requirements.txt  (默认复用本机 Edge/Chrome，无需下载浏览器)")
        print("  2. 修改配置: config/config.yaml (密码、U盘白名单、弱网参数、浏览器规则等)")
        print("  3. (可选)创建调试快捷方式: powershell -ExecutionPolicy Bypass -File scripts\\create_cdp_shortcut.ps1")
        print("  4. 启动: python main.py")
    else:
        print("⚠ 部分测试失败，请根据以上错误排查。")
        print("  最常见原因是未安装依赖，请执行: pip install -r requirements.txt")


if __name__ == "__main__":
    main()
