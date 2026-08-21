"""
AOTE 管控系统 - 卸载脚本（纯文件清理，无任何进程/系统操作）
新架构完全基于浏览器层面，不再写入注册表/服务/计划任务，
因此卸载仅需清理：日志目录、浏览器沙盒用户数据目录、临时文件。

无需管理员权限。
"""
import os
import sys
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 兼容 GBK 控制台
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def cleanup_logs():
    """清理日志目录"""
    print("\n[1/3] 清理日志目录...")
    log_paths = [
        r"C:\ProgramData\ClassroomGuard\logs",
        os.path.join(BASE_DIR, "logs"),
        os.path.join(BASE_DIR, "boot_trace.log"),
        os.path.join(BASE_DIR, "crash.log"),
    ]
    cleaned = 0
    for p in log_paths:
        if os.path.isfile(p):
            try:
                os.remove(p)
                cleaned += 1
                print(f"  ✔ 删除文件: {p}")
            except Exception as e:
                print(f"  ✗ 删除失败 {p}: {e}")
        elif os.path.isdir(p):
            try:
                shutil.rmtree(p, ignore_errors=True)
                cleaned += 1
                print(f"  ✔ 清理目录: {p}")
            except Exception as e:
                print(f"  ✗ 清理失败 {p}: {e}")
    if cleaned == 0:
        print("  - 未发现日志文件")


def cleanup_browser_profile():
    """清理浏览器沙盒用户数据目录（Playwright 独立 Chromium 数据）"""
    print("\n[2/3] 清理浏览器沙盒用户数据...")
    candidates = [
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "AOTE", "chromium_profile"),
        os.path.join(BASE_DIR, ".playwright_profile"),
    ]
    cleaned = 0
    for p in candidates:
        if p and os.path.isdir(p):
            try:
                shutil.rmtree(p, ignore_errors=True)
                cleaned += 1
                print(f"  ✔ 清理浏览器数据: {p}")
            except Exception as e:
                print(f"  ✗ 清理失败 {p}: {e}")
    if cleaned == 0:
        print("  - 未发现浏览器沙盒用户数据")


def cleanup_pycache():
    """清理 __pycache__ 编译缓存"""
    print("\n[3/3] 清理 __pycache__ 目录...")
    cleaned = 0
    for root, dirs, files in os.walk(BASE_DIR):
        if "__pycache__" in dirs:
            target = os.path.join(root, "__pycache__")
            try:
                shutil.rmtree(target, ignore_errors=True)
                cleaned += 1
                print(f"  ✔ 清理: {target}")
            except Exception as e:
                print(f"  ✗ 清理失败 {target}: {e}")
    if cleaned == 0:
        print("  - 未发现 __pycache__")


def main():
    print("=" * 60)
    print("🧹 AOTE 管控系统 - 卸载脚本（纯文件清理）")
    print("=" * 60)
    print()
    print("说明：新版本为纯浏览器内容管控架构，")
    print("      不写入注册表/服务/计划任务，卸载仅清理数据文件。")
    print()

    try:
        answer = input("⚠  确认清理所有 AOTE 数据文件？ [y/N]: ").strip().lower()
    except EOFError:
        answer = "n"
    if answer != "y":
        print("已取消。")
        sys.exit(0)

    cleanup_logs()
    cleanup_browser_profile()
    cleanup_pycache()

    print()
    print("=" * 60)
    print("✅ 卸载流程执行完成")
    print("   如需彻底移除，请手动删除程序所在目录。")
    print("=" * 60)
    try:
        input("按回车键退出...")
    except EOFError:
        pass


if __name__ == "__main__":
    main()
