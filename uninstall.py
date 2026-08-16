"""
AOTE 管控系统 - 完整卸载脚本
清理：注册表、服务、计划任务、WMI订阅、自启动项
必须以管理员权限运行
"""
import os
import sys
import subprocess


def is_admin() -> bool:
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run(cmd: list, ignore_error: bool = True):
    print(f"  > {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0 and not ignore_error:
            print(f"    警告: 返回码 {r.returncode}")
            if r.stderr:
                print(f"    {r.stderr.strip()}")
        return r
    except Exception as e:
        if not ignore_error:
            print(f"    执行失败: {e}")
        return None


def cleanup_registry():
    """清理注册表自启动项"""
    print("\n[1/6] 清理注册表自启动项...")
    if sys.platform != "win32":
        print("  (非Windows，跳过)")
        return
    try:
        import winreg
        paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "AOTE_Guardian"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "AOTE_Respawn"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "AOTE_Guardian"),
        ]
        for hive, subkey, name in paths:
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE)
                winreg.DeleteValue(key, name)
                winreg.CloseKey(key)
                print(f"  ✔ 删除 {subkey}\\{name}")
            except FileNotFoundError:
                print(f"  - {subkey}\\{name} 不存在，跳过")
            except PermissionError as e:
                print(f"  ✗ 权限不足: {e}")
            except OSError as e:
                print(f"  ✗ 错误: {e}")
    except Exception as e:
        print(f"  注册表清理异常: {e}")


def cleanup_scheduled_task():
    """清理计划任务"""
    print("\n[2/6] 清理计划任务...")
    if sys.platform != "win32":
        print("  (非Windows，跳过)")
        return
    tasks = ["AOTE Guardian", "AOTE Guardian Respawn", "AOTE_Guardian"]
    for name in tasks:
        r = run(["schtasks", "/Delete", "/TN", name, "/F"])
        if r and r.returncode == 0:
            print(f"  ✔ 删除计划任务: {name}")
        else:
            print(f"  - 计划任务不存在: {name}")


def cleanup_wmi_subscriptions():
    """清理WMI永久事件订阅"""
    print("\n[3/6] 清理WMI永久事件订阅...")
    if sys.platform != "win32":
        print("  (非Windows，跳过)")
        return
    # 尝试使用PowerShell移除与AOTE相关的WMI订阅
    ps_commands = [
        "Get-WmiObject -Namespace root/subscription -Class __EventFilter | Where-Object { $_.Name -like '*AOTE*' } | Remove-WmiObject",
        "Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -like '*AOTE*' } | Remove-WmiObject",
        "Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding | Remove-WmiObject -ErrorAction SilentlyContinue",
    ]
    for cmd in ps_commands:
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=30
            )
        except Exception as e:
            print(f"  执行失败: {e}")
    print("  ✔ 已尝试清理WMI订阅")


def cleanup_services():
    """清理Windows服务"""
    print("\n[4/6] 清理Windows服务...")
    if sys.platform != "win32":
        print("  (非Windows，跳过)")
        return
    services = ["AOTEGuardian", "AOTE Guardian", "AOTEService"]
    for svc in services:
        # 先停止
        run(["sc", "stop", svc], ignore_error=True)
        # 删除
        r = run(["sc", "delete", svc])
        if r and r.returncode == 0:
            print(f"  ✔ 删除服务: {svc}")
        else:
            print(f"  - 服务不存在: {svc}")


def kill_running_processes():
    """终止所有运行中的AOTE进程"""
    print("\n[5/6] 终止运行中的进程...")
    try:
        import psutil
        killed = 0
        script_basename = os.path.basename(sys.argv[0]).lower()
        my_pid = os.getpid()
        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                if p.pid == my_pid:
                    continue
                name = (p.info.get("name") or "").lower()
                cmdline = " ".join(p.info.get("cmdline") or []).lower()
                if (
                    "aote" in name or
                    "guardian" in name or
                    script_basename.replace(".py", "") in cmdline or
                    "main.py" in cmdline and "aote" in cmdline
                ):
                    p.terminate()
                    killed += 1
                    print(f"  ✔ 终止进程 PID={p.pid} {p.info.get('name')}")
            except Exception:
                continue
        if killed == 0:
            print("  - 未发现运行中的AOTE进程")
    except ImportError:
        print("  psutil未安装，尝试用taskkill")
        script_name = os.path.basename(sys.argv[0])
        if script_name.endswith(".py"):
            # 查找 python.exe 中带脚本名的
            run(["taskkill", "/F", "/IM", "python.exe", "/FI", f"WINDOWTITLE eq *{script_name}*"], ignore_error=True)
        else:
            run(["taskkill", "/F", "/IM", script_name], ignore_error=True)


def cleanup_logs():
    """可选清理日志"""
    print("\n[6/6] 可选：清理日志与配置...")
    log_paths = [
        r"C:\ProgramData\ClassroomGuard\logs",
        os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "logs"),
    ]
    import shutil
    cleaned = 0
    for p in log_paths:
        if os.path.isdir(p):
            try:
                shutil.rmtree(p, ignore_errors=True)
                cleaned += 1
                print(f"  ✔ 清理目录: {p}")
            except Exception as e:
                print(f"  ✗ 清理失败 {p}: {e}")
    if cleaned == 0:
        print("  - 未发现日志目录（或手动保留）")


def main():
    print("=" * 60)
    print("🧹 AOTE 管控系统 - 完整卸载脚本")
    print("=" * 60)
    print()

    if not is_admin():
        print("[错误] 请以管理员权限运行此卸载脚本！")
        print("  右键 -> 以管理员身份运行")
        if sys.platform == "win32":
            try:
                input("按回车键尝试UAC提升...")
                import ctypes
                params = " ".join([f'"{a}"' for a in sys.argv])
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, params, None, 1
                )
            except Exception:
                pass
        sys.exit(1)

    try:
        answer = input("⚠  确认执行完整卸载？将清理所有注册表/服务/计划任务。 [y/N]: ").strip().lower()
    except EOFError:
        answer = "n"
    if answer != "y":
        print("已取消。")
        sys.exit(0)

    kill_running_processes()
    cleanup_registry()
    cleanup_scheduled_task()
    cleanup_wmi_subscriptions()
    cleanup_services()
    cleanup_logs()

    print()
    print("=" * 60)
    print("✅ 卸载流程执行完成")
    print("   如需清理残留文件，请手动删除程序所在目录。")
    print("=" * 60)
    try:
        input("按回车键退出...")
    except EOFError:
        pass


if __name__ == "__main__":
    main()
