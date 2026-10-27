#!/usr/bin/env python3
"""check_windows.py — 老百姓电脑体检 · 只读检测脚本

设计约束（不要违反）：
1. 只读。不修改任何设置、不删除任何文件、不启动任何服务。
2. 不联网。所有检测在本机完成。
3. 只用 Python 标准库。使用者不会为了跑一个体检去装 pip 包。
4. 单项失败不影响整体。每项独立 try，失败标 unknown，不抛异常给用户。
5. 输出是给 agent 读的 JSON，不是给人看的。翻译成人话是 SKILL.md 的活。

用法：
    python check_windows.py              # 输出 JSON 到 stdout
    python check_windows.py --pretty     # 缩进 JSON
    python check_windows.py --human      # 直接输出粗略的人话版（调试用）
    python check_windows.py --out x.json # 写到文件
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

GREEN, YELLOW, RED, UNKNOWN = "green", "yellow", "red", "unknown"

LEVEL_ORDER = {RED: 0, YELLOW: 1, UNKNOWN: 2, GREEN: 3}


# ---------------------------------------------------------------- 基础工具


def decode_bytes(raw: bytes) -> str:
    """Windows 命令行输出可能是 UTF-8、GBK 或 OEM 代码页，逐个试。"""
    for enc in ("utf-8", "gbk", "mbcs"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def run_cmd(args: list[str], timeout: int = 20) -> tuple[bool, str]:
    """跑一条只读命令。返回 (是否成功, 输出文本)。"""
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        text = decode_bytes(proc.stdout) + decode_bytes(proc.stderr)
        return proc.returncode == 0, text.strip()
    except Exception as exc:  # 超时、找不到命令、权限不足
        return False, f"{type(exc).__name__}: {exc}"


def run_ps(script: str, timeout: int = 25) -> tuple[bool, str]:
    """跑一段只读 PowerShell。"""
    return run_cmd(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout=timeout,
    )


def reg_read(root, path: str, name: str | None = None):
    """读注册表。失败返回 None，不抛异常。"""
    try:
        import winreg
    except ImportError:
        return None

    flags = [
        winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
        winreg.KEY_READ | getattr(winreg, "KEY_WOW64_32KEY", 0),
        winreg.KEY_READ,
    ]
    for flag in flags:
        try:
            with winreg.OpenKey(root, path, 0, flag) as key:
                if name is None:
                    return True
                value, _ = winreg.QueryValueEx(key, name)
                return value
        except OSError:
            continue
    return None


def reg_enum_values(root, path: str) -> dict[str, str]:
    """列出一个注册表键下所有值。失败返回空 dict。"""
    try:
        import winreg
    except ImportError:
        return {}

    for flag in (
        winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
        winreg.KEY_READ | getattr(winreg, "KEY_WOW64_32KEY", 0),
    ):
        try:
            out: dict[str, str] = {}
            with winreg.OpenKey(root, path, 0, flag) as key:
                index = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    out[str(value_name)] = str(value_data)
                    index += 1
            return out
        except OSError:
            continue
    return {}


def reg_subkeys(root, path: str) -> list[str]:
    try:
        import winreg
    except ImportError:
        return []

    for flag in (
        winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
        winreg.KEY_READ | getattr(winreg, "KEY_WOW64_32KEY", 0),
    ):
        try:
            out = []
            with winreg.OpenKey(root, path, 0, flag) as key:
                index = 0
                while True:
                    try:
                        out.append(winreg.EnumKey(key, index))
                    except OSError:
                        break
                    index += 1
            return out
        except OSError:
            continue
    return []


def make_item(
    item_id: str,
    group: str,
    title: str,
    level: str,
    found: str,
    why: str,
    fix: str,
    tech: dict | None = None,
) -> dict:
    return {
        "id": item_id,
        "group": group,
        "title": title,
        "level": level,
        "found": found,
        "why": why,
        "fix": fix,
        "tech": tech or {},
    }


# ---------------------------------------------------------------- 检测项


def check_firewall() -> dict:
    """防火墙。三个配置文件任一关闭都算风险。"""
    try:
        import winreg

        base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        profiles = {
            "域网络": f"{base}\\DomainProfile",
            "专用网络": f"{base}\\StandardProfile",
            "公用网络": f"{base}\\PublicProfile",
        }
        state: dict[str, int | None] = {}
        for label, path in profiles.items():
            value = reg_read(winreg.HKEY_LOCAL_MACHINE, path, "EnableFirewall")
            state[label] = int(value) if isinstance(value, int) else None

        known = {k: v for k, v in state.items() if v is not None}
        if not known:
            return make_item(
                "firewall", "上网安全", "防火墙", UNKNOWN,
                "这次没能读到防火墙状态（可能需要管理员权限）。",
                "读不到不代表有问题，只是这次查不了。",
                "想确认的话，打开「Windows 安全中心」→「防火墙和网络保护」，看一眼是不是都开着。",
                {"raw": state},
            )

        off = [k for k, v in known.items() if v == 0]
        if off:
            return make_item(
                "firewall", "上网安全", "防火墙", RED,
                f"你的「{ '、'.join(off) }」防火墙是关着的。",
                "防火墙是电脑的门。门开着，别人从网络进来就不用撬锁了。",
                "打开「Windows 安全中心」→「防火墙和网络保护」，把上面每一项都点成「开启」。",
                {"off": off, "state": state},
            )
        return make_item(
            "firewall", "上网安全", "防火墙", GREEN,
            "防火墙三个配置都是开着的。",
            "这条没问题。",
            "不用动。",
            {"state": state},
        )
    except Exception as exc:
        return make_item(
            "firewall", "上网安全", "防火墙", UNKNOWN,
            "检查防火墙时出错了。",
            "可能是系统版本差异或权限不足。",
            "可以手动看一眼「Windows 安全中心」→「防火墙和网络保护」。",
            {"error": f"{type(exc).__name__}: {exc}"},
        )


def check_antivirus() -> dict:
    """杀毒软件实时保护。优先读安全中心聚合状态。"""
    try:
        ok, out = run_ps(
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
            "| Select-Object -ExpandProperty displayName"
        )
        names = [line.strip() for line in out.splitlines() if line.strip()] if ok else []

        if not names:
            # 退回读 Defender 注册表
            try:
                import winreg

                disabled = reg_read(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
                    "DisableRealtimeMonitoring",
                )
                if disabled == 1:
                    return make_item(
                        "antivirus", "上网安全", "病毒防护", RED,
                        "你的实时病毒防护是关着的，而且没有装别的杀毒软件。",
                        "实时防护是电脑的哨兵。哨兵睡了，进来的东西没人查。",
                        "打开「Windows 安全中心」→「病毒和威胁防护」→「管理设置」，把「实时保护」打开。",
                        {"defender_disabled": True},
                    )
            except Exception:
                pass

            return make_item(
                "antivirus", "上网安全", "病毒防护", UNKNOWN,
                "这次没能确认杀毒软件的运行状态。",
                "读不到不代表没装，只是这次查不了。",
                "打开「Windows 安全中心」，首页会直接写「病毒和威胁防护」是不是正常。",
                {"names": [], "ps_ok": ok},
            )

        return make_item(
            "antivirus", "上网安全", "病毒防护", GREEN,
            f"检测到正在运行的杀毒软件：{ '、'.join(names[:3]) }。",
            "这条没问题。",
            "不用动。",
            {"names": names},
        )
    except Exception as exc:
        return make_item(
            "antivirus", "上网安全", "病毒防护", UNKNOWN,
            "检查杀毒软件时出错了。",
            "可能是权限不足。",
            "手动打开「Windows 安全中心」看一眼即可。",
            {"error": f"{type(exc).__name__}: {exc}"},
        )


def check_windows_version() -> dict:
    """系统是否还在官方支持期。"""
    try:
        ver = platform.version()
        release = platform.release()
        build = 0
        parts = ver.split(".")
        if len(parts) >= 3:
            build = int(parts[2])

        if build >= 22000:
            return make_item(
                "windows_version", "系统健康", "系统版本", GREEN,
                f"你用的是 Windows 11（{release}，内部版本 {build}）。",
                "还在官方支持期内。",
                "不用动。",
                {"release": release, "build": build},
            )
        if build >= 10240:
            return make_item(
                "windows_version", "系统健康", "系统版本", GREEN,
                f"你用的是 Windows 10（{release}，内部版本 {build}）。",
                "还在官方支持期内，但 Windows 10 的支持窗口在收窄，建议找机会升到 11。",
                "不用急着动。等有空的周末再说。",
                {"release": release, "build": build},
            )
        return make_item(
            "windows_version", "系统健康", "系统版本", RED,
            f"你用的系统版本偏老（{release}，内部版本 {build}），已经不在官方安全更新范围内。",
            "老系统不再收到安全补丁。已经公开的漏洞没人帮你补，谁都知道怎么打。",
            "这是这次体检里最该处理的一项。备份好文件，找时间升级系统。",
            {"release": release, "build": build},
        )
    except Exception as exc:
        return make_item(
            "windows_version", "系统健康", "系统版本", UNKNOWN,
            "没能读出系统版本。",
            "可能是环境限制。",
            "按 Win+R 输入 winver 就能看到。",
            {"error": f"{type(exc).__name__}: {exc}"},
        )


def check_rdp() -> dict:
    """远程桌面。家用电脑通常不该开。"""
    try:
        import winreg

        deny = reg_read(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections",
        )
        if deny is None:
            return make_item(
                "rdp", "上网安全", "远程桌面", UNKNOWN,
                "没读到远程桌面的开关状态。",
                "读不到就不好判断。",
                "打开「设置」→「系统」→「远程桌面」，看一眼开关是不是「关」。",
                {},
            )
        if int(deny) == 0:
            return make_item(
                "rdp", "上网安全", "远程桌面", YELLOW,
                "你的「远程桌面」是开着的。",
                "开了远程桌面，就等于给这台电脑开了一扇可以从别的电脑连进来的门。自己家用不上它的话，等于白留一个入口。",
                "如果你不用别的设备连这台电脑：打开「设置」→「系统」→「远程桌面」，把它关掉。",
                {"fDenyTSConnections": int(deny)},
            )
        return make_item(
            "rdp", "上网安全", "远程桌面", GREEN,
            "远程桌面是关着的。",
            "这条没问题。",
            "不用动。",
            {"fDenyTSConnections": int(deny)},
        )
    except Exception as exc:
        return make_item(
            "rdp", "上网安全", "远程桌面", UNKNOWN,
            "检查远程桌面时出错了。",
            "可能是权限不足。",
            "手动去「设置」→「系统」→「远程桌面」看一眼。",
            {"error": f"{type(exc).__name__}: {exc}"},
        )


def check_smb1() -> dict:
    """老式文件共享协议 SMBv1。勒索病毒最爱走的门。"""
    try:
        import winreg

        value = reg_read(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1",
        )
        if value is None:
            return make_item(
                "smb1", "上网安全", "老式文件共享", GREEN,
                "没有开启老式文件共享协议（SMBv1）。",
                "这条没问题。新系统默认就是关的。",
                "不用动。",
                {"SMB1": None},
            )
        if int(value) == 1:
            return make_item(
                "smb1", "上网安全", "老式文件共享", RED,
                "你开着「SMBv1」这个很老的文件共享协议。",
                "这是 2017 年那波勒索病毒（WannaCry）主要走的门。现在的电脑基本不需要它，留着只是给人留路。",
                "打开「控制面板」→「程序」→「启用或关闭 Windows 功能」，找到「SMB 1.0/CIFS 文件共享支持」，取消勾选，重启。",
                {"SMB1": int(value)},
            )
        return make_item(
            "smb1", "上网安全", "老式文件共享", GREEN,
            "老式文件共享协议是关着的。",
            "这条没问题。",
            "不用动。",
            {"SMB1": int(value)},
        )
    except Exception as exc:
        return make_item(
            "smb1", "上网安全", "老式文件共享", UNKNOWN,
            "没能读到这项设置。",
            "读不到不代表有问题。",
            "可以在「启用或关闭 Windows 功能」里自己看一眼。",
            {"error": f"{type(exc).__name__}: {exc}"},
        )


def check_guest_account() -> dict:
    """来宾账户。开着等于给陌生人留了个不需要密码的座位。"""
    try:
        ok, out = run_cmd(["net", "user", "guest"])
        if not ok:
            return make_item(
                "guest_account", "账号安全", "来宾账户", UNKNOWN,
                "没读到来宾账户的状态。",
                "读不到不代表有问题。",
                "打开「计算机管理」→「本地用户和组」→「用户」，看 Guest 图标上有没有红色小箭头。",
                {},
            )
        lowered = out.lower()
        if "account active" in lowered:
            active_line = ""
            for line in out.splitlines():
                if "account active" in line.lower():
                    active_line = line.strip()
                    break
            is_active = active_line.lower().rstrip().endswith("yes")
            if is_active:
                return make_item(
                    "guest_account", "账号安全", "来宾账户", YELLOW,
                    "你的「来宾账户（Guest）」是开着的。",
                    "来宾账户不需要密码就能用。虽然默认权限低，但它是一个多余的入口。",
                    "打开「计算机管理」→「本地用户和组」→「用户」，右键 Guest →「属性」→ 勾上「账户已禁用」。",
                    {"line": active_line},
                )
        return make_item(
            "guest_account", "账号安全", "来宾账户", GREEN,
            "来宾账户是关着的。",
            "这条没问题。",
            "不用动。",
            {},
        )
    except Exception as exc:
        return make_item(
            "guest_account", "账号安全", "来宾账户", UNKNOWN,
            "检查来宾账户时出错了。",
            "可能是权限不足。",
            "手动去「计算机管理」看一眼。",
            {"error": f"{type(exc).__name__}: {exc}"},
        )


def check_admins() -> dict:
    """管理员账户数量。一个人用的电脑不需要好几个。"""
    try:
        ok, out = run_cmd(["net", "localgroup", "administrators"])
        if not ok:
            return make_item(
                "admins", "账号安全", "管理员账户", UNKNOWN,
                "没读到管理员账户列表。",
                "读不到不代表有问题。",
                "打开「计算机管理」→「本地用户和组」→「组」→「Administrators」，看成员有几个。",
                {},
            )

        members: list[str] = []
        capture = False
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("---"):
                capture = True
                continue
            if capture:
                if stripped.startswith("The command completed") or stripped.startswith("命令成功完成"):
                    break
                if stripped:
                    members.append(stripped)

        real = [m for m in members if "Administrator" not in m or m.lower() != "administrator"]
        if len(members) > 3:
            return make_item(
                "admins", "账号安全", "管理员账户", YELLOW,
                f"这台电脑有 {len(members)} 个管理员账户。",
                "管理员账户越多，被人猜到密码的机会越多。家用电脑一两个就够。",
                "打开「计算机管理」→「本地用户和组」，看看多出来的那些是不是你自己建的。不是就删掉。",
                {"members": members},
            )
        return make_item(
            "admins", "账号安全", "管理员账户", GREEN,
            f"管理员账户数量正常（{len(members)} 个）。",
            "这条没问题。",
            "不用动。",
            {"members": members},
        )
    except Exception as exc:
        return make_item(
            "admins", "账号安全", "管理员账户", UNKNOWN,
            "检查管理员账户时出错了。",
            "可能是权限不足。",
            "手动去「计算机管理」看一眼。",
            {"error": f"{type(exc).__name__}: {exc}"},
        )


def check_startup() -> dict:
    """开机自启动项。不是安全问题，是「为什么电脑越来越慢」的答案。"""
    try:
        import winreg

        # 启动文件夹里混着 desktop.ini 这类文件夹配置文件，不是程序，不能算自启项
        skip_names = {"desktop.ini", "thumbs.db", ".ds_store", "ini"}
        skip_ext = {".ini", ".txt", ".url", ".lnk.bak"}

        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "当前用户"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "所有用户"),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                "所有用户(32位)",
            ),
        ]
        items: list[dict] = []
        for root, path, scope in run_keys:
            for name, value in reg_enum_values(root, path).items():
                if name.lower() in skip_names:
                    continue
                items.append({"name": name, "path": value, "scope": scope})

        startup_dir = os.path.join(
            os.environ.get("APPDATA", ""),
            r"Microsoft\Windows\Start Menu\Programs\Startup",
        )
        if os.path.isdir(startup_dir):
            for entry in os.listdir(startup_dir):
                low = entry.lower()
                if low in skip_names or os.path.splitext(low)[1] in skip_ext:
                    continue
                if low.endswith(".ini"):
                    continue
                items.append({"name": entry, "path": startup_dir, "scope": "启动文件夹"})

        if len(items) >= 12:
            return make_item(
                "startup", "系统健康", "开机自启", YELLOW,
                f"你有 {len(items)} 个程序会在开机时自动跑起来。",
                "这是电脑越用越慢最常见的原因。每个自启程序都要抢开机那几秒。",
                "打开「任务管理器」（Ctrl+Shift+Esc）→「启动应用」，把不认识的、不需要开机就跑的右键「禁用」。禁用不是删除，随时能改回来。",
                {"count": len(items), "items": items[:40]},
            )
        return make_item(
            "startup", "系统健康", "开机自启", GREEN,
            f"开机自启的程序有 {len(items)} 个，数量正常。",
            "这条没问题。",
            "不用动。",
            {"count": len(items), "items": items[:40]},
        )
    except Exception as exc:
        return make_item(
            "startup", "系统健康", "开机自启", UNKNOWN,
            "没能列出开机自启的程序。",
            "读不到不代表有问题。",
            "打开「任务管理器」→「启动应用」自己看。",
            {"error": f"{type(exc).__name__}: {exc}"},
        )


BROWSER_PROFILES = [
    ("Chrome", os.path.join("Google", "Chrome", "User Data")),
    ("Edge", os.path.join("Microsoft", "Edge", "User Data")),
    ("Brave", os.path.join("BraveSoftware", "Brave-Browser", "User Data")),
]

HIGH_RISK_PERMISSIONS = {"<all_urls>", "*://*/*", "tabs", "webRequest", "cookies", "history"}


def check_browser_extensions() -> dict:
    """浏览器扩展。这是普通人电脑上最容易被忽视的口子。"""
    try:
        local = os.environ.get("LOCALAPPDATA", "")
        results: list[dict] = []

        for browser, rel in BROWSER_PROFILES:
            base = os.path.join(local, rel)
            if not os.path.isdir(base):
                continue
            for profile in os.listdir(base):
                ext_dir = os.path.join(base, profile, "Extensions")
                if not os.path.isdir(ext_dir):
                    continue
                for ext_id in os.listdir(ext_dir):
                    version_dir = os.path.join(ext_dir, ext_id)
                    if not os.path.isdir(version_dir):
                        continue
                    versions = sorted(os.listdir(version_dir))
                    if not versions:
                        continue
                    manifest = os.path.join(version_dir, versions[-1], "manifest.json")
                    if not os.path.isfile(manifest):
                        continue
                    try:
                        with open(manifest, "r", encoding="utf-8", errors="replace") as handle:
                            data = json.load(handle)
                    except Exception:
                        continue

                    name = data.get("name", ext_id)
                    perms = list(data.get("permissions", []) or [])
                    host_perms = list(data.get("host_permissions", []) or [])
                    all_perms = set(perms) | set(host_perms)
                    risky = sorted(all_perms & HIGH_RISK_PERMISSIONS)
                    results.append(
                        {
                            "browser": browser,
                            "profile": profile,
                            "id": ext_id,
                            "name": name,
                            "risky": risky,
                            "all_urls": any(
                                p in all_perms for p in ("<all_urls>", "*://*/*")
                            ),
                        }
                    )

        if not results:
            return make_item(
                "browser_ext", "上网安全", "浏览器扩展", GREEN,
                "没有检测到已安装的浏览器扩展（或者你没用 Chrome / Edge / Brave）。",
                "没有扩展就没有扩展带来的风险。",
                "不用动。",
                {"extensions": []},
            )

        full_access = [e for e in results if e["all_urls"]]
        if full_access:
            names = "、".join(f"{e['name']}({e['browser']})" for e in full_access[:5])
            more = f" 等 {len(full_access)} 个" if len(full_access) > 5 else ""
            return make_item(
                "browser_ext", "上网安全", "浏览器扩展", YELLOW,
                f"有 {len(full_access)} 个扩展能读取你在所有网站上的内容：{names}{more}。",
                "这类扩展能看到你打开的每一个网页，包括银行、邮箱、公司系统。绝大多数是正常的，但一旦某个扩展被卖掉或者自己出问题，你的登录状态就可能被别人拿到。",
                "打开浏览器 →「扩展程序」页面（地址栏输入 chrome://extensions 或 edge://extensions），逐个看。不认识的、很久没用的，直接删掉。常用的留着没关系。",
                {"total": len(results), "full_access": full_access, "extensions": results[:60]},
            )

        return make_item(
            "browser_ext", "上网安全", "浏览器扩展", GREEN,
            f"装了 {len(results)} 个浏览器扩展，没有能读取所有网站的。",
            "这条没问题。",
            "不用动。",
            {"total": len(results), "extensions": results[:60]},
        )
    except Exception as exc:
        return make_item(
            "browser_ext", "上网安全", "浏览器扩展", UNKNOWN,
            "检查浏览器扩展时出错了。",
            "读不到不代表有问题。",
            "打开浏览器自己看扩展列表即可。",
            {"error": f"{type(exc).__name__}: {exc}"},
        )


def check_bitlocker() -> dict:
    """磁盘加密。笔记本丢了才想起来的那个。"""
    try:
        ok, out = run_cmd(["manage-bde", "-status"], timeout=25)
        if not ok or not out:
            return make_item(
                "bitlocker", "账号安全", "磁盘加密", UNKNOWN,
                "这次没能读到磁盘加密状态（这条通常需要管理员权限）。",
                "读不到不代表没开。",
                "打开「控制面板」→「系统和安全」→「BitLocker 驱动器加密」看一眼。",
                {},
            )

        lowered = out.lower()
        protected = "protection on" in lowered or "保护已启用" in out
        if protected:
            return make_item(
                "bitlocker", "账号安全", "磁盘加密", GREEN,
                "系统盘是加密的。",
                "这条没问题。笔记本丢了别人也读不出里面的东西。",
                "不用动。",
                {"snippet": out[:600]},
            )
        return make_item(
            "bitlocker", "账号安全", "磁盘加密", YELLOW,
            "系统盘没有加密。",
            "加密是防「电脑丢了」的。别人把硬盘拆下来接到别的机器上，没加密就能直接读你的文件。台式机放在家里影响小，笔记本经常带出门就值得开。",
            "打开「控制面板」→「系统和安全」→「BitLocker 驱动器加密」，对系统盘点「启用 BitLocker」。开之前先把恢复密钥存好（存到微软账户或打印出来），忘了密钥自己都打不开。",
            {"snippet": out[:600]},
        )
    except Exception as exc:
        return make_item(
            "bitlocker", "账号安全", "磁盘加密", UNKNOWN,
            "检查磁盘加密时出错了。",
            "可能是权限不足。",
            "手动去「BitLocker 驱动器加密」看一眼。",
            {"error": f"{type(exc).__name__}: {exc}"},
        )


def check_disk_space() -> dict:
    """磁盘空间。满了会引发一堆莫名其妙的问题。"""
    try:
        drives = []
        if sys.platform == "win32":
            import string

            for letter in string.ascii_uppercase:
                root = f"{letter}:\\"
                if os.path.exists(root):
                    try:
                        usage = shutil.disk_usage(root)
                    except OSError:
                        continue
                    if usage.total == 0:
                        continue
                    drives.append(
                        {
                            "drive": root,
                            "total_gb": round(usage.total / 1024**3, 1),
                            "free_gb": round(usage.free / 1024**3, 1),
                            "free_pct": round(usage.free / usage.total * 100, 1),
                        }
                    )

        if not drives:
            return make_item(
                "disk_space", "系统健康", "磁盘空间", UNKNOWN,
                "没能读到磁盘空间。",
                "读不到不影响判断其它项。",
                "打开「此电脑」自己看一眼。",
                {},
            )

        low = [d for d in drives if d["free_pct"] < 10]
        system_drive = next((d for d in drives if d["drive"].upper().startswith("C")), None)

        if system_drive and system_drive["free_pct"] < 10:
            return make_item(
                "disk_space", "系统健康", "磁盘空间", RED,
                f"系统盘只剩 {system_drive['free_gb']} GB（{system_drive['free_pct']}%）。",
                "系统盘快满的时候，Windows 会没法更新、程序会莫名其妙卡死、有些软件直接打不开。",
                "先清「下载」文件夹和回收站，再打开「设置」→「系统」→「存储」，用「临时文件」清理。至少要留出 15% 以上。",
                {"drives": drives},
            )
        if low:
            names = "、".join(f"{d['drive']}（剩 {d['free_pct']}%）" for d in low)
            return make_item(
                "disk_space", "系统健康", "磁盘空间", YELLOW,
                f"有磁盘快满了：{names}。",
                "盘满了会拖慢整体速度，也会让程序报奇怪的错。",
                "清一下这几个盘的下载目录和回收站。",
                {"drives": drives},
            )
        return make_item(
            "disk_space", "系统健康", "磁盘空间", GREEN,
            "各磁盘空间都还宽裕。",
            "这条没问题。",
            "不用动。",
            {"drives": drives},
        )
    except Exception as exc:
        return make_item(
            "disk_space", "系统健康", "磁盘空间", UNKNOWN,
            "检查磁盘空间时出错了。",
            "不影响其它项。",
            "打开「此电脑」看一眼。",
            {"error": f"{type(exc).__name__}: {exc}"},
        )


CHECKS = [
    check_firewall,
    check_antivirus,
    check_windows_version,
    check_rdp,
    check_smb1,
    check_guest_account,
    check_admins,
    check_startup,
    check_browser_extensions,
    check_bitlocker,
    check_disk_space,
]


# ---------------------------------------------------------------- 汇总


def run_all() -> dict:
    items = []
    for check in CHECKS:
        try:
            items.append(check())
        except Exception as exc:  # 兜底，绝不让单项炸掉整体
            items.append(
                make_item(
                    check.__name__.replace("check_", ""),
                    "其它",
                    check.__name__,
                    UNKNOWN,
                    "这项检查失败了。",
                    "不影响其它项。",
                    "可以忽略这一条。",
                    {"error": f"{type(exc).__name__}: {exc}"},
                )
            )

    items.sort(key=lambda item: LEVEL_ORDER.get(item["level"], 9))
    counts = {level: 0 for level in (RED, YELLOW, GREEN, UNKNOWN)}
    for item in items:
        counts[item["level"]] = counts.get(item["level"], 0) + 1

    return {
        "tool": "laobaixing-computer-check",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "machine": {
            "os": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "arch": platform.machine(),
            "hostname": platform.node(),
        },
        "summary": counts,
        "items": items,
    }


LEVEL_ICON = {RED: "红", YELLOW: "黄", GREEN: "绿", UNKNOWN: "未查"}


def verdict_line(report: dict) -> str:
    counts = report["summary"]
    red = counts.get(RED, 0)
    yellow = counts.get(YELLOW, 0)
    if red:
        return f"有 {red} 件事需要你现在处理，{yellow} 件可以缓一缓。"
    if yellow:
        return f"没有非处理不可的问题，但有 {yellow} 件事值得留意。"
    return "这次没发现需要处理的问题。"


HTML_STYLE = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:#F5F4F0;color:#23211E;line-height:1.65;padding:32px 16px}
.report{max-width:720px;margin:0 auto;background:#fff;border-radius:16px;padding:40px 44px;border:1px solid #E2DFD7}
h1{font-size:24px;font-weight:500;letter-spacing:-.01em}
.meta{font-size:13px;color:#7A756B;margin-top:6px}
.verdict{margin:28px 0 8px;padding:22px 24px;border-radius:12px;background:#F7F6F2;border:1px solid #E7E4DB}
.verdict p{font-size:17px;font-weight:500}
.counts{display:flex;gap:10px;margin-top:16px;flex-wrap:wrap}
.count{display:flex;align-items:baseline;gap:6px;font-size:13px;color:#5F5A51;padding:6px 12px;border-radius:999px;background:#fff;border:1px solid #E7E4DB}
.count b{font-size:16px;font-weight:500}
h2{font-size:15px;font-weight:500;margin:32px 0 14px;color:#5F5A51}
.issue{border-radius:12px;padding:18px 20px;margin-bottom:12px;border-left:3px solid}
.issue h3{font-size:15px;font-weight:500;margin-bottom:10px}
.issue dl{display:grid;grid-template-columns:76px 1fr;gap:6px 10px;font-size:14px}
.issue dt{color:#7A756B;font-size:13px}
.issue dd{color:#23211E}
.r-red{background:#FDECEA;border-color:#C62828}
.r-red h3{color:#9B1C1C}
.r-yellow{background:#FFF8E1;border-color:#B26A00}
.r-yellow h3{color:#8A5200}
.r-unknown{background:#F5F5F5;border-color:#9E9E9E}
.r-unknown h3{color:#5F5A51}
.passed{font-size:14px;color:#3B6D11;background:#EAF3DE;border-radius:12px;padding:16px 20px;border-left:3px solid #639922}
.card{margin-top:32px;border:1px solid #E2DFD7;border-radius:12px;overflow:hidden}
.card h2{margin:0;padding:14px 20px;background:#F7F6F2;border-bottom:1px solid #E2DFD7;font-size:14px}
.card ul{list-style:none;padding:0}
.card li{padding:12px 20px;border-bottom:1px solid #F0EDE5;font-size:14px;display:grid;grid-template-columns:120px 1fr;gap:12px}
.card li:last-child{border-bottom:0}
.card li span:first-child{color:#7A756B;font-size:13px}
footer{margin-top:28px;font-size:12px;color:#9A948A;text-align:center}
@media print{body{background:#fff;padding:0}.report{border:0;padding:0}}
"""


def render_html(report: dict) -> str:
    counts = report["summary"]
    machine = report["machine"]

    issues = [i for i in report["items"] if i["level"] in (RED, YELLOW, UNKNOWN)]
    passed = [i for i in report["items"] if i["level"] == GREEN]

    issue_html = []
    for item in issues:
        css = f"r-{item['level']}"
        issue_html.append(
            f'<article class="issue {css}">'
            f"<h3>{item['title']}</h3>"
            f"<dl>"
            f"<dt>查到什么</dt><dd>{item['found']}</dd>"
            f"<dt>要不要紧</dt><dd>{item['why']}</dd>"
            f"<dt>怎么办</dt><dd>{item['fix']}</dd>"
            f"</dl></article>"
        )
    if not issue_html:
        issue_html.append(
            '<article class="passed">这次没有发现需要处理的问题。</article>'
        )

    passed_html = ""
    if passed:
        names = "、".join(i["title"] for i in passed)
        passed_html = f'<p class="passed">这些都没问题：{names}</p>'

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>电脑体检报告</title>
<style>{HTML_STYLE}</style>
</head>
<body>
<article class="report">
<header>
<h1>电脑体检报告</h1>
<p class="meta">{report['generated_at'][:16].replace('T', ' ')} · {machine.get('hostname', '')} · Windows {machine.get('release', '')}{' · <strong>演示数据，不是真实检测结果</strong>' if report.get('demo') else ''}</p>
</header>

<section class="verdict">
<p>{verdict_line(report)}</p>
<div class="counts">
<span class="count">需要处理 <b>{counts.get(RED, 0)}</b></span>
<span class="count">值得留意 <b>{counts.get(YELLOW, 0)}</b></span>
<span class="count">没问题 <b>{counts.get(GREEN, 0)}</b></span>
<span class="count">没查成 <b>{counts.get(UNKNOWN, 0)}</b></span>
</div>
</section>

<h2>需要你看一眼的</h2>
{''.join(issue_html)}

{passed_html}

<div class="card">
<h2>这次做了什么</h2>
<ul>
<li><span>一句话结果</span><span>{verdict_line(report)}</span></li>
<li><span>能看见的变化</span><span>这次只检查、没有改动任何设置。你的电脑和体检前完全一样。</span></li>
<li><span>你自己怎么查</span><span>按上面每条里的「怎么办」操作；报告里的路径都能直接打开。</span></li>
<li><span>明确没做的事</span><span>没有修改设置、没有删除文件、没有上传任何数据、没有联网。</span></li>
</ul>
</div>

<footer>本报告只在本机生成，没有上传到任何地方。</footer>
</article>
</body>
</html>"""


def to_human(report: dict) -> str:
    lines = []
    counts = report["summary"]
    lines.append(f"体检完成：红 {counts.get(RED,0)} 项 · 黄 {counts.get(YELLOW,0)} 项 · 绿 {counts.get(GREEN,0)} 项 · 未查 {counts.get(UNKNOWN,0)} 项")
    lines.append("")
    for item in report["items"]:
        if item["level"] == GREEN:
            continue
        lines.append(f"[{LEVEL_ICON.get(item['level'], '?')}] {item['title']}")
        lines.append(f"    查到：{item['found']}")
        lines.append(f"    要紧吗：{item['why']}")
        lines.append(f"    怎么办：{item['fix']}")
        lines.append("")
    green_titles = [i["title"] for i in report["items"] if i["level"] == GREEN]
    if green_titles:
        lines.append(f"没问题的：{ '、'.join(green_titles) }")
    return "\n".join(lines)


def demo_report() -> dict:
    """演示数据。用于 README 截图和给用户看「有问题时长什么样」。
    明确标注 demo=true，不要拿它冒充真实检测结果。"""
    items = [
        make_item(
            "firewall", "上网安全", "防火墙", RED,
            "你的「公用网络」防火墙是关着的。",
            "防火墙是电脑的门。门开着，别人从网络进来就不用撬锁了。",
            "打开「Windows 安全中心」→「防火墙和网络保护」，把「公用网络」点成「开启」。",
            {"off": ["公用网络"]},
        ),
        make_item(
            "windows_version", "系统健康", "系统版本", RED,
            "你用的系统版本偏老（7，内部版本 7601），已经不在官方安全更新范围内。",
            "老系统不再收到安全补丁。已经公开的漏洞没人帮你补，谁都知道怎么打。",
            "这是这次体检里最该处理的一项。备份好文件，找时间升级系统。",
            {"release": "7", "build": 7601},
        ),
        make_item(
            "rdp", "上网安全", "远程桌面", YELLOW,
            "你的「远程桌面」是开着的。",
            "开了远程桌面，就等于给这台电脑开了一扇可以从别的电脑连进来的门。自己家用不上它的话，等于白留一个入口。",
            "如果你不用别的设备连这台电脑：打开「设置」→「系统」→「远程桌面」，把它关掉。",
            {},
        ),
        make_item(
            "browser_ext", "上网安全", "浏览器扩展", YELLOW,
            "有 3 个扩展能读取你在所有网站上的内容：网页翻译助手(Chrome)、比价小工具(Chrome)、PDF 转换(Edge)。",
            "这类扩展能看到你打开的每一个网页，包括银行、邮箱、公司系统。绝大多数是正常的，但一旦某个扩展被卖掉或者自己出问题，你的登录状态就可能被别人拿到。",
            "打开浏览器 →「扩展程序」页面，逐个看。不认识的、很久没用的，直接删掉。常用的留着没关系。",
            {"total": 12, "full_access": 3},
        ),
        make_item(
            "bitlocker", "账号安全", "磁盘加密", YELLOW,
            "系统盘没有加密。",
            "加密是防「电脑丢了」的。别人把硬盘拆下来接到别的机器上，没加密就能直接读你的文件。台式机放在家里影响小，笔记本经常带出门就值得开。",
            "打开「控制面板」→「系统和安全」→「BitLocker 驱动器加密」，对系统盘点「启用 BitLocker」。开之前先把恢复密钥存好。",
            {},
        ),
        make_item(
            "disk_space", "系统健康", "磁盘空间", YELLOW,
            "系统盘只剩 12.4 GB（7.8%）。",
            "系统盘快满的时候，Windows 会没法更新、程序会莫名其妙卡死、有些软件直接打不开。",
            "先清「下载」文件夹和回收站，再打开「设置」→「系统」→「存储」，用「临时文件」清理。至少要留出 15% 以上。",
            {"drives": [{"drive": "C:\\", "total_gb": 158.0, "free_gb": 12.4, "free_pct": 7.8}]},
        ),
        make_item(
            "antivirus", "上网安全", "病毒防护", GREEN,
            "检测到正在运行的杀毒软件：Windows Defender。",
            "这条没问题。", "不用动。", {"names": ["Windows Defender"]},
        ),
        make_item(
            "smb1", "上网安全", "老式文件共享", GREEN,
            "老式文件共享协议是关着的。", "这条没问题。", "不用动。", {},
        ),
        make_item(
            "guest_account", "账号安全", "来宾账户", GREEN,
            "来宾账户是关着的。", "这条没问题。", "不用动。", {},
        ),
        make_item(
            "admins", "账号安全", "管理员账户", GREEN,
            "管理员账户数量正常（1 个）。", "这条没问题。", "不用动。", {"members": ["Kyrie"]},
        ),
        make_item(
            "startup", "系统健康", "开机自启", GREEN,
            "开机自启的程序有 9 个，数量正常。", "这条没问题。", "不用动。", {"count": 9},
        ),
    ]
    counts = {level: 0 for level in (RED, YELLOW, GREEN, UNKNOWN)}
    for item in items:
        counts[item["level"]] += 1
    return {
        "tool": "laobaixing-computer-check",
        "version": "1.0.0",
        "demo": True,
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "machine": {"os": "Windows", "release": "11", "version": "10.0.22631", "arch": "AMD64", "hostname": "DEMO-PC"},
        "summary": counts,
        "items": items,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="老百姓电脑体检 · 只读检测")
    parser.add_argument("--pretty", action="store_true", help="缩进输出")
    parser.add_argument("--human", action="store_true", help="输出人话版（调试用）")
    parser.add_argument("--html", action="store_true", help="输出可打印的 HTML 报告")
    parser.add_argument("--demo", action="store_true", help="用演示数据出报告（README 截图用，不检测本机）")
    parser.add_argument("--out", metavar="PATH", help="写到文件")
    args = parser.parse_args()

    report = demo_report() if args.demo else run_all()

    if args.html:
        text = render_html(report)
    elif args.human:
        text = to_human(report)
    else:
        text = json.dumps(report, ensure_ascii=False, indent=2 if args.pretty else None)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        sys.stderr.write(f"已写入 {args.out}\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
