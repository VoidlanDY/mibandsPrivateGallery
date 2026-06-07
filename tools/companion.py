#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
私密图库 - 手机端管理工具

通过ADB管理手表上的私密图库快应用。
功能：
  - 设置/修改普通密码和私密密码
  - 导入图片到普通图库或私密图库
  - 查看图库状态
  - 验证密码对应模式

依赖: Python 3.6+, ADB工具, requests (可选)
用法: python companion.py
"""

import os
import sys
import json
import struct
import hashlib
import subprocess
import re
import tempfile
import shutil
from pathlib import Path

# ============================================================
# 配置
# ============================================================

# 手表端快应用的内部存储路径（Vela快应用）
WATCH_APP_DATA = "/data/app/com.privategallery"
WATCH_FILES_DIR = WATCH_APP_DATA + "/files"
WATCH_NORMAL_DIR = WATCH_FILES_DIR + "/normal"
WATCH_PRIVATE_DIR = WATCH_FILES_DIR + "/private"
WATCH_STORAGE_FILE = WATCH_APP_DATA + "/storage.db"

PIN_LENGTH = 6
MAX_ATTEMPTS = 5

# ============================================================
# ADB 工具
# ============================================================

def run_adb(cmd, timeout=10):
    """执行ADB命令"""
    try:
        result = subprocess.run(
            ["adb"] + cmd,
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        print("\n[错误] 未找到 adb 命令。请安装 Android SDK Platform Tools。")
        print("下载: https://developer.android.com/studio/releases/platform-tools")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        return False, "", "超时"
    except Exception as e:
        return False, "", str(e)

def check_adb():
    """检查ADB连接"""
    ok, out, err = run_adb(["devices"])
    if not ok:
        return False, "ADB 不可用"
    lines = [l for l in out.split('\n') if l.strip() and not l.startswith('*')]
    devices = [l for l in lines[1:] if '\tdevice' in l]
    if not devices:
        return False, "未检测到已连接的设备"
    return True, f"已连接 {len(devices)} 个设备"

def adb_shell(cmd):
    """执行ADB shell命令"""
    ok, out, err = run_adb(["shell", cmd])
    return ok, out

def adb_push(local, remote):
    """推送文件到手表"""
    ok, out, err = run_adb(["push", local, remote])
    return ok, out

def adb_pull(remote, local):
    """从手表拉取文件"""
    ok, out, err = run_adb(["pull", remote, local])
    return ok, out

# ============================================================
# SHA-256 密码工具
# ============================================================

def sha256(data):
    """计算SHA-256哈希"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()

def hash_to_hex(h):
    """哈希转hex字符串"""
    return h.hex()

def hex_to_hash(s):
    """hex字符串转哈希"""
    return bytes.fromhex(s)

# ============================================================
# 手表端密码管理
# ============================================================

def ensure_dirs():
    """确保手表上的目录结构存在"""
    cmds = [
        f"mkdir -p {WATCH_NORMAL_DIR}",
        f"mkdir -p {WATCH_PRIVATE_DIR}",
    ]
    for cmd in cmds:
        adb_shell(cmd)

def get_watch_storage():
    """读取手表的storage数据"""
    # Vela快应用storage通常存在SQLite或JSON文件中
    # 这里使用JSON文件方案
    config_file = WATCH_FILES_DIR + "/.gallery_config.json"
    ok, data = adb_shell(f"cat {config_file} 2>/dev/null")
    if ok and data:
        try:
            return json.loads(data)
        except:
            pass
    return {"normal_pw": "", "private_pw": "", "normal_images": [], "private_images": []}

def save_watch_storage(config):
    """保存配置到手表中转文件，然后让快应用读取"""
    config_file = WATCH_FILES_DIR + "/.gallery_config.json"
    config_json = json.dumps(config)

    # 通过本地临时文件推送
    tmp = os.path.join(tempfile.gettempdir(), "gallery_config.json")
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(config_json)

    adb_push(tmp, config_file)
    os.unlink(tmp)

    # 同时设置文件权限
    adb_shell(f"chmod 644 {config_file}")

def set_watch_password(mode, pin):
    """设置手表密码"""
    if len(pin) != PIN_LENGTH or not pin.isdigit():
        return False, f"密码必须是{PIN_LENGTH}位数字"

    pw_hash = hash_to_hex(sha256(pin))
    config = get_watch_storage()

    if mode == "normal":
        config["normal_pw"] = pw_hash
        label = "普通密码"
    else:
        config["private_pw"] = pw_hash
        label = "私密密码"

    save_watch_storage(config)
    return True, f"{label}已设置"

def verify_watch_password(pin):
    """验证密码对应哪种模式"""
    if len(pin) != PIN_LENGTH or not pin.isdigit():
        return "invalid"

    input_hash = sha256(pin)
    config = get_watch_storage()

    normal_match = False
    private_match = False

    if config.get("normal_pw"):
        stored = hex_to_hash(config["normal_pw"])
        # 常量时间比较
        diff = 0
        for a, b in zip(stored, input_hash):
            diff |= a ^ b
        normal_match = (diff == 0)

    if config.get("private_pw"):
        stored = hex_to_hash(config["private_pw"])
        diff = 0
        for a, b in zip(stored, input_hash):
            diff |= a ^ b
        private_match = (diff == 0)

    if private_match and normal_match:
        return "both"
    elif private_match:
        return "private"
    elif normal_match:
        return "normal"
    return "none"

# ============================================================
# 图片管理
# ============================================================

def import_images(mode, file_paths):
    """导入图片到手表中转区域"""
    target_dir = WATCH_NORMAL_DIR if mode == "normal" else WATCH_PRIVATE_DIR

    ensure_dirs()

    success = 0
    for fp in file_paths:
        if not os.path.isfile(fp):
            print(f"  跳过（不存在）: {fp}")
            continue

        # 只允许图片格式
        ext = os.path.splitext(fp)[1].lower()
        if ext not in ('.png', '.jpg', '.jpeg', '.bmp', '.gif'):
            print(f"  跳过（非图片格式）: {fp}")
            continue

        basename = os.path.basename(fp)
        remote_path = f"{target_dir}/{basename}"

        ok, msg = adb_push(fp, remote_path)
        if ok:
            success += 1
            print(f"  [OK] {basename}")
        else:
            print(f"  [ERR] {basename}: {msg}")

    # 更新图片清单到配置
    if success > 0:
        ok, ls_out = adb_shell(f"ls {target_dir}/")
        if ok:
            image_names = [n for n in ls_out.split() if not n.startswith('.')]

            config = get_watch_storage()
            if mode == "normal":
                config["normal_images"] = [
                    {"name": n, "uri": f"internal://files/normal/{n}"}
                    for n in image_names
                ]
            else:
                config["private_images"] = [
                    {"name": n, "uri": f"internal://files/private/{n}"}
                    for n in image_names
                ]
            save_watch_storage(config)

    return success

def list_gallery():
    """列出图库状态"""
    config = get_watch_storage()
    normal_count = len(config.get("normal_images", []))
    private_count = len(config.get("private_images", []))
    return normal_count, private_count

# ============================================================
# 交互式菜单
# ============================================================

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    clear_screen()
    print("=" * 50)
    print("  私密图库 · 手机端管理工具")
    print("  小米手环9 Pro · Vela快应用")
    print("=" * 50)

def print_menu():
    print()
    connected, msg = check_adb()
    if connected:
        print(f"  [状态] OK {msg}")
    else:
        print(f"  [状态] !! {msg}")
        print()
        print("  请先通过USB连接手表并开启ADB调试")
        print()
        input("按回车键重试...")
        return False

    normal, private = list_gallery()
    print(f"  [普通图库] {normal} 张图片")
    print(f"  [私密图库] {private} 张图片")
    print()
    print("  1. 导入图片到普通图库")
    print("  2. 导入图片到私密图库")
    print("  3. 设置普通密码")
    print("  4. 设置私密密码")
    print("  5. 验证密码（确认密码对应模式）")
    print("  6. 刷新状态")
    print("  7. 恢复默认密码 (000000)")
    print("  0. 退出")
    print()
    return True

def pick_files():
    """选择文件"""
    print()
    print("请输入图片文件路径（支持拖拽多个文件）:")
    print("每行一个路径，输入空行结束：")
    files = []
    while True:
        line = input().strip().strip('"').strip("'")
        if not line:
            break
        if os.path.isfile(line):
            files.append(line)
        else:
            # 尝试glob
            import glob
            matched = glob.glob(line)
            if matched:
                files.extend(matched)
            else:
                print(f"  文件不存在: {line}")
    return files

def main():
    while True:
        print_header()
        if not print_menu():
            continue

        choice = input("请选择 [0-7]: ").strip()

        if choice == '1':
            files = pick_files()
            if files:
                print(f"\n导入 {len(files)} 个文件到普通图库...")
                n = import_images("normal", files)
                print(f"\n成功导入 {n} 个文件")
                input("\n按回车键继续...")

        elif choice == '2':
            files = pick_files()
            if files:
                print(f"\n导入 {len(files)} 个文件到私密图库...")
                n = import_images("private", files)
                print(f"\n成功导入 {n} 个文件")
                input("\n按回车键继续...")

        elif choice == '3':
            print()
            pin = input(f"请输入{PIN_LENGTH}位数字普通密码: ").strip()
            if len(pin) == PIN_LENGTH and pin.isdigit():
                pin2 = input("请再次输入确认: ").strip()
                if pin == pin2:
                    ok, msg = set_watch_password("normal", pin)
                    print(f"\n{msg}")
                else:
                    print("\n两次输入的密码不一致！")
            else:
                print(f"\n密码必须是{PIN_LENGTH}位数字！")
            input("\n按回车键继续...")

        elif choice == '4':
            print()
            pin = input(f"请输入{PIN_LENGTH}位数字私密密码: ").strip()
            if len(pin) == PIN_LENGTH and pin.isdigit():
                pin2 = input("请再次输入确认: ").strip()
                if pin == pin2:
                    ok, msg = set_watch_password("private", pin)
                    print(f"\n{msg}")
                else:
                    print("\n两次输入的密码不一致！")
            else:
                print(f"\n密码必须是{PIN_LENGTH}位数字！")
            input("\n按回车键继续...")

        elif choice == '5':
            print()
            pin = input(f"请输入{PIN_LENGTH}位数字密码进行验证: ").strip()
            if len(pin) == PIN_LENGTH and pin.isdigit():
                result = verify_watch_password(pin)
                print()
                if result == "both":
                    print("  [WARN] 密码匹配: 普通图库 和 私密图库（两个密码相同！）")
                    print("    建议设置不同的密码以确保隐私")
                elif result == "private":
                    print("  [PRIVATE] 匹配: 私密图库")
                    print("    （在手表上输入此密码将显示私密图片）")
                elif result == "normal":
                    print("  [NORMAL] 匹配: 普通图库")
                    print("    （在手表上输入此密码将显示普通图片）")
                elif result == "none":
                    print("  [NONE] 不匹配任何密码")
                else:
                    print(f"  密码格式不正确")
            input("\n按回车键继续...")

        elif choice == '6':
            print("\n刷新中...")
            input("按回车键继续...")

        elif choice == '7':
            print()
            confirm = input("确认恢复默认密码? (y/N): ").strip().lower()
            if confirm == 'y':
                set_watch_password("normal", "000000")
                set_watch_password("private", "999999")
                print("\n普通密码已重置为: 000000")
                print("私密密码已重置为: 999999")
            else:
                print("\n已取消")
            input("\n按回车键继续...")

        elif choice == '0':
            print("\n再见！")
            break

        else:
            print("\n无效选择，请重试")
            input("按回车键继续...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n已退出")
        sys.exit(0)
