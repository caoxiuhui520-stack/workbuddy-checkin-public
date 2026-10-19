#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在本机从 WorkBuddy AI（国际版）客户端导出明文长效令牌（仅 Windows）。

5.6.2+ 客户端把 auth.refreshToken/accessToken 存成 AES-256-GCM 信封，
密钥不落盘、只在运行中的客户端进程内存里。本脚本：

  1) 读取 ~/.workbuddy-ai/keyblob 得到 protectorKeyId（密钥指纹）
  2) 扫描 WorkBuddy.exe 进程内存，找 44 字符规范 base64 且指纹匹配的 at-rest 密钥
  3) 用 keyblob 的 static-v1 槽做一次解封校验（确认密钥正确）
  4) 解出 refreshToken / accessToken，连同 uid/domain 写入输出文件

用法：
  python scripts/export_intl_token.py --out "%USERPROFILE%\\.wb_intl_tokens.json"
  python scripts/export_intl_token.py --auth "C:\\...\\workbuddy-desktop-ai.info"

输出文件含明文令牌，脚本只打印字段长度，绝不打印内容。用完请删除。

注意：客户端需已安装并登录，且保持运行；脚本与客户端须在同一 Windows 用户下运行。
"""

import argparse
import base64
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import re
import struct
import sys

try:
    from Crypto.Cipher import AES
except Exception:  # pragma: no cover
    AES = None


AUTH_CANDIDATES = [
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "CodeBuddyExtension", "Data",
                 "Public", "auth", "workbuddy-desktop-ai.info"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "CodeBuddyExtension", "Data",
                 "Public", "auth", "workbuddy-desktop.info"),
    os.path.join(os.path.expanduser("~"), ".workbuddy-ai", "auth", "workbuddy-desktop.info"),
]
KEYBLOB_CANDIDATES = [
    os.path.join(os.path.expanduser("~"), ".workbuddy-ai", "keyblob"),
    os.path.join(os.path.expanduser("~"), ".workbuddy", "keyblob"),
]
FRAME_MAGIC = {"file": b"WBEF1", "field": b"WBEV1"}
FRAME_BYTE = {"file": 1, "field": 2}
TARGET_EXE = "workbuddy.exe"


# ---------------------------------------------------------------- AES-GCM

def lp(s):
    b = s.encode("utf-8") if isinstance(s, str) else s
    return struct.pack(">I", len(b)) + b


def build_aad(kind, key_id, suite):
    return (b"WB-AAD\x00" + b"\x01" + lp(FRAME_MAGIC[kind]) + lp("sym-v1")
            + struct.pack(">I", suite) + lp(key_id) + bytes([FRAME_BYTE[kind]])
            + b"\x00" + b"\x00")


def key_id_of(key):
    return hashlib.sha256(key).hexdigest()[:16]


def open_envelope(key, env_b64, kind):
    env = json.loads(base64.b64decode(env_b64))
    kid = key_id_of(key)
    if str(env.get("keyId", "")).lower() != kid:
        raise ValueError("keyId mismatch")
    if AES is None:
        raise RuntimeError("缺少 pycryptodome（pip install pycryptodome）")
    c = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(env["nonce"]), mac_len=16)
    c.update(build_aad(kind, kid, int(env.get("suite", 1))))
    return c.decrypt_and_verify(base64.b64decode(env["ciphertext"]),
                                base64.b64decode(env["authTag"]))


# ---------------------------------------------------------------- 进程内存

READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
CHUNK = 4 << 20
B64_44 = re.compile(rb"[A-Za-z0-9+/]{43}=")


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)), ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_char * 260),
    ]


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wt.DWORD), ("_a", wt.DWORD),
        ("RegionSize", ctypes.c_ulonglong), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_b", wt.DWORD),
    ]


k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.CloseHandle.argtypes = [wt.HANDLE]


def list_pids():
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (0, ctypes.c_void_p(-1).value):
        return []
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    pids = []
    ok = k32.Process32First(snap, ctypes.byref(entry))
    while ok:
        name = entry.szExeFile.decode("ascii", "ignore").lower()
        if name == TARGET_EXE or name.endswith(".exe") and "workbuddy" in name:
            pids.append(entry.th32ProcessID)
        ok = k32.Process32Next(snap, ctypes.byref(entry))
    k32.CloseHandle(snap)
    return pids


def scan_for_key(pids, want_key_id):
    buf = ctypes.create_string_buffer(CHUNK)
    rd = ctypes.c_size_t(0)
    for pid in pids:
        h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            continue
        addr = 0
        mbi = MBI()
        try:
            while k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                                     ctypes.sizeof(mbi)):
                base, size = mbi.BaseAddress, mbi.RegionSize
                if size == 0:
                    break
                if (mbi.State == 0x1000 and (mbi.Protect & 0xFF) in READABLE
                        and not (mbi.Protect & 0x100)):
                    off = 0
                    while off < size:
                        n = min(CHUNK, size - off)
                        if k32.ReadProcessMemory(h, ctypes.c_void_p(base + off), buf, n,
                                                 ctypes.byref(rd)):
                            for m in B64_44.finditer(buf.raw[:rd.value]):
                                try:
                                    key = hashlib.sha256(m.group(0)).digest()
                                except Exception:
                                    continue
                                if key_id_of(key) == want_key_id:
                                    return key
                        off += n
                addr = base + size
        finally:
            k32.CloseHandle(h)
    return None


# ---------------------------------------------------------------- 导出

def load_keyblob():
    for p in KEYBLOB_CANDIDATES:
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return p, json.load(f)
    return None, None


def find_auth_file(explicit=None):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for p in AUTH_CANDIDATES:
        if p and os.path.isfile(p):
            return p
    return None


def resolve_field(raw, key, label):
    if isinstance(raw, str):
        if not raw.strip():
            return None, "%s: 空" % label
        return raw.strip(), "%s: 明文" % label
    if isinstance(raw, dict) and raw.get("$wbEncrypted") == 1:
        try:
            return open_envelope(key, raw["envelope"], "field").decode("utf-8"), \
                   "%s: 信封已解密" % label
        except Exception as e:
            return None, "%s: 解密失败(%s)" % (label, str(e)[:80])
    return None, "%s: 形态无法识别" % label


def realm_of(token, domain):
    """粗判令牌归属：intl（.ai）/ cn（.cn）/ None。"""
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        payload = json.loads(base64.urlsafe_b64decode(seg.encode("ascii")))
    except Exception:
        payload = {}
    blob = " ".join(str(payload.get(k) or "") for k in ("iss", "domain", "aud", "sub")).lower()
    d = (domain or "").lower()
    if "workbuddy.ai" in blob or "codebuddy.ai" in blob or ".ai" in d:
        return "intl"
    if ("codebuddy.cn" in blob or "workbuddy.cn" in blob or "tencent.com" in blob
            or ".cn" in d):
        return "cn"
    return None


def main():
    ap = argparse.ArgumentParser(description="导出 WorkBuddy AI 国际版明文令牌")
    ap.add_argument("--auth", help="登录态文件路径（默认自动探测）")
    ap.add_argument("--out", default=os.path.join(os.path.expanduser("~"),
                                                  ".wb_intl_tokens.json"))
    ap.add_argument("--allow-cn", action="store_true",
                    help="允许导出国区登录态（默认拒绝，避免把国内账号当国际版）")
    args = ap.parse_args()

    if os.name != "nt":
        print("仅支持 Windows"); return 2
    if AES is None:
        print("缺少 pycryptodome：pip install pycryptodome"); return 2

    auth_path = find_auth_file(args.auth)
    if not auth_path:
        print("未找到登录态文件，请确认国际版客户端已安装并登录")
        return 2
    print("登录态文件：%s" % auth_path)

    blob_path, blob = load_keyblob()
    if not blob:
        print("未找到 keyblob，请确认客户端已登录过")
        return 2
    protector_id, wrapped = None, None
    for slot in blob.get("slots") or []:
        if slot.get("type") == "static-v1" and slot.get("protectorKeyId"):
            protector_id, wrapped = str(slot["protectorKeyId"]).lower(), slot.get("wrapped")
            break
    if not protector_id:
        print("keyblob 中没有 static-v1 槽")
        return 2
    print("keyblob：%s（protectorKeyId=%s）" % (blob_path, protector_id))

    pids = list_pids()
    if not pids:
        print("没有运行中的 WorkBuddy 进程，请先启动客户端并登录")
        return 2
    print("扫描进程：%s" % ",".join(str(p) for p in pids))
    key = scan_for_key(pids, protector_id)
    if not key:
        print("未在进程内存中找到 at-rest 密钥")
        return 2
    print("已定位 at-rest 密钥（%d bytes）" % len(key))

    # keyblob 解封自检：能解出 32 字节主密钥且 keyId 匹配，才继续
    try:
        master = open_envelope(key, wrapped, "file")
        if len(master) != 32 or key_id_of(master) != str(blob.get("keyId", "")).lower():
            raise ValueError("主密钥校验失败")
        print("keyblob 解封校验通过")
    except Exception as e:
        print("keyblob 解封校验失败：%s" % str(e)[:120])
        return 2

    with open(auth_path, encoding="utf-8") as f:
        data = json.load(f)
    auth = data.get("auth") or {}
    account = data.get("account") or {}
    rt, rt_note = resolve_field(auth.get("refreshToken"), key, "refreshToken")
    at, at_note = resolve_field(auth.get("accessToken"), key, "accessToken")
    if not rt:
        print("无法取得明文长效令牌：%s；%s" % (rt_note, at_note))
        return 2

    realm = realm_of(rt, str(auth.get("domain") or ""))
    print("区域判定：%s" % (realm or "未知"))
    if realm == "cn" and not args.allow_cn:
        print("检测到国内版（.cn）登录态。请先在 WorkBuddy AI 国际版客户端登录，"
              "或显式加 --allow-cn 强制导出。")
        return 2

    out = {
        "refreshToken": rt,
        "accessToken": at or "",
        "uid": str(account.get("uid") or "").strip(),
        "domain": str(auth.get("domain") or "www.workbuddy.ai").strip(),
        "enterpriseId": str(account.get("enterpriseId") or "").strip(),
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(args.out, 0o600)
    except OSError:
        pass

    print("refreshToken：%s" % rt_note)
    print("accessToken ：%s" % at_note)
    print("uid：%s" % ("已取得" if out["uid"] else "缺失"))
    print("domain：%s" % out["domain"])
    print("已写入：%s（含明文令牌，用完请删除）" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
