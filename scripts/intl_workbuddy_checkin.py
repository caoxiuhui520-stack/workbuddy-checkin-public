#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WorkBuddy AI（国际版）每日活跃 → 积分 自动化。

国际版没有「签到」按钮，每日福利按「活跃账号」发放：
  当天至少发起一次客户端对话（chat_request_send），服务端才会记一次活跃。
本脚本复刻桌面客户端链路：

  1) refresh token  → access token
     POST https://www.workbuddy.ai/v2/plugin/auth/token/refresh
  2) 云端会话登记     POST /console/as/conversations/v2（尽力而为）
  3) 对话请求         POST /v2/chat/completions（SSE，system 必须在最前）
  4) 遥测上报         POST /v2/report（chat_request_send，尽力而为）
  5) 积分查询         POST https://www.codebuddy.ai/v2/billing/meter/get-user-resource

环境变量（GitHub Secrets）：
  WB_INTL_REFRESH_TOKEN   长效令牌（必填）
  WB_INTL_UID             账号 UID（必填；也可从 JWT 自动解析）
  WB_INTL_DOMAIN          默认 www.workbuddy.ai
  WB_INTL_ENTERPRISE_ID   企业账号可选
  WB_INTL_NICKNAME        可选（仅遥测字段）
  WB_INTL_MODEL           默认 hy3
  WB_INTL_PROMPT          自定义提问（默认一句自然的多句问题）
  WB_INTL_MACHINE_ID      可选，稳定机器标识

推送环境变量（可选，四个通道互相独立，配了哪个推哪个）：
  WECOM_WEBHOOK           企业微信群机器人 webhook 完整地址
  PUSHPLUS_TOKEN          PushPlus token（微信）
  BARK_URL                Bark 地址，形如 https://api.day.app/<key>/
  SERVERCHAN_SENDKEY      Server酱 SendKey（SCT 开头为 Turbo，SCU 开头为旧版）
  SUCCESS_NOTIFY          true/1/yes 时成功也推送；失败始终推送

安全：token 只在内存中使用，输出只报状态/长度，绝不回显内容。
"""

import base64
import hashlib
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

GLOBAL_BASE = "https://www.workbuddy.ai"
GLOBAL_BILLING = "https://www.codebuddy.ai"
REFRESH_PATH = "/v2/plugin/auth/token/refresh"
CONVERSATION_PATH = "/console/as/conversations/v2"
CHAT_PATH = "/v2/chat/completions"
REPORT_PATH = "/v2/report"
POINTS_PATH = "/v2/billing/meter/get-user-resource"

# 对齐国际版客户端身份（逆向自 WorkBuddy AI 桌面端 / CLI 拦截器）
INTL_UA = "WorkBuddy/5.5.2 WorkBuddy AI/5.5.2 CLI/2.137.1"
INTL_NAME = "WorkBuddy"
INTL_VER = "5.5.2"
LEGACY_UA = "CLI/2.63.2 CodeBuddy/2.63.2"

DEFAULT_PROMPT = (
    "你好，请用三句话分别回答：你是谁、你由哪家公司开发、"
    "以及你在处理多步骤任务时通常怎样规划步骤。"
)
HTTP_TIMEOUT = 30
MAX_STREAM_BYTES = 2 << 20


# ---------------------------------------------------------------- 基础工具

def mask(t):
    if not t:
        return "<empty>"
    return "<已配置，长度 %d，不回显>" % len(t)


def truthy(v):
    return str(v or "").strip().lower() in ("1", "true", "yes", "on", "y")


def now_local():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def new_uuid():
    return str(uuid.uuid4())


def no_dash(v):
    return v.replace("-", "")


def machine_id():
    env = (os.environ.get("WB_INTL_MACHINE_ID") or "").strip()
    if env:
        return env
    raw = "workbuddy-intl-actions:" + socket.gethostname()
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def jwt_payload(token):
    """尽力解析 JWT payload；失败返回 {}。仅用于取 uid。"""
    try:
        parts = token.split(".")
        if len(parts) < 3:
            return {}
        seg = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(seg.encode("ascii")))
    except Exception:
        return {}


def uid_from_jwt(token):
    p = jwt_payload(token)
    for k in ("uid", "userId", "user_id", "sub", "openid", "openId"):
        v = p.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def http_json(url, method="GET", headers=None, body=None, timeout=HTTP_TIMEOUT):
    """返回 (http_status, parsed_json_or_None, raw_text)。"""
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_STREAM_BYTES)
            txt = raw.decode("utf-8", "replace")
            try:
                return resp.status, json.loads(txt), txt
            except Exception:
                return resp.status, None, txt
    except urllib.error.HTTPError as e:
        raw = e.read(MAX_STREAM_BYTES)
        txt = raw.decode("utf-8", "replace")
        try:
            return e.code, json.loads(txt), txt
        except Exception:
            return e.code, None, txt
    except Exception as e:
        return 0, None, "transport: %s" % str(e)[:200]


# ---------------------------------------------------------------- 凭据

def _base_headers(origin):
    return {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Origin": origin,
        "Referer": origin + "/",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": LEGACY_UA if "workbuddy.ai" in origin else INTL_UA,
    }


def refresh_token(rt, domain):
    """长效令牌换 access token。返回 (access, new_rt, domain, err)。"""
    url = GLOBAL_BASE + REFRESH_PATH
    headers = _base_headers(GLOBAL_BASE)
    headers["X-Refresh-Token"] = rt
    headers["X-Auth-Refresh-Source"] = "plugin"
    headers["X-Domain"] = "www.workbuddy.ai"
    st, body, raw = http_json(url, "POST", headers, None)
    if not isinstance(body, dict):
        return None, None, None, "刷新接口返回非 JSON（HTTP %s）" % st
    if body.get("code") not in (0, None):
        return None, None, None, "刷新失败 code=%s msg=%s" % (
            body.get("code"), str(body.get("msg") or body.get("message") or "")[:160])
    data = body.get("data") if isinstance(body.get("data"), dict) else body
    at = (data or {}).get("accessToken") or ""
    if not at:
        return None, None, None, "刷新应答缺少 accessToken（HTTP %s）" % st
    return at, (data or {}).get("refreshToken") or "", (data or {}).get("domain") or domain, None


def auth_headers(token, uid, domain, enterprise_id, ua=INTL_UA, origin=GLOBAL_BASE):
    h = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": ua,
        "Authorization": "Bearer " + token,
        "X-Product": "SaaS",
        "X-IDE-Type": INTL_NAME,
        "X-IDE-Name": INTL_NAME,
        "X-IDE-Version": INTL_VER,
        "X-Domain": domain,
    }
    if uid:
        h["X-User-Id"] = uid
    if enterprise_id:
        h["X-Enterprise-Id"] = enterprise_id
        h["X-Tenant-Id"] = enterprise_id
    return h


# ---------------------------------------------------------------- 积分

def points_detail(token, uid, domain):
    """查询全部积分套餐明细。

    返回 (detail, err)：
      detail = {
        "total_remain": int|None,   # 所有套餐剩余之和
        "packs": [ {...}, ... ],    # 逐套餐明细（已脱敏，不含 Uin/DealName 等）
      }
    国际版的每日活跃积分以「新建一个 30/50 分的 Bonus Pack」形式发放，
    而不是在旧套餐里加数；因此判断今日是否到账必须看套餐列表，不能只看总余额。
    """
    now = time.localtime()
    begin = time.strftime("%Y-%m-%d %H:%M:%S", now)
    end = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + 101 * 365 * 86400))
    body = {
        "PageNumber": 1,
        "PageSize": 100,
        "ProductCode": "p_tcaca",
        "Status": [0, 3],
        "PackageEndTimeRangeBegin": begin,
        "PackageEndTimeRangeEnd": end,
    }
    h = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token,
    }
    if uid:
        h["X-User-Id"] = uid
    h["X-Domain"] = domain
    resp = None
    last_err = ""
    # 国际版 billing 在 workbuddy.ai 上可用（实测）；codebuddy.ai 作为历史回退。
    for host in (GLOBAL_BASE, GLOBAL_BILLING):
        st, resp, raw = http_json(host + POINTS_PATH, "POST", h, body)
        if isinstance(resp, dict):
            break
        last_err = "HTTP %s：%s" % (st, raw[:120])
    if not isinstance(resp, dict):
        return None, "积分接口返回非 JSON（%s）" % last_err
    if resp.get("code") not in (0, None):
        return None, "积分查询失败 code=%s msg=%s" % (
            resp.get("code"), str(resp.get("msg") or "")[:120])
    data = resp.get("data") or {}
    inner = ((data.get("Response") or {}).get("Data") or {}) if isinstance(data, dict) else {}
    accounts = inner.get("Accounts") or []

    packs = []
    total = 0
    found = False
    for p in accounts:
        if not isinstance(p, dict):
            continue
        remain = p.get("CycleCapacityRemain")
        if not isinstance(remain, (int, float)):
            remain = p.get("CapacityRemain")
        size = p.get("CycleCapacitySize")
        if not isinstance(size, (int, float)):
            size = p.get("CapacitySize")
        used = p.get("CycleCapacityUsed")
        if not isinstance(used, (int, float)):
            used = p.get("CapacityUsed")
        if isinstance(remain, (int, float)):
            total += int(remain)
            found = True
        packs.append({
            "name": p.get("PackageName"),
            "code": p.get("PackageCode"),
            "size": int(size) if isinstance(size, (int, float)) else None,
            "remain": int(remain) if isinstance(remain, (int, float)) else None,
            "used": int(used) if isinstance(used, (int, float)) else None,
            "start": p.get("CycleStartTime"),
            "end": p.get("CycleEndTime"),
        })
    packs.sort(key=lambda x: (x.get("start") or "", x.get("name") or ""))
    return {"total_remain": (total if found else None), "packs": packs}, None


def daily_grant(packs, day=None):
    """从套餐明细里找出「今天新发的每日活跃包」。

    判定：CycleStartTime 落在今天，且 CapacitySize 属于 30/50 这一档。
    返回命中的套餐 dict，没有则 None。
    """
    day = day or time.strftime("%Y-%m-%d")
    for p in packs or []:
        start = p.get("start") or ""
        if not start.startswith(day):
            continue
        if p.get("size") in (30, 50):
            return p
    return None


# ---------------------------------------------------------------- 活跃链路

def create_conversation(token, uid, domain, enterprise_id, session_id, model):
    body = {
        "type": "local",
        "sessionId": session_id,
        "name": "新任务",
        "conversationOrigin": "legacy_workbuddy_local",
        "workDir": "",
        "isPlayground": 1,
        "createdAtMs": int(time.time() * 1000),
        "updatedAtMs": int(time.time() * 1000),
        "lastActivityAtMs": int(time.time() * 1000),
        "clientContext": {
            "localStatus": "active",
            "hostId": machine_id(),
            "sessionKind": "manual",
            "model": model,
            "sourceMode": "",
            "permissionMode": "",
            "expert": {"id": "", "locale": "", "runtimeIdentity": "", "marketplace": ""},
        },
    }
    h = auth_headers(token, uid, domain, enterprise_id)
    h["X-Request-ID"] = no_dash(new_uuid())
    st, resp, raw = http_json(GLOBAL_BASE + CONVERSATION_PATH, "POST", h, body)
    if isinstance(resp, dict) and isinstance(resp.get("data"), dict):
        return resp["data"].get("id") or "", None
    return "", "会话登记失败 HTTP %s %s" % (
        st, str((resp or {}).get("msg") if isinstance(resp, dict) else raw)[:120])


def chat_text(raw_content):
    if isinstance(raw_content, str):
        return raw_content
    if isinstance(raw_content, list):
        out = []
        for b in raw_content:
            if isinstance(b, dict) and isinstance(b.get("text"), str):
                out.append(b["text"])
        return "".join(out)
    return ""


def validate_stream(raw):
    """解析 SSE/整段 JSON，返回 (saw_answer, snippet, err)。"""
    saw = False
    snippet = ""
    lines = raw.replace("\r\n", "\n").split("\n")
    has_sse = any(l.startswith("data:") or l.startswith("event:") for l in lines)
    blocks = []
    if not has_sse:
        blocks.append(("", raw.strip()))
    else:
        event, data_lines = "", []
        for line in lines:
            if line == "":
                if data_lines:
                    blocks.append((event, "\n".join(data_lines)))
                    event, data_lines = "", []
            elif line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].strip())
        if data_lines:
            blocks.append((event, "\n".join(data_lines)))

    for event, data in blocks:
        if not data or data == "[DONE]":
            continue
        if not snippet:
            snippet = data[:160]
        try:
            pkt = json.loads(data)
        except Exception:
            return saw, snippet, "对话流包含无效 JSON"
        if isinstance(pkt, dict) and pkt.get("code") not in (0, None):
            return saw, snippet, "对话流业务错误 code=%s msg=%s" % (
                pkt.get("code"), str(pkt.get("msg") or "")[:120])
        if event == "error":
            return saw, snippet, "对话流返回 error 事件"
        choices = pkt.get("choices") if isinstance(pkt, dict) else None
        for c in choices or []:
            if not isinstance(c, dict):
                continue
            for node in (c.get("delta") or {}, c.get("message") or {}):
                if chat_text(node.get("content")).strip():
                    saw = True
                if (node.get("reasoning_content") or node.get("reasoning") or "").strip():
                    saw = True
            if (c.get("text") or "").strip():
                saw = True
    return saw, snippet, None


def active_chat(token, uid, domain, enterprise_id, model, prompt, conv_id=None):
    session_id = new_uuid()
    req_id = no_dash(new_uuid())
    if not conv_id:
        conv_id = session_id
    growth = [{
        "eventCode": "chat_request_send",
        "id": session_id,
        "extra": {
            "inputLength": len(prompt),
            "requestModelId": model,
            "requestModelName": model,
            "mode": "craft",
            "command": "",
            "expertId": "",
            "recommendId": "",
            "skillId": "",
            "skillCount": 0,
            "totalCount": 0,
            "rootRequestId": req_id,
            "parentConversationId": session_id,
            "agentName": "craft",
            "agentType": "default",
        },
    }]
    body = {
        "model": model,
        "stream": True,
        "max_tokens": 4096,
        "extra_vars": {"growthEvent": json.dumps(growth, ensure_ascii=False)},
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": [{"type": "text",
                                          "text": "<user_query> " + prompt + " </user_query>"}]},
        ],
    }
    h = auth_headers(token, uid, domain, enterprise_id)
    h["Accept"] = "text/event-stream"
    h["X-Conversation-ID"] = conv_id
    h["X-Conversation-Request-ID"] = req_id
    h["X-Conversation-Message-ID"] = no_dash(new_uuid())
    h["X-Request-ID"] = no_dash(new_uuid())
    h["X-Agent-Intent"] = "craft"
    st, _, raw = http_json(GLOBAL_BASE + CHAT_PATH, "POST", h, body)
    if st < 200 or st >= 300:
        try:
            env = json.loads(raw)
            return False, "对话请求 HTTP %s code=%s msg=%s" % (
                st, env.get("code"), str(env.get("msg") or "")[:160]), conv_id, req_id, session_id
        except Exception:
            return False, "对话请求 HTTP %s" % st, conv_id, req_id, session_id
    saw, snippet, err = validate_stream(raw)
    if err:
        return False, err, conv_id, req_id, session_id
    if not saw:
        return False, "对话未返回有效回答（片段：%s）" % snippet, conv_id, req_id, session_id
    return True, None, conv_id, req_id, session_id


def report_event(token, uid, domain, enterprise_id, nickname, prompt, model, conv_id, req_id):
    now_ms = int(time.time() * 1000)
    event = {
        "eventCode": "chat_request_send",
        "timestamp": now_ms,
        "reportDelay": 0,
        "ideType": INTL_NAME,
        "ideName": INTL_NAME,
        "ideVersion": INTL_VER,
        "machineId": machine_id(),
        "sessionId": conv_id,
        "userId": uid,
        "username": nickname,
        "userNickname": nickname,
        "enterpriseId": enterprise_id,
        "extName": "workbuddy-desktop",
        "extVersion": INTL_VER,
        "downloadChannel": "official",
        "userAgent": INTL_UA,
        "mode": "craft",
        "conversationId": conv_id,
        "requestId": req_id,
        "inputLength": len(prompt),
        "requestModelId": model,
        "requestModelName": model,
        "isPlan": False,
        "isAutoExecuteTerminal": False,
        "isAutoModify": False,
        "codebaseEnable": False,
        "maxToken": 0,
        "maxSteps": 0,
        "temperature": 0,
        "maxRetries": 0,
        "mentionContexts": [],
        "knowledgeId": [],
        "knowledgeName": [],
        "codebaseId": "",
        "mentionContextCount": 0,
        "command": "",
        "expertId": "",
        "recommendId": "",
        "skillId": "",
        "skillCount": 0,
        "totalCount": 0,
        "fileUri": "",
        "presentAt": now_ms,
        "rootRequestId": req_id,
        "parentConversationId": conv_id,
        "agentName": "craft",
        "agentType": "default",
    }
    h = {
        "Content-Type": "application/json;charset=UTF-8",
        "Accept": "application/json, text/plain, */*",
        "X-Request-ID": no_dash(new_uuid()),
        "X-Product": "SaaS",
        "User-Agent": INTL_UA,
        "Authorization": "Bearer " + token,
        "X-Domain": domain,
    }
    if uid:
        h["X-User-Id"] = uid
    if enterprise_id:
        h["X-Enterprise-Id"] = enterprise_id
        h["X-Tenant-Id"] = enterprise_id
    st, resp, raw = http_json(GLOBAL_BASE + REPORT_PATH, "POST", h, [event])
    if st < 200 or st >= 300:
        return "遥测上报 HTTP %s" % st
    if isinstance(resp, dict) and resp.get("code") not in (0, None):
        return "遥测上报 code=%s" % resp.get("code")
    return None


# ---------------------------------------------------------------- 推送

PUSH_UA = "WorkBuddy-Intl-Checkin/1.0"


def notify_via_wecom(webhook, title, content):
    """企业微信群机器人：markdown 消息，标题并入正文。"""
    payload = {"msgtype": "markdown", "markdown": {"content": content}}
    st, resp, raw = http_json(webhook, "POST",
                              {"Content-Type": "application/json",
                               "User-Agent": PUSH_UA}, payload)
    errcode = resp.get("errcode") if isinstance(resp, dict) else None
    if st < 200 or st >= 300:
        return "wecom:%s/%s" % (st, str(raw)[:80])
    return "wecom:%s/%s" % (st, errcode)


def notify_via_pushplus(token, title, content):
    payload = {"token": token, "title": title, "content": content, "template": "markdown"}
    st, resp, raw = http_json("https://www.pushplus.plus/send", "POST",
                              {"Content-Type": "application/json",
                               "User-Agent": PUSH_UA}, payload)
    code = resp.get("code") if isinstance(resp, dict) else None
    if st < 200 or st >= 300:
        return "pushplus:%s/%s" % (st, str(raw)[:80])
    return "pushplus:%s/%s" % (st, code)


def notify_via_bark(bark_url, title, content):
    """Bark：GET <base>/<urlencode(title)>/<urlencode(content)>。"""
    base = bark_url.rstrip("/")
    url = "%s/%s/%s" % (base, urllib.parse.quote(title), urllib.parse.quote(content))
    st, resp, raw = http_json(url, "GET", {"User-Agent": PUSH_UA})
    code = resp.get("code") if isinstance(resp, dict) else None
    if st < 200 or st >= 300:
        return "bark:%s/%s" % (st, str(raw)[:80])
    return "bark:%s/%s" % (st, code)


def notify_via_serverchan(sendkey, title, content):
    """Server酱：SCT 开头走 Turbo（title/desp），SCU 开头走旧版（text/desp）。"""
    if sendkey.startswith("SCU"):
        url = "https://sc.ftqq.com/%s.send" % sendkey
        form = {"text": title, "desp": content}
    else:
        url = "https://sctapi.ftqq.com/%s.send" % sendkey
        form = {"title": title, "desp": content}
    data = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", PUSH_UA)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            txt = resp.read(65536).decode("utf-8", "replace")
            try:
                code = json.loads(txt).get("code")
            except Exception:
                code = None
            if resp.status < 200 or resp.status >= 300:
                return "serverchan:%s/%s" % (resp.status, txt[:80])
            return "serverchan:%s/%s" % (resp.status, code)
    except urllib.error.HTTPError as e:
        return "serverchan:%s/%s" % (e.code, e.read(4096).decode("utf-8", "replace")[:80])
    except Exception as e:
        return "serverchan_err:%s" % str(e)[:120]


def _dispatch_channels(title, content):
    """按环境变量向所有已启用通道推送，返回结果列表（不含任何密钥）。

    顺序：企微 → PushPlus → Bark → Server酱。未配置的通道直接跳过。
    """
    results = []

    webhook = (os.environ.get("WECOM_WEBHOOK") or "").strip()
    if webhook:
        try:
            results.append(notify_via_wecom(webhook, title, content))
        except Exception as e:
            results.append("wecom_err:%s" % str(e)[:120])

    token = (os.environ.get("PUSHPLUS_TOKEN") or "").strip()
    if token:
        try:
            results.append(notify_via_pushplus(token, title, content))
        except Exception as e:
            results.append("pushplus_err:%s" % str(e)[:120])

    bark = (os.environ.get("BARK_URL") or "").strip()
    if bark:
        try:
            results.append(notify_via_bark(bark, title, content))
        except Exception as e:
            results.append("bark_err:%s" % str(e)[:120])

    sc = (os.environ.get("SERVERCHAN_SENDKEY") or "").strip()
    if sc:
        try:
            results.append(notify_via_serverchan(sc, title, content))
        except Exception as e:
            results.append("serverchan_err:%s" % str(e)[:120])

    return results


# ---------------------------------------------------------------- 主流程

def run():
    rt = (os.environ.get("WB_INTL_REFRESH_TOKEN") or "").strip()
    uid = (os.environ.get("WB_INTL_UID") or "").strip()
    domain = (os.environ.get("WB_INTL_DOMAIN") or "www.workbuddy.ai").strip()
    enterprise = (os.environ.get("WB_INTL_ENTERPRISE_ID") or "").strip()
    nickname = (os.environ.get("WB_INTL_NICKNAME") or "").strip()
    model = (os.environ.get("WB_INTL_MODEL") or "hy3").strip()
    prompt = (os.environ.get("WB_INTL_PROMPT") or DEFAULT_PROMPT).strip()
    res = {"status": "unknown", "action": None, "model": model,
           "balance_before": None, "balance_after": None, "msg": "", "detail": {}}

    if not rt:
        res.update(status="error", msg="未配置 WB_INTL_REFRESH_TOKEN（国际版长效令牌）")
        res["detail"]["credential"] = "<empty>"
        return res
    if not uid:
        uid = uid_from_jwt(rt)
        if uid:
            res["detail"]["uid_source"] = "jwt"
    if not uid:
        res.update(status="error",
                   msg="缺少 WB_INTL_UID，且无法从令牌解析；请在 Secret 中补充账号 UID")
        return res

    at, new_rt, new_domain, err = refresh_token(rt, domain)
    if err:
        res.update(status="error", msg=err)
        return res
    domain = new_domain or domain
    res["detail"].update({
        "credential": "refresh_token（国际版长效令牌）",
        "token_masked": mask(at),
        "domain": domain,
        "rt_rotated": bool(new_rt and new_rt != rt),
    })

    before, perr = points_detail(at, uid, domain)
    res["balance_before"] = (before or {}).get("total_remain")
    if perr:
        res["detail"]["points_before_error"] = perr

    conv_id, cerr = create_conversation(at, uid, domain, enterprise, new_uuid(), model)
    if cerr:
        res["detail"]["conversation_warning"] = cerr

    ok, aerr, conv_id, req_id, session_id = active_chat(
        at, uid, domain, enterprise, model, prompt, conv_id or None)
    if not ok:
        res.update(status="error", action="failed", msg=aerr)
        return res

    rerr = report_event(at, uid, domain, enterprise, nickname, prompt, model, conv_id, req_id)
    if rerr:
        res["detail"]["report_warning"] = rerr

    after, perr2 = points_detail(at, uid, domain)
    res["balance_after"] = (after or {}).get("total_remain")
    if perr2:
        res["detail"]["points_after_error"] = perr2

    delta = None
    if isinstance(res["balance_before"], int) and isinstance(res["balance_after"], int):
        delta = res["balance_after"] - res["balance_before"]

    # 每日活跃积分是「新建一个 30/50 分的 Bonus Pack」，不是旧套餐加数。
    # 服务端异步发放，当场看不到属正常；只要当天最终出现该包即算到账。
    packs = (after or {}).get("packs") or []
    grant = daily_grant(packs)
    today_packs = [p for p in packs
                   if (p.get("start") or "").startswith(time.strftime("%Y-%m-%d"))]
    res.update(status="ok", action="active_chat_sent",
               msg="已发送一次有效对话；每日活跃积分由服务端异步发放")
    res["detail"]["balance_delta"] = delta
    res["detail"]["daily_grant"] = grant
    res["detail"]["daily_grant_received"] = bool(grant)
    res["detail"]["today_packs"] = today_packs
    res["detail"]["pack_count"] = len(packs)
    res["detail"]["conversation_id"] = conv_id
    res["detail"]["prompt_length"] = len(prompt)
    res["detail"]["machine_id"] = machine_id()
    return res


def main():
    res = run()
    # 推送：失败始终推；成功按 SUCCESS_NOTIFY
    if res.get("status") == "ok" and not truthy(os.environ.get("SUCCESS_NOTIFY")):
        pass
    elif res.get("status") == "ok":
        d = res.get("detail") or {}
        grant = d.get("daily_grant")
        if grant:
            grant_line = "> **今日积分**：+%s（%s 起生效）\n\n" % (
                grant.get("size"), grant.get("start"))
        else:
            grant_line = "> **今日积分**：尚未到账，服务端异步发放，通常数分钟内\n\n"
        res["detail"]["notify"] = _dispatch_channels(
            "✅ WorkBuddy AI 国际版 · 活跃已发送",
            "### ✅ WorkBuddy AI 国际版 · 活跃已发送\n\n"
            "> **时间**：%s\n\n> **模型**：%s\n\n"
            "%s> **余额**：%s → %s\n\n"
            "> **说明**：活跃已上报，积分以「新建 Bonus Pack」形式发放。\n"
            % (now_local(), res.get("model"), grant_line,
               res.get("balance_before"), res.get("balance_after")))
    else:
        res["detail"]["notify"] = _dispatch_channels(
            "❌ WorkBuddy AI 国际版 · 活跃失败",
            "### ❌ WorkBuddy AI 国际版 · 活跃失败\n\n"
            "> **时间**：%s\n\n> **原因**：%s\n\n"
            "> **处理**：检查 WB_INTL_REFRESH_TOKEN / WB_INTL_UID 是否失效。\n"
            % (now_local(), res.get("msg")))

    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("status") == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
