#!/usr/bin/env python3
"""
TickTick ↔ 飞书任务 双向同步桥接脚本

用法:
  python3 ticktick-bridge.py auth              # OAuth2 授权（获取 token）
  python3 ticktick-bridge.py status             # 检查 token 状态
  python3 ticktick-bridge.py list-projects      # 列取滴答项目
  python3 ticktick-bridge.py list-tasks [--project-id X]   # 列取滴答任务
  python3 ticktick-bridge.py create --title "xxx" --project-id X [--due "2026-06-20"]
  python3 ticktick-bridge.py complete --task-id X --project-id Y
  python3 ticktick-bridge.py sync               # 双向同步（飞书↔滴答）

首次使用:
  1. 先去 https://developer.dida365.com/manage 创建应用
     （滴答清单中国版用户用这个，国际版用 developer.ticktick.com）
  2. 拿到 client_id 和 client_secret
  3. 创建 .env 文件: ~/.hermes/ticktick.env
     TICKTICK_CLIENT_ID=xxx
     TICKTICK_CLIENT_SECRET=***
     TICKTICK_REDIRECT_URI=http://localhost:8765/callback
     # 中国版用户加这行：
     DIDA365=true
  4. 运行 python3 ticktick-bridge.py auth
"""

import json
import os
import sys
import time
import hashlib
import secrets
import urllib.parse
import urllib.request
import urllib.error
import subprocess
import http.server
import threading
import base64
from pathlib import Path
from datetime import datetime, timezone, timedelta

# ──────────────────────────────────────────────
# 配置路径
# ──────────────────────────────────────────────
HERMES_DIR = Path.home() / ".hermes"
ENV_FILE = HERMES_DIR / "ticktick.env"
TOKEN_FILE = HERMES_DIR / "ticktick_token.json"
SYNC_STATE_FILE = HERMES_DIR / "ticktick_sync_state.json"

# 飞书任务清单名称（用于同步，滴答任务会同步到这个清单）
FEISHU_TASKLIST_NAME = "滴答同步"

# 同步方向标记: 在任务标题/描述中加入标记避免循环同步
SYNC_MARKER = "🔗"

# TickTick / Dida365 API
# 自动检测: 如果 ENV 中设置了 DID365=true 则使用中国版 API
DIDA365 = os.environ.get("DIDA365", "true").lower() in ("1", "true", "yes")
TICKTICK_API = "https://api.dida365.com" if DIDA365 else "https://api.ticktick.com"
TICKTICK_OAUTH_AUTHORIZE = "https://dida365.com/oauth/authorize" if DIDA365 else "https://ticktick.com/oauth/authorize"
TICKTICK_OAUTH_TOKEN = "https://dida365.com/oauth/token" if DIDA365 else "https://ticktick.com/oauth/token"

# ──────────────────────────────────────────────
# 工具函数
# ──────────────────────────────────────────────

def load_env():
    """加载 .env 文件"""
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def load_token():
    """加载 OAuth token"""
    if TOKEN_FILE.exists():
        try:
            return json.loads(TOKEN_FILE.read_text())
        except (json.JSONDecodeError, KeyError):
            pass
    return None


def save_token(data):
    """保存 OAuth token"""
    TOKEN_FILE.write_text(json.dumps(data, indent=2))


def load_sync_state():
    """加载同步状态（记录已同步任务 ID 映射）"""
    if SYNC_STATE_FILE.exists():
        try:
            return json.loads(SYNC_STATE_FILE.read_text())
        except json.JSONDecodeError:
            pass
    return {"ticktick_to_feishu": {}, "feishu_to_ticktick": {}, "last_sync": None}


def save_sync_state(state):
    """保存同步状态"""
    SYNC_STATE_FILE.write_text(json.dumps(state, indent=2))


# SSL 上下文 (跳过验证，因为 MacPacket 代理会拦截证书)
_SSL_CTX = None

def _get_ssl_ctx():
    global _SSL_CTX
    if _SSL_CTX is None:
        import ssl as _ssl
        _SSL_CTX = _ssl.create_default_context()
        _SSL_CTX.check_hostname = False
        _SSL_CTX.verify_mode = _ssl.CERT_NONE
    return _SSL_CTX


def http_request(method, url, headers=None, body=None, expect_status=200):
    """简单的 HTTP 请求，使用 urllib"""
    req = urllib.request.Request(url, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if body:
        data = json.dumps(body).encode("utf-8") if isinstance(body, (dict, list)) else body
        req.add_header("Content-Type", "application/json")
    else:
        data = None

    try:
        with urllib.request.urlopen(req, data=data, timeout=30, context=_get_ssl_ctx()) as resp:
            resp_body = resp.read().decode("utf-8")
            if resp.status != expect_status and expect_status != 0:
                print(f"⚠ HTTP {resp.status}: {resp_body[:200]}", file=sys.stderr)
            return resp.status, (json.loads(resp_body) if resp_body else {})
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8") if e.fp else ""
        return e.code, {"error": err_body}
    except Exception as e:
        return 0, {"error": str(e)}


def run_larkcli(*args):
    """运行 lark-cli 命令，返回 (exit_code, stdout_json)"""
    cmd = ["lark-cli"] + list(args) + ["--json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0 and result.returncode != 10:
            return result.returncode, {"error": result.stderr.strip(), "cmd": " ".join(cmd)}
        try:
            return result.returncode, json.loads(result.stdout) if result.stdout.strip() else {}
        except json.JSONDecodeError:
            return result.returncode, {"raw": result.stdout.strip(), "error_raw": result.stderr.strip()}
    except subprocess.TimeoutExpired:
        return -1, {"error": "timeout"}
    except FileNotFoundError:
        return -1, {"error": "lark-cli not found. Install it first."}


def get_ticktick_client():
    """获取已认证的 TickTick API 客户端"""
    token_data = load_token()
    if not token_data or "access_token" not in token_data:
        die("❌ 未授权。请先运行: python3 ticktick-bridge.py auth")

    # 简单地检查 token 是否可用（TickTick 的 token 过期时间未明确文档化）
    # 如果 API 返回 401，则需要重新授权
    return token_data["access_token"]


def die(msg):
    """打印错误并退出"""
    print(msg, file=sys.stderr)
    sys.exit(1)


# ──────────────────────────────────────────────
# TickTick API 方法
# ──────────────────────────────────────────────

def ticktick_api(method, path, body=None, expect_status=200):
    """调用 TickTick API"""
    token = get_ticktick_client()
    url = f"{TICKTICK_API}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
    }
    status, data = http_request(method, url, headers, body, expect_status)
    if status == 401:
        die("❌ Token 已过期或无效，请重新授权: python3 ticktick-bridge.py auth")
    if status == 403:
        die(f"❌ 权限不足 (403): {data.get('error', data)}")
    if status not in (expect_status, 200, 201) and status != 0:
        print(f"⚠ API 返回 {status}: {data.get('error', str(data)[:200])}", file=sys.stderr)
    return data


def ticktick_list_projects():
    """列取所有项目"""
    return ticktick_api("GET", "/open/v1/project")


def ticktick_list_tasks(project_id=None):
    """列取未完成任务"""
    if project_id:
        data = ticktick_api("POST", "/open/v1/task/filter", {
            "projectIds": [project_id],
            "status": [0]  # 0 = 未完成
        })
    else:
        # 获取所有项目的任务
        projects = ticktick_list_projects()
        all_tasks = []
        for proj in projects:
            tasks = ticktick_api("POST", "/open/v1/task/filter", {
                "projectIds": [proj["id"]],
                "status": [0]
            })
            if isinstance(tasks, list):
                for t in tasks:
                    t["_projectName"] = proj.get("name", "")
                all_tasks.extend(tasks)
        return all_tasks
    return data if isinstance(data, list) else []


def ticktick_list_completed(project_id, start_date=None, end_date=None):
    """列取已完成任务"""
    body = {}
    if project_id:
        body["projectIds"] = [project_id]
    if start_date:
        body["startDate"] = start_date
    if end_date:
        body["endDate"] = end_date
    data = ticktick_api("POST", "/open/v1/task/completed", body)
    return data if isinstance(data, list) else []


def ticktick_create_task(title, project_id, content=None, due_date=None, priority=0,
                         tags=None, start_date=None):
    """创建任务"""
    body = {
        "title": title,
        "projectId": project_id,
        "priority": priority,
    }
    if content:
        body["content"] = content
    if due_date:
        body["dueDate"] = due_date
    if start_date:
        body["startDate"] = start_date
    if tags:
        body["tags"] = tags

    # 时区设为 Asia/Shanghai
    body["timeZone"] = "Asia/Shanghai"

    return ticktick_api("POST", "/open/v1/task", body, expect_status=200)


def ticktick_update_task(task_id, project_id, updates):
    """更新任务"""
    body = {"id": task_id, "projectId": project_id}
    body.update(updates)
    # Note: TickTick Update Task uses POST /open/v1/task/{taskId}
    return ticktick_api("POST", f"/open/v1/task/{task_id}", body, expect_status=200)


def ticktick_complete_task(task_id, project_id):
    """完成任务"""
    return ticktick_api("POST", f"/open/v1/project/{project_id}/task/{task_id}/complete",
                        expect_status=200)


def ticktick_delete_task(task_id, project_id):
    """删除任务"""
    return ticktick_api("DELETE", f"/open/v1/project/{project_id}/task/{task_id}",
                        expect_status=200)


# ──────────────────────────────────────────────
# 飞书任务操作（通过 lark-cli）
# ──────────────────────────────────────────────

def feishu_get_or_create_tasklist():
    """获取或创建同步用的飞书任务清单"""
    # 列取现有清单
    exit_code, result = run_larkcli("task", "tasklists", "list", "--as", "user")

    if exit_code != 0:
        print(f"⚠ 获取飞书清单失败: {result}", file=sys.stderr)
        return None

    tasklists = result.get("data", {}).get("items", []) if "data" in result else result.get("items", [])
    if isinstance(tasklists, dict):
        tasklists = tasklists.get("items", tasklists.get("tasklists", []))

    # 查找已有清单
    for tl in tasklists:
        if isinstance(tl, dict) and tl.get("name") == FEISHU_TASKLIST_NAME:
            return tl.get("guid") or tl.get("id")

    # 不存在则创建
    exit_code, result = run_larkcli("task", "tasklists", "create", "--as", "user",
                                    "--data", json.dumps({"name": FEISHU_TASKLIST_NAME}))
    if exit_code != 0:
        print(f"⚠ 创建飞书清单失败: {result}", file=sys.stderr)
        return None

    data = result.get("data", result)
    if isinstance(data, dict):
        return data.get("guid") or data.get("id")
    return None


def feishu_list_tasks(tasklist_guid):
    """列取飞书任务清单中的未完成任务"""
    exit_code, result = run_larkcli("task", "tasklists", "tasks", "--as", "user",
                                    "--params", json.dumps({"tasklist_guid": tasklist_guid}))
    if exit_code != 0:
        print(f"⚠ 获取飞书任务列表失败: {result}", file=sys.stderr)
        return []

    tasks = result.get("data", {}).get("items", []) if "data" in result else result.get("items", [])
    if isinstance(tasks, dict):
        tasks = tasks.get("items", tasks.get("tasks", []))
    if not isinstance(tasks, list):
        return []

    # 过滤: 只取未完成的
    active = []
    for t in tasks:
        if isinstance(t, dict):
            is_done = t.get("status") == "done" or t.get("is_completed") or t.get("completed")
            if not is_done:
                active.append(t)
    return active


def feishu_create_task(tasklist_guid, title, description=None, due_date=None):
    """在飞书中创建任务"""
    body = {
        "tasklists": [{"tasklist_guid": tasklist_guid}],
        "summary": title,
    }
    if description:
        body["description"] = description

    exit_code, result = run_larkcli("task", "tasks", "create", "--as", "user",
                                    "--data", json.dumps(body))
    if exit_code != 0:
        print(f"⚠ 创建飞书任务失败: {result}", file=sys.stderr)
        return None

    data = result.get("data", result)
    if isinstance(data, dict):
        # API v2 返回 {data: {task: {...}}}
        task = data.get("task", data)
        return task.get("guid") or task.get("id") or task
    return data


def feishu_complete_task(task_guid):
    """完成飞书任务"""
    exit_code, result = run_larkcli("task", "tasks", "patch", "--as", "user",
                                    "--params", json.dumps({"task_guid": task_guid}),
                                    "--data", json.dumps({"is_completed": True}))
    if exit_code != 0:
        print(f"⚠ 完成飞书任务失败: {result}", file=sys.stderr)
        return False
    return True


def feishu_delete_task(task_guid):
    """删除飞书任务"""
    exit_code, result = run_larkcli("task", "tasks", "delete", "--as", "user",
                                    "--params", json.dumps({"task_guid": task_guid}))
    if exit_code != 0:
        print(f"⚠ 删除飞书任务失败: {result}", file=sys.stderr)
        return False
    return True


# ──────────────────────────────────────────────
# OAuth 授权流程
# ──────────────────────────────────────────────

def do_auth():
    """执行 OAuth2 授权"""
    env = load_env()
    client_id = env.get("TICKTICK_CLIENT_ID")
    client_secret = env.get("TICKTICK_CLIENT_SECRET")
    redirect_uri = env.get("TICKTICK_REDIRECT_URI", "http://localhost:8765/callback")

    if not client_id or not client_secret:
        die("""❌ 缺少配置。请先创建 ~/.hermes/ticktick.env：

TICKTICK_CLIENT_ID=你的client_id
TICKTICK_CLIENT_SECRET=你的client_secret
TICKTICK_REDIRECT_URI=http://localhost:8765/callback

如何获取：
  1. 打开 https://developer.ticktick.com/manage
  2. 点击 "New App"，填写应用名称和回调地址 http://localhost:8765/callback
  3. 复制生成的 client_id 和 client_secret
""")

    state = secrets.token_urlsafe(16)

    # 构建授权 URL
    params = {
        "client_id": client_id,
        "scope": "tasks:write tasks:read",
        "state": state,
        "redirect_uri": redirect_uri,
        "response_type": "code",
    }
    auth_url = f"{TICKTICK_OAUTH_AUTHORIZE}?{urllib.parse.urlencode(params)}"

    # 用于在线程间传递授权码
    auth_code = [None]
    auth_done = threading.Event()

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            if "code" in params:
                auth_code[0] = params["code"][0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write("<html><body><h1>✅ 授权成功！</h1><p>可以关闭此页面。</p></body></html>".encode("utf-8"))
                auth_done.set()
            else:
                self.send_response(400)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write("<html><body><h1>❌ 授权失败</h1><p>未收到授权码。</p></body></html>".encode("utf-8"))

        def log_message(self, format, *args):
            pass  # 静默 HTTP 日志

    # 启动本地回调服务器
    port = int(redirect_uri.split(":")[-1].split("/")[0])
    server = http.server.HTTPServer(("127.0.0.1", port), CallbackHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    print(f"\n🔐 请用浏览器打开以下链接完成授权：\n")
    print(f"   {auth_url}\n")
    print(f"⏳ 等待授权回调（http://localhost:{port}/callback）...")
    print(f"   如果浏览器没有自动跳转回来，请确保应用的回调地址配置正确。\n")

    # 等待回调（最多 5 分钟）
    if not auth_done.wait(timeout=300):
        server.shutdown()
        die("\n❌ 授权超时（5分钟），请重试。")

    server.shutdown()
    code = auth_code[0]

    if not code:
        die("❌ 未收到授权码。")

    print("✅ 收到授权码，正在交换 token...")

    # 交换 token
    token_body = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "scope": "tasks:write tasks:read",
        "redirect_uri": redirect_uri,
    }).encode("utf-8")

    req = urllib.request.Request(
        TICKTICK_OAUTH_TOKEN,
        data=token_body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic " + base64.b64encode(
                f"{client_id}:{client_secret}".encode()
            ).decode(),
        }
    )

    # 跳过 SSL 验证 (MacPacket 代理会拦截证书)
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            token_data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8")
        die(f"❌ Token 交换失败: {err}")
    except Exception as e:
        die(f"❌ Token 交换失败: {e}")

    if "access_token" not in token_data:
        die(f"❌ Token 响应异常: {token_data}")

    # 保存 token
    token_data["_obtained_at"] = datetime.now(timezone.utc).isoformat()
    save_token(token_data)

    print("✅ 授权成功！Token 已保存。")
    print(f"   Access Token: {token_data['access_token'][:12]}...")

    # 列一下项目试试
    print("\n📋 你的滴答清单项目：")
    try:
        # 需要直接测试 API
        projects = ticktick_list_projects_no_auth(token_data["access_token"])
        for i, p in enumerate(projects):
            print(f"   [{i+1}] {p.get('name', '(未命名)')}  (id: {p['id']})  kind: {p.get('kind', 'TASK')}")
    except Exception as e:
        print(f"   ⚠ 获取项目列表失败: {e}")
        print("   这不影响授权，可以后续再排查。")


def ticktick_list_projects_no_auth(access_token):
    """列取项目（直接使用 access_token，不检查本地缓存）"""
    status, data = http_request("GET", f"{TICKTICK_API}/open/v1/project", {
        "Authorization": f"Bearer {access_token}"
    })
    return data if isinstance(data, list) else []


# ──────────────────────────────────────────────
# 同步逻辑
# ──────────────────────────────────────────────

def build_task_key(title):
    """构建任务匹配键（用于去重/匹配）"""
    # 去除同步标记后标准化
    clean = title.replace(SYNC_MARKER, "").strip().lower()
    return clean


def sync_bidirectional():
    """双向同步：飞书 ↔ 滴答清单"""
    print("🔄 开始双向同步...")
    print()

    # 1. 获取飞书任务清单
    print("📋 获取飞书任务清单...")
    fl_guid = feishu_get_or_create_tasklist()
    if not fl_guid:
        die("❌ 无法获取或创建飞书任务清单。")
    print(f"   ✅ 飞书清单: {FEISHU_TASKLIST_NAME} ({fl_guid})")

    # 2. 获取滴答项目
    print("📋 获取滴答清单项目...")
    try:
        projects = ticktick_list_projects()
    except Exception as e:
        die(f"❌ 获取滴答项目失败: {e}")
    print(f"   ✅ 找到 {len(projects)} 个项目")

    # 3. 获取两边任务
    print("📋 获取滴答任务...")
    try:
        tt_tasks = ticktick_list_tasks()
    except Exception as e:
        die(f"❌ 获取滴答任务失败: {e}")
    print(f"   ✅ 滴答未完成任务: {len(tt_tasks)}")

    print("📋 获取飞书任务...")
    fl_tasks = feishu_list_tasks(fl_guid)
    print(f"   ✅ 飞书未完成任务: {len(fl_tasks)}")

    # 4. 加载同步状态
    state = load_sync_state()

    # 5. 构建任务映射
    # 滴答任务: key → task
    tt_map = {}
    for t in tt_tasks:
        title = t.get("title", "")
        key = build_task_key(title)
        tt_map[key] = t

    # 飞书任务: key → task
    fl_map = {}
    for t in fl_tasks:
        title = t.get("title") or t.get("summary", "")
        key = build_task_key(title)
        fl_map[key] = t

    created_in_feishu = 0
    created_in_ticktick = 0
    completed_in_feishu = 0
    completed_in_ticktick = 0

    # 6. 滴答 → 飞书: 滴答有但飞书没有的 → 在飞书创建
    print()
    print("➡️  滴答 → 飞书 同步中...")
    for key, tt_task in tt_map.items():
        if key not in fl_map:
            # 跳过已有映射记录的（之前同步过但被手动删除的情况，先不做复杂处理）
            title = tt_task.get("title", "")
            desc = tt_task.get("content", "") or tt_task.get("desc", "")
            project_name = tt_task.get("_projectName", "")
            due = tt_task.get("dueDate")

            fl_desc = f"{SYNC_MARKER} 来自滴答清单"
            if project_name:
                fl_desc += f" [{project_name}]"
            if desc:
                fl_desc += f"\n{desc[:200]}"

            result = feishu_create_task(fl_guid, f"{SYNC_MARKER} {title}", fl_desc)
            if result:
                created_in_feishu += 1
                print(f"   ✅ 创建飞书任务: {title}")
                # 记录映射
                state["ticktick_to_feishu"][tt_task["id"]] = result
            else:
                print(f"   ⚠ 创建飞书任务失败: {title}")

    # 7. 飞书 → 滴答: 飞书有但滴答没有的 → 在滴答创建
    print()
    print("⬅️  飞书 → 滴答 同步中...")
    if projects:
        default_project_id = projects[0]["id"]  # 使用第一个项目作为默认目标

        for key, fl_task in fl_map.items():
            if key not in tt_map:
                title = fl_task.get("title") or fl_task.get("summary", "")
                # 去掉同步标记
                clean_title = title.replace(SYNC_MARKER, "").strip()
                if not clean_title:
                    continue

                desc = fl_task.get("description", "")
                fl_guid_task = fl_task.get("guid") or fl_task.get("id", "")

                result = ticktick_create_task(
                    f"{SYNC_MARKER} {clean_title}",
                    default_project_id,
                    content=f"来自飞书任务\n{desc[:200]}" if desc else "来自飞书任务"
                )
                if result and "id" in result:
                    created_in_ticktick += 1
                    print(f"   ✅ 创建滴答任务: {clean_title}")
                    state["feishu_to_ticktick"][fl_guid_task] = result["id"]
                else:
                    print(f"   ⚠ 创建滴答任务失败: {clean_title}")

    # 8. 更新同步状态
    state["last_sync"] = datetime.now(timezone.utc).isoformat()
    save_sync_state(state)

    # 9. 输出汇总
    print()
    print("=" * 50)
    print("📊 同步完成！")
    print(f"   滴答 → 飞书 新建: {created_in_feishu} 个")
    print(f"   飞书 → 滴答 新建: {created_in_ticktick} 个")
    print(f"   最后同步: {state['last_sync']}")
    print()

    return {
        "created_in_feishu": created_in_feishu,
        "created_in_ticktick": created_in_ticktick,
    }


# ──────────────────────────────────────────────
# CLI 入口
# ──────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "auth":
        do_auth()

    elif cmd == "status":
        token_data = load_token()
        if not token_data:
            print("❌ 未授权。请先运行: python3 ticktick-bridge.py auth")
        else:
            obtained = token_data.get("_obtained_at", "未知")
            print(f"✅ 已授权")
            print(f"   Access Token: {token_data['access_token'][:12]}...")
            print(f"   获取时间: {obtained}")
            # 尝试调用 API 验证
            try:
                projects = ticktick_list_projects()
                print(f"   API 可用: ✅ ({len(projects)} 个项目)")
            except SystemExit:
                print(f"   API 可用: ❌ (Token 已过期，请重新授权)")
            except Exception as e:
                print(f"   API 可用: ⚠ ({e})")

    elif cmd == "list-projects":
        projects = ticktick_list_projects()
        print(f"📋 滴答清单项目 ({len(projects)}):")
        for i, p in enumerate(projects):
            print(f"  [{i+1}] {p.get('name', '(未命名)')}")
            print(f"      id: {p['id']}")
            print(f"      kind: {p.get('kind', 'TASK')}")
            print(f"      closed: {p.get('closed', False)}")

    elif cmd == "list-tasks":
        # 解析 --project-id
        project_id = None
        for i, a in enumerate(args):
            if a == "--project-id" and i + 1 < len(args):
                project_id = args[i + 1]
                break
        tasks = ticktick_list_tasks(project_id)
        print(f"📋 滴答未完成任务 ({len(tasks)}):")
        for t in tasks:
            title = t.get("title", "")
            due = t.get("dueDate", "")
            priority = t.get("priority", 0)
            tags = t.get("tags", [])
            print(f"  🔹 {title}")
            if due:
                print(f"     ⏰ {due}")
            if tags:
                print(f"     🏷 {', '.join(tags)}")
            print(f"     id: {t['id']}  project: {t.get('_projectName', t.get('projectId', ''))}")

    elif cmd == "create":
        # 解析参数
        params = {}
        i = 0
        while i < len(args):
            if args[i].startswith("--"):
                key = args[i][2:].replace("-", "_")
                if i + 1 < len(args) and not args[i + 1].startswith("--"):
                    params[key] = args[i + 1]
                    i += 2
                else:
                    params[key] = True
                    i += 1
            else:
                i += 1

        title = params.get("title")
        project_id = params.get("project_id")

        if not title or not project_id:
            die("用法: python3 ticktick-bridge.py create --title '任务名' --project-id XXX [--due '2026-06-20T10:00:00+0800']")

        result = ticktick_create_task(
            title=title,
            project_id=project_id,
            content=params.get("content"),
            due_date=params.get("due"),
        )
        print(f"✅ 滴答任务已创建: {result.get('title', result.get('id', result))}")

    elif cmd == "complete":
        params = {}
        i = 0
        while i < len(args):
            if args[i].startswith("--"):
                key = args[i][2:].replace("-", "_")
                if i + 1 < len(args):
                    params[key] = args[i + 1]
                    i += 2
                else:
                    params[key] = True
                    i += 1
            else:
                i += 1

        task_id = params.get("task_id")
        project_id = params.get("project_id")
        if not task_id or not project_id:
            die("用法: python3 ticktick-bridge.py complete --task-id XXX --project-id YYY")

        ticktick_complete_task(task_id, project_id)
        print(f"✅ 滴答任务已完成: {task_id}")

    elif cmd == "sync":
        sync_bidirectional()

    else:
        print(f"未知命令: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
