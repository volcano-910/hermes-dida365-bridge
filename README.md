# Hermes Dida365 Bridge

滴答清单与中国版 API 的 OAuth2 桥接脚本，支持任务 CRUD 与飞书双向同步。

## 功能

- OAuth2 授权（中国版 dida365.com）
- 项目/任务 CRUD
- 飞书 ↔ 滴答 双向同步
- 自动 SSL 绕过（适配 MacPacket 等代理）

## 安装

```bash
cp ticktick-bridge.py ~/.hermes/scripts/
```

## 配置

创建 `~/.hermes/ticktick.env`：
```
TICKTICK_CLIENT_ID=xxx
TICKTICK_CLIENT_SECRET=xxx
TICKTICK_REDIRECT_URI=http://localhost:8765/callback
DIDA365=true
```

## 用法

```bash
python3 ticktick-bridge.py auth              # OAuth 授权
python3 ticktick-bridge.py status            # 状态检查
python3 ticktick-bridge.py list-projects     # 列项目
python3 ticktick-bridge.py list-tasks        # 列任务
python3 ticktick-bridge.py create ...        # 创建任务
python3 ticktick-bridge.py complete ...      # 完成任务
python3 ticktick-bridge.py sync             # 双向同步
```
