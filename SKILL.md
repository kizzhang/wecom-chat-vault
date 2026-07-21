---
name: wecomcracker
description: "从当前 Windows 用户自己的企业微信本地聊天中重建个人工作历史：整理有证据支持的时间线，找回任务与承诺，识别决定、期限、交付物、阻塞、依赖、已完成事项和未闭环跟进，并生成可审阅的项目管理交接预览。当企业微信 API 或 CLI 的历史范围不足时，使用零第三方 Python 依赖、Windows CNG 和不可变只读 SQLite 查询来解密、校验、检查、列出和搜索本地 wxSQLite3 数据库。不得用于其他人的账号、远程机器、绕过 Windows 权限、发送消息，或把推断出的任务直接写入外部项目系统。"
---

# WeComCracker：企微工作回溯

使用 WeComCracker 把用户自己的企业微信历史对话整理成可靠的个人工作记忆：谁提出了什么、承诺了什么、做了什么决定、交付了什么、被什么阻塞、哪些要求已被替代，以及哪些事项尚未闭环。确保每个结论都能追溯到聊天记录或用户明确授权读取的文件证据。

本版本只生成供用户审阅的工作摘要和项目交接预览。不要仅凭本 Skill 在 Vikunja、Microsoft Project 或其他外部系统中创建或更新事项。

使用 `scripts/wecomcracker.py`。该脚本只导入 Python 标准库，并调用 Windows `kernel32.dll` 和 `bcrypt.dll`。旧命令名 `scripts/wecom_chat_vault.py` 仅作为兼容入口保留。

## 安全边界

- 只在用户明确授权后处理当前 Windows 用户自己的企业微信本地数据。
- 创建快照时，保持 `WXWork.exe` 正在运行且账号处于登录状态。
- 只读取加密的源数据库；仅向独立且明确指定的输出目录写入明文快照。
- 绝不打印、返回、记录或持久化恢复出的数据库密钥或进程内存内容。
- 从解析结果中遮盖文件传输密钥及类似令牌。
- 不要禁用终端安全软件、提升到其他 Windows 会话，或更改文件系统权限。
- 将明文快照和提取出的聊天文本视为敏感数据。
- 始终选择全新的输出目录；脚本会拒绝已有路径和局部替换。

解密前，或者需要判断时效性、WAL、隐私与附件完整性时，先阅读 [references/safety-and-limitations.md](references/safety-and-limitations.md)。

## 1. 定位当前账号

先检查运行环境，再发现数据源：

```powershell
python scripts/wecomcracker.py doctor
python scripts/wecomcracker.py discover
```

如果自动发现遗漏了自定义位置，传入其配置的父目录：

```powershell
python scripts/wecomcracker.py discover --data-root 'E:\WeCom\WXWork'
```

选择 `message.db`、`session.db` 和 `user.db` 修改时间最新的 `Data` 目录。若多个账号都有可能，先询问用户再选择。

## 2. 创建经过校验的明文快照

在企业微信源目录之外选择一个全新的输出目录：

```powershell
python scripts/wecomcracker.py decrypt `
  --db-dir '<账号目录>\Data' `
  --out-dir '<全新的明文输出目录>' `
  --timeout 120 `
  --verbose
```

只要任何已识别的源数据库存在非空 WAL，该命令默认就会安全失败。只有当用户明确接受可能遗漏尚未 checkpoint 的近期记录时，才添加 `--base-only`，并将生成的快照明确标注为不完整。

仅在以下条件全部满足时声明成功：

- `success` 为 `true`。
- `complete` 为 `true`；若用户明确授权了 `--base-only`，则必须将结果标注为不完整。
- `third_party_dependencies` 为 `0`。
- `failed` 为 `0`。
- 每个 `quick_check` 值均为 `ok`。

报告明文快照位置、清单位置以及 `complete` 和 `wal_processed` 的值。不要报告恢复出的密钥。

## 3. 检查并查询

查询使用 `mode=ro&immutable=1` 和 `PRAGMA query_only=ON`；不会在明文快照中创建 SQLite WAL/SHM 边车文件。

```powershell
python scripts/wecomcracker.py inspect --decrypted-dir '<快照目录>'

python scripts/wecomcracker.py sessions `
  --decrypted-dir '<快照目录>' --keyword 'AI' --limit 50

python scripts/wecomcracker.py messages `
  --decrypted-dir '<快照目录>' --conversation-id '<会话 ID>' --limit 100

python scripts/wecomcracker.py search `
  --decrypted-dir '<快照目录>' --keyword '待办' --limit 100
```

使用 Unix 秒格式的 `--since` 和 `--until` 限定消息时间范围。添加 `--conversation-id` 可将搜索限制在单个会话内。

需要关联会话、发送者、消息或附件元数据，或者要把聊天转换为有证据支持的任务时，阅读 [references/data-model.md](references/data-model.md)。

## 4. 梳理结果

将结果分为：

- 有负责人和明确期限的显式任务；
- 需要用户确认的隐含跟进；
- 决定、审批和变更后的指令；
- 已承诺或已交付的产物；
- 阻塞、依赖与等待状态；
- 已完成或已被替代的工作；
- 项目或工作流线索，但不要凭空指定所属项目；
- 内容尚未解析的附件；
- 包含会话、发送者、时间戳和消息 ID 的证据行。

不要根据沉默推断任务已经完成。优先使用明确确认、后续状态消息或已交付附件作为依据。区分“聊天中出现了文件名”和“已经读取了该附件内容”。

## 5. 构建任务关系图

当用户询问任务之间的关系、阻塞链、可并行工作或排期方式时，阅读 [references/task-relationships.md](references/task-relationships.md)。

为每条推断出的关系边返回：

- `from_task` 和 `to_task`；
- 参考分类中的一个关系类型；
- 支持该关系的会话、发送者、时间戳、消息 ID，以及可用时的文件和页码证据；
- `high`、`medium` 或 `low` 置信度；
- 简短依据；
- 只要该关系会改变排期却并非明确表达，就设置 `needs_confirmation: true`。

将“等 X 后再做 Y”等明确表达、交付物结构、共享产物以及后续纠正作为证据。仅仅时间相近不构成依赖。将不确定关系与已确认阻塞分开，并保留互相矛盾的证据，不要悄悄选择其中一个版本。

按以下结构概括关系图：

1. 关键链和硬阻塞；
2. 可并行分支；
3. 父任务及其子任务；
4. 重复、替换和已被取代的工作；
5. 需要用户确认的未决关系。

## 6. 准备项目交接

当用户需要适用于 Vikunja、Microsoft Project 或其他项目管理系统的任务清单时，阅读 [references/project-handoff.md](references/project-handoff.md)。

先生成与具体厂商无关的交接预览。保持所有事项为 `not_synced`，未知字段保留为 `null`，并将已确认任务与推断候选项分开。必须让用户审阅有歧义的负责人、日期、状态和依赖，再由独立连接器向外部系统写入。
