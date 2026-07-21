# 项目管理交接

提取出有证据支持的工作项并梳理其关系后，使用本协议。该协议与具体平台无关，因此后续连接器可以将同一份经过审核的数据映射到 Vikunja、Microsoft Project 或其他项目系统。

## 边界

- 只生成预览；将每个工作项都设为 `not_synced`。
- 本 Skill 不得在外部项目系统中创建、更新、关闭、分派或删除项目条目。
- 在单独的连接器同步推断出的负责人、日期、状态、优先级或依赖关系前，必须取得用户确认。
- 将未知值保留为 `null`；不要仅仅为了满足目标系统的要求而填充字段。

## 交接 schema

```json
{
  "schema_version": "1",
  "source": {
    "system": "wecom",
    "snapshot_manifest": null,
    "snapshot_complete": null,
    "extracted_at": "ISO-8601 timestamp",
    "working_timezone": "IANA timezone"
  },
  "work_items": [
    {
      "local_id": "wecom:<conversation_id>:<message_id>",
      "title": "简洁、以行动为导向的标题",
      "description": "结果、验收证据和相关上下文",
      "classification": "explicit_task | follow_up | completed | superseded | attachment_pending",
      "status": "candidate | open | in_progress | done | cancelled | uncertain",
      "owner": null,
      "start_at": null,
      "due_at": null,
      "project_hint": null,
      "priority_hint": null,
      "tags": [],
      "dependencies": [
        {
          "target_local_id": "wecom:<conversation_id>:<message_id>",
          "type": "blocks",
          "confidence": "high",
          "needs_confirmation": false
        }
      ],
      "evidence": [
        {
          "conversation": "...",
          "sender": "...",
          "timestamp": 0,
          "message_id": "...",
          "file": null,
          "page": null,
          "excerpt": "最少必要文本"
        }
      ],
      "confidence": "high | medium | low",
      "needs_confirmation": false,
      "sync": {
        "state": "not_synced",
        "target": null,
        "external_id": null
      }
    }
  ]
}
```

## 规范化规则

- 使用从最有力的来源消息中派生出的稳定 `local_id`。将后续有关同一工作的消息合并到其证据中，不要创建重复条目。
- `title` 采用“动作 + 结果”的形式；将讨论过程保留在 `description` 或 `evidence` 中。
- 按用户的工作时区将日期转换为 ISO 8601。对依赖上下文或含义模糊的日期暂不解析，并设为 `needs_confirmation: true`。
- 保留已完成、已取消和已被替代的工作以供历史追溯，但默认不要建议为其新建外部任务。
- 在用户授权并实际检查附件前，将依赖附件的工作项保持为待确认状态。
- 使用 [task-relationships.md](task-relationships.md) 中的关系分类。在得到确认前，不要将低置信度依赖纳入排期。

## 连接器交接

未来任何连接器向 Vikunja 或 Microsoft Project 写入前：

1. 展示规范化后的工作项和建议的字段映射；
2. 让用户选择要同步的工作项；
3. 补全缺失的目标项目、负责人、日期和依赖关系映射；
4. 使用幂等写入，并保留返回的外部 ID；
5. 报告部分失败，但不要重复创建已成功写入的条目。
