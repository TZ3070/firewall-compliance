# JR/T 0071.2—2020 防火墙相关要求扫描结果

## 1. 结果概览

本次扫描以 `JR/T 0071.2—2020《金融行业网络安全等级保护实施指引 第2部分：基本要求》` 为标准来源，仅整理可由防火墙配置、设备运行状态、设备日志或针对防火墙的测试直接或部分验证的要求。

整理结果：

- 通用防火墙控制族：49 个；
- 条件适用扩展控制：14 个；
- 合计候选控制：63 个；
- 推荐 P0 控制：30 个；
- 自动配置检查：13 个；
- 配置与人工、日志或测试混合检查：45 个；
- 防火墙承担特定功能时适用：5 个；
- 覆盖等级：第二级、第三级、第四级；
- 场景扩展：云计算、移动互联、物联网。

数据状态为 `Candidate`。进入正式规则包前，仍需由标准或测评人员审核，并绑定版本化目录中的 verbatim 原文记录。

## 2. 与前两个标准的关系

| 标准 | 评价对象 | 本目录的作用 |
|---|---|---|
| GB/T 22239—2019 | 通用等级保护对象 | 提供通用等级保护基线 |
| GB/T 20281—2020 | 防火墙产品 | 验证防火墙产品功能、安全和测试能力 |
| JR/T 0071.2—2020 | 金融行业等级保护对象 | 在通用基线上增加金融行业 F2/F3/F4 增强要求 |

三个标准不能简单合并成一个无来源的“合规规则”。一次检查至少需要以下上下文：

```json
{
  "classified_protection_level": 3,
  "industry": "financial",
  "deployment_contexts": ["general"],
  "firewall_product_type": "network-based-firewall",
  "firewall_product_security_level": "enhanced"
}
```

其中 `classified_protection_level` 用于选择 JR/T 0071.2 和 GB/T 22239 条款；`firewall_product_security_level` 只用于 GB/T 20281，二者不能混用。

## 3. 文档内容的处理方式

| 文档部分 | 处理方式 |
|---|---|
| 封面、前言、目录、引言 | 不进入检索库 |
| 第 1～6 章 | 保存标准元数据、等级模型和金融增强标记，不生成防火墙 Finding |
| 第 7 章 | 提取第二级防火墙相关要求及 F2 增强项 |
| 第 8 章 | 提取第三级防火墙相关要求及 F3 增强项 |
| 第 9 章 | 提取第四级防火墙相关要求及 F4 增强项 |
| 云、移动、物联网扩展 | 单独标记为条件适用，不随关键词命中自动套用 |
| 大数据及终端应用自身要求 | 不进入防火墙配置目录 |
| 管理、人员、物理环境要求 | 排除或保留为人工测评边界，不生成自动防火墙结果 |

正文印刷页码与当前 PDF 的关系为：

```text
PDF 物理页序号 = 正文印刷页码 + 8
```

## 4. 通用候选控制分布

| 主题 | 控制数量 | 典型检查内容 |
|---|---:|---|
| 网络架构与通信 | 4 | 分区隔离、容量冗余、跨机构前置隔离、加密通信 |
| 边界与访问控制 | 9 | 受控接口、默认拒绝、规则清理、五元组、状态检测、端口治理 |
| 入侵与恶意代码 | 4 | 内外部攻击、APT、攻击日志告警、恶意代码 |
| 边界日志审计 | 6 | 审计覆盖、字段、六个月留存、时间戳和行为审计 |
| 身份、账号和权限 | 7 | 口令周期、登录保护、MFA、默认账号、最小权限 |
| 设备加固与自身审计 | 8 | 管理来源、服务关闭、漏洞、节点入侵、设备审计 |
| 备份、监测和版本 | 5 | 每月配置备份、恢复、管理员审计、每日监测、版本核验 |
| 管理员和集中管控 | 6 | 审计员、安全管理员、集中监测、日志、策略和事件管理 |

合计 49 个通用控制族。同一控制中的第二级、第三级和第四级引用分别保存，运行时只能选择当前等级及其适用增强要求。

## 5. 关键金融增强要求

### 5.1 审计记录保存

标准在多个 F2/F3/F4 条款中要求审计记录保存不少于六个月，包括防火墙边界日志和设备自身审计日志。

候选规则使用：

```json
{
  "suggested_minimum_retention_days": 183
}
```

183 天只是便于初步机器比较。正式判定最好比较日志最早和最新时间，按自然月验证六个月，而不是固定天数。

### 5.2 分级口令策略

| 等级 | 候选阈值 |
|---|---|
| 第二级 | 静态口令 8 位以上，字母、数字、符号混合并定期更换 |
| 第三级 | 8 位以上；最长约半年更换；新口令不得与上一次相同 |
| 第四级 | 8 位以上；至少每 90 天更换；不得与前三次相同 |

如果设备使用集中身份源，应同时采集本地账号策略和集中身份平台策略，不能只查看防火墙本地口令配置。

### 5.3 配置备份

第二至第四级金融增强要求均包含：

- 每月备份设备配置文件；
- 配置发生变动时及时备份。

仅发现“自动备份已开启”还不足以判定完全符合，应核验最近一次成功时间、变更后备份和备份记录。

### 5.4 运行监测和版本核验

- 第二级要求定期监测设备运行状态并定期核验软件版本；
- 第三级要求自动化实时监测、每日查看记录，并每季度核验版本；
- 第四级要求自动化监控平台实时监测、每日查看记录，并每月核验版本；
- 第三级和第四级升级前还要求有效测试并保留记录。

这些项目属于混合证据，设备配置只能证明监控或版本状态，无法证明人员实际查看、测试和留痕。

## 6. 推荐 P0 检查范围

推荐 P0 共 30 个，优先覆盖：

- 跨边界流量必须经过受控接口；
- 默认拒绝、五元组和状态检测；
- 无效规则、无用服务端口和无用账号治理；
- 内外部攻击检测、防护、记录与告警；
- 边界审计、设备审计、日志字段、六个月留存和统一时钟；
- 分级口令、登录失败、会话超时、MFA 和安全远程管理；
- 默认账号、共享账号、最小权限和管理来源限制；
- 漏洞检查与修补；
- 每月及变更后配置备份；
- 设备实时监测、每日查看和软件版本核验；
- 审计管理员权限分离；
- 安全事件集中分析、响应和告警合并。

机器可读的完整 P0 ID 清单保存在候选目录的 `recommended_p0_control_ids` 中。

## 7. 条件适用扩展控制

| 场景 | 数量 | 主要要求 |
|---|---:|---|
| 云计算 | 8 | 虚拟网络隔离、虚拟边界规则、东西向流量、DDoS、WAF、特权审计 |
| 移动互联 | 3 | TLS/IPSec、有线无线边界网关、无线攻击检测阻断 |
| 物联网 | 3 | 授权节点、目标地址限制、攻击信息上报 |

只有明确存在对应场景，而且防火墙承担相应能力时，扩展控制才能进入检查清单。例如：

```text
cloud_enabled = true
cloud_firewall_in_scope = true
internet_financial_service = true
```

上述条件成立时，云 DDoS 和 WAF 要求才进入本轮检查。仅因为检索文本包含“防护”或“访问控制”不能自动认定适用。

## 8. 当前 Mock 字段覆盖情况

当前已有事实可覆盖：

- 默认动作和访问策略；
- 源区域、目的区域、地址、服务、动作和日志；
- SSH、HTTPS、Telnet 和 HTTP 管理协议；
- 管理接口和允许来源网段；
- 管理员、审计员角色和 MFA 标记；
- 策略日志、威胁日志和审计日志；
- 本地留存天数、远程 SYSLOG 和 NTP；
- IPS、反病毒、DoS 和 HA 状态。

建议补充：

```text
assessment.classified_protection_level
assessment.industry
assessment.deployment_contexts
access_control.stateful_inspection_enabled
access_control.rule_hits
access_control.shadow_analysis
management.password_policy
management.login_policy
management.session_timeout_minutes
management.authentication_factors
management.default_accounts
management.shared_account_flags
management.roles
management.role_permissions
management.allowed_source_macs
logging.audit_record_fields
logging.audit_log_protection_enabled
logging.audit_process_protected
logging.timestamp_source
configuration_backup.last_success_at
configuration_backup.on_change
monitoring.mode
monitoring.last_operator_review_at
version_review.last_reviewed_at
upgrade.test_records
threat_prevention.attack_log_fields
threat_prevention.severe_event_alerting_enabled
alerting.aggregation_enabled
```

字段缺失时返回 `NeedsReview`，不能将“未采集到”解释为“不符合”。

## 9. 搜索与判定建议

推荐先过滤后检索：

1. 根据 `standard_code` 选择 JR/T 0071.2—2020；
2. 根据 `classified_protection_level` 选择二级、三级或四级引用；
3. 默认只选择 `general`；
4. 根据部署事实增加 `cloud-conditional`、`mobile-conditional` 或 `iot-conditional`；
5. 根据配置字段和控制主题召回候选控制；
6. 使用确定性规则计算配置差异；
7. 再从 Qdrant 精确取回原文，并与版本化目录校验；
8. 缺少拓扑、日志样本、工单或主动测试时返回 `NeedsReview`。

结果证据状态建议继续区分：

```text
ConfigurationVerified  配置字段已验证
RuntimeVerified        运行状态或日志样本已验证
TestVerified           主动测试已验证
DocumentVerified       工单、备份或审核记录已验证
```

只有该控制要求的证据类型都满足时，才能输出最终 `Passed`。

## 10. 不进入自动防火墙检测的内容

- 机房、门禁、消防、防雷、防水、供配电和电磁防护；
- 安全制度、组织机构、人员录用离岗、培训和沟通；
- 定级备案、采购、开发、实施、验收和系统交付；
- 数据库、应用系统、个人金融信息和业务数据本身的要求；
- 大数据安全扩展和移动终端应用自身安全；
- 使用“可”表述的可信验证要求；
- 事件处置、应急预案、外包管理等需要制度、工单或访谈的要求。

这些内容只是超出本项目的自动防火墙检查范围，不代表标准层面不适用，报告中不应直接生成 `NotApplicable`。

## 11. 产物使用方法

机器可读候选目录：

```text
backend/data/catalog/jr-t-0071-2-2020-firewall-candidates.json
```

正式进入 `control-catalog-v1` 前，需要完成：

1. 确定等保等级和金融行业适用范围；
2. 确定云、移动、物联网部署上下文；
3. 人工复核控制粒度和 F2/F3/F4 引用；
4. 绑定稳定 Qdrant point ID、源目录指针、内容哈希和审核状态；
5. 为自动项建立确定性规则和单元测试；
6. 为混合项声明必须补充的日志、拓扑、工单和测试证据；
7. 报告中同时披露标准来源、等级、适用上下文和自动化覆盖边界。
