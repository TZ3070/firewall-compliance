# GB/T 20281—2020 防火墙要求扫描结果

## 1. 结果概览

本次扫描以 `GB/T 20281—2020《信息安全技术 防火墙安全技术要求和测试评价方法》` 为标准来源，对安全技术要求、对应测评方法以及防火墙分类和等级适用矩阵进行了整理。

整理结果：

- 候选控制：47 个；
- 推荐 P0 控制：18 个；
- 可仅根据配置进行初步判断：6 个；
- 配置与测试或运行证据混合判断：27 个；
- 必须主动测试：13 个；
- 必须审查产品研发和测评文档：1 个控制族；
- 产品类型：网络型、WEB 应用、数据库、主机型防火墙；
- 产品安全等级：基本级、增强级。

数据状态为 `Candidate`。正式进入规则包前，需要人工审核，并将每项要求绑定至版本化目录中的 verbatim 原文记录。

## 2. 与 GB/T 22239—2019 的区别

| 项目 | GB/T 22239—2019 | GB/T 20281—2020 |
|---|---|---|
| 标准对象 | 等级保护对象 | 防火墙产品 |
| 等级字段 | 等保一级至四级 | 产品基本级、增强级 |
| 主要用途 | 安全建设与监督管理 | 防火墙设计、开发与测试 |
| 自动配置检测 | 可对部分技术要求直接判断 | 多数项目还必须执行主动功能测试 |
| 适用性来源 | 等保等级和应用场景 | 防火墙类型及产品安全等级 |

因此代码中不能继续复用一个无类型的 `level`：

```json
{
  "classified_protection_level": 3,
  "firewall_product_type": "network-based-firewall",
  "firewall_product_security_level": "enhanced"
}
```

## 3. 标准结构的处理方式

| 标准部分 | 处理方式 |
|---|---|
| 第 1～5 章 | 保存范围、定义、产品分类和等级模型，不生成配置规则 |
| 第 6.1 章安全功能 | 原子化为配置、混合或主动测试控制 |
| 第 6.2 章自身安全 | 身份、管理、审计和加固要求进入主要控制目录 |
| 第 6.3 章性能 | 保存阈值和测试条件，但不根据配置判定 Passed |
| 第 6.4 章安全保障 | 作为产品文档和认证证据检查，不进入配置规则 |
| 第 7 章测评方法 | 与第 6 章控制逐项绑定，作为所需证据和测试步骤 |
| 附录 A | 产品类型和产品安全等级的技术要求适用性来源 |
| 附录 B | 产品类型和产品安全等级的测评方法适用性来源 |

## 4. 候选控制分布

| 主题 | 控制数量 | 典型要求 |
|---|---:|---|
| 组网、路由、HA、虚拟化、IPv6 | 8 | 部署模式、路由、冗余、IPv6 健壮性 |
| 网络层控制与流量管理 | 9 | 默认拒绝、五元组、NAT、状态检测、限速、会话超时 |
| 应用层控制 | 5 | 用户、应用识别、WEB、数据库和其他协议内容控制 |
| 攻击防护 | 8 | DoS、WEB、数据库、恶意代码、逃逸和协同防护 |
| 审计、告警和统计 | 5 | 审计事件、日志字段、留存、告警合并和统计 |
| 身份、管理和自身安全 | 10 | 登录保护、MFA、NTP、SYSLOG、角色分离、远程管理和加固 |
| 性能 | 1 | 吞吐、延迟、连接速率和并发数 |
| 安全保障 | 1 | 开发、指导文档、生命周期、测试和脆弱性评定 |

## 5. 推荐 P0 的 18 个控制

| 控制 ID | 内容 | 判断方式 |
|---|---|---|
| GB20281-FW-009 | 包过滤默认禁止 | 配置 |
| GB20281-FW-010 | 包过滤维度和组合策略 | 配置 + 主动测试 |
| GB20281-FW-012 | 状态检测 | 配置 + 主动测试 |
| GB20281-FW-016 | 连接数和新建速率限制 | 配置 + 主动测试 |
| GB20281-FW-017 | 非活跃会话超时 | 配置 + 主动测试 |
| GB20281-FW-023 | 拒绝服务攻击防护 | 配置 + 攻击测试 |
| GB20281-FW-031 | 策略命中和攻击事件审计 | 配置 + 日志样本 |
| GB20281-FW-032 | 安全审计日志字段 | 配置 + 日志样本 |
| GB20281-FW-033 | 日志授权、查询、六个月留存和备份 | 配置 + 运行证据 |
| GB20281-FW-034 | 攻击告警和告警合并 | 配置 + 告警测试 |
| GB20281-FW-036 | 身份唯一和鉴别信息保护 | 配置 + 存储或传输证据 |
| GB20281-FW-037 | 登录失败和管理超时 | 配置 |
| GB20281-FW-038 | 口令复杂度和默认口令 | 配置 |
| GB20281-FW-039 | 管理员 MFA | 配置，网络型增强级适用 |
| GB20281-FW-040 | 管理能力、NTP、SYSLOG | 配置 |
| GB20281-FW-042 | 管理操作审计和异常告警 | 配置 + 日志样本 |
| GB20281-FW-043 | 远程管理来源和加密 | 配置 |
| GB20281-FW-045 | 最小化、重启保护和漏洞基线 | 配置 + 重启及漏洞测试 |

## 6. 当前 Mock 已有和缺少的数据

当前 Mock 已有：

- 默认访问控制动作和策略；
- 源、目的地址和服务；
- SSH、HTTPS、Telnet、HTTP；
- 管理来源接口和 CIDR；
- 管理员、审计员角色及 MFA 标记；
- 策略日志、威胁日志和审计日志开关；
- 本地留存天数和远程 SYSLOG；
- NTP；
- IPS、反病毒和 DoS 防护状态；
- 高可用状态及配置同步。

建议补充：

```text
product.firewall_type
product.security_level
access_control.stateful_inspection_enabled
access_control.policies[*].schedule
access_control.policies[*].source_mac
connection_control.max_sessions_per_ip
connection_control.new_connection_rate_limit
session_management.timeouts
management.password_policy
management.login_policy
management.session_timeout_minutes
management.authentication_factors
management.allowed_source_macs
management.snmp
management.interface_separated
logging.audit_record_fields
logging.authorized_roles
logging.query_capabilities
logging.nonvolatile_storage
logging.capacity_alerting
logging.admin_operation_log_enabled
alerting.aggregation_enabled
restart_preserves_policy
restart_preserves_logs
vulnerability_scan
```

其中最重要的是：

```text
firewall_product_type = network-based-firewall
firewall_product_security_level = basic | enhanced
```

如果这两个字段未知，系统无法根据附录 A/B 确定完整检查清单，应返回 `NeedsReview`。

## 7. 配置合规与产品测评的边界

以下示例不能只根据开关判定完全符合：

```text
ips_enabled = true
dos_protection_enabled = true
antivirus_enabled = true
```

这些字段只能证明功能被配置。完整符合性还要根据第 7 章验证：

- 发送对应攻击样本；
- 检查是否检测和阻断；
- 检查日志字段；
- 检查是否产生告警；
- 验证攻击逃逸、异常协议和故障切换等行为。

建议在 Finding 中区分：

```text
Configured       已发现并启用相关配置
TestVerified     按标准测试方法验证通过
NeedsReview      缺少主动测试、样本或产品文档
```

现有结果枚举不需要增加 `Configured` 作为最终结果，可以将其作为证据状态；只有 `TestVerified` 或标准允许的纯配置证据才能支持最终 Passed。

## 8. 六个月日志留存

本标准 `6.1.5.1 c)` 明确要求日志存储周期不小于六个月。候选目录暂以 183 天作为便于机器比较的最低值：

```json
{
  "operator": "greater_than_or_equal",
  "expected_days": 183
}
```

如果项目希望严格按自然月计算，应把规则改成基于日志起止日期判断，而不是固定天数。

当前 Mock 的 `local_retention_days = 30` 明确低于候选阈值；但在生成正式 Failed 前，仍需确认：

1. 产品类型和安全等级适用；
2. 远程日志是否构成有效的完整留存；
3. 引用是否从 Qdrant 取回并与版本化目录逐字段核验成功；
4. 证据字段是否为 `ConfigurationVerified`。

## 9. 产物使用方法

机器可读目录：

```text
backend/data/catalog/gb-t-20281-2020-firewall-candidates.json
```

进入正式 `control-catalog-v1` 前需要：

1. 确定目标是网络型、WEB、数据库还是主机型防火墙；
2. 确定产品基本级或增强级；
3. 根据附录 A 枚举技术要求；
4. 根据附录 B 绑定测评步骤；
5. 将第 6 章要求和第 7 章测试方法分别绑定为稳定 Qdrant point，并保存源指针和内容哈希；
6. 配置类规则只读取配置证据；
7. 主动测试类没有测试证据时返回 `NeedsReview`；
8. 性能和安全保障要求不从防火墙配置快照生成 Passed。
