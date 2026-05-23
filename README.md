# 多模块 RWA Tokenization 实验系统

## 项目总体定位

本项目是一个面向 **AI Agent 原生联盟链** 资产通证化的多模块实验系统，旨在通过五个互补的工程模块验证以下核心技术假设：

1. **Agent-Native 执行范式**：资产操作不是直接 API 改状态，而是通过 AgentTask 的生命周期编排实现身份校验、策略评估、受控工具调用、链上交易提交和审计证据生成的全闭环。
2. **异构资产业务统一建模**：基金份额认购(LP FundShareToken)、股权投资 RWA(GP PortfolioEquityRWA)、算力收益审计(ComputePowerToken)三类不同法律属性的资产在统一的 AgentTask 框架下完成发行、确权和审计。
3. **合规控制项的链上/链下协同**：KYC/AML 档案、持牌机构注册表、法律权益映射、托管签名请求和 Oracle 证明作为一等公民进入 Agent 执行轨迹，而非事后审计补丁。
4. **零知识隐私门控的渐进式集成**：引入 Groth16 SNARK 证明在不泄露 LP 明文 KYC 数据的前提下完成合规门控，且集成方式对现有系统仅需手术式修改。
5. **工程化全链路交付**：从可运行 MVP、生产级 DDL、OpenAPI 规范、合约伪代码、Agent 规格到服务化拆分蓝图和自定义 AI Skill，覆盖从演示验证到生产部署的完整工程路径。

---

## 模块一：MVP — Agent-Native 可运行演示系统

### 1.1 模块概述

`mvp/` 是本项目的核心可运行单元，使用 Python 标准库 + SQLite 实现零外部依赖的完整 Agent-Native 资产操作台。

### 1.2 技术突破

#### 突破一：Intent-first 执行范式

传统资产通证化系统的 API 设计通常直接暴露状态变更端点（如 `POST /assets/issue`），调用方绕过策略和审计直接操作资产状态。本项目的 MVP 提出并实现了 **Intent-first** 范式：

- 外部用户/机构提交的是 **意图(intent)**、约束(constraints)和授权范围(authorization_scope)，而非直接的状态变更指令。
- 系统内部通过 `AgentTask` 状态机驱动：`created → planning → policy_checking → tool_executing → chain_confirming → auditing → succeeded/failed`。
- 兼容接口 `POST /assets/issue` 和 `POST /assets/transfer` 在内部仍创建 AgentTask，绝不允许绕过 Agent 执行链路。

#### 突破二：三类异构资产的统一业务闭环

MVP 实现了三种法律属性截然不同的资产类型，且每一种都走通完整的 AgentTask 审计轨迹：

| 资产类型 | 业务链路 | 链上操作 | 合规控制点 |
|---------|---------|---------|-----------|
| `FundShareToken` | LP 资金进入基金份额 | `issueFundShareToken` | KYC/AML + 持牌机构 + 法律权益映射 |
| `PortfolioEquityRWA` | GP 投向标的公司股权 | `issuePortfolioEquityRWA` | IC 审批 + 权益映射 + 托管签名 |
| `ComputePowerToken` | 托管方记录算力收益证据 | `recordComputeRevenue` | Oracle 证明 + 受益人 KYC + 托管确认 |

#### 突破三：香港合规控制项的全链路执行化

以下控制项不再停留在数据模型或文档层面，而是作为受控工具(`controlled tools`)进入 Agent 执行轨迹：

- `tool.compliance.verifyKycAml`：校验 KYC 状态、AML 状态、专业投资者资格、制裁名单检查
- `tool.legal.verifyRightsMapping`：校验 token 与法律文件哈希、权益类型和转让限制的映射关系
- `tool.custody.signTransaction`：生成托管签名请求并返回 KMS/HSM mock 签名哈希
- `tool.oracle.verifyAttestation`：校验算力计量 Oracle 的证明数据

#### 突破四：可替换链适配器边界

系统通过 `ChainAdapter` 抽象层解耦业务逻辑与链交互：

- 默认使用本地 `MockChainAdapter`（确定性状态模拟）
- 通过环境变量 `CHAIN_ADAPTER=http` 切换到外部 HTTP 链适配器
- 外部适配器只需实现 `POST {CHAIN_RPC_URL}/transactions` 并返回 `{ tx_hash, status, block_height, block_hash }`

这一设计为后续接入 Hyperledger Fabric、FISCO BCOS、Quorum 等真实联盟链节点预留了清晰接口。

---

## 模块二：Engineering — 工程化全链路设计

### 2.1 模块概述

`engineering/` 提供从 Agent 角色规格、API 规范、智能合约伪代码到生产级数据库 schema 和服务拆分蓝图的完整工程设计方案。

### 2.2 技术突破

#### 突破五：九大 Agent 角色的完整规格体系

`engineering/agents/agent-specs.md` 定义了九个专业 Agent 角色的职责边界、系统 prompt、输入/输出契约和 handoff 规则：

| Agent | 核心职责 | Handoff 目标 |
|-------|---------|-------------|
| Orchestrator Agent | 意图解析、计划生成、多 Agent 协调 | 所有专业 Agent |
| Identity Agent | 主体身份校验、权限范围验证 | Compliance, Orchestrator |
| Compliance Agent | KYC/AML/黑名单/限额/策略评估 | Orchestrator, Recovery |
| Asset Agent | 资产业务校验、合约参数准备 | Transaction, Audit |
| Transaction Agent | 交易构造、签名请求、提交确认 | Monitor, Recovery, Audit |
| Audit Agent | 证据写入、审计轨迹查询 | Orchestrator, Monitor |
| Monitor Agent | 链上事件监听、任务卡死检测、索引一致性监控 | Recovery, Audit |
| Recovery Agent | 补偿计划生成和执行 | Compliance, Transaction, Audit |
| Governance Agent | 联盟成员准入、策略版本管理、合约升级提案 | Compliance, Audit |

每次 handoff 都有明确的触发条件（如 "Transaction → Monitor after transaction submission"），Agent 的自然语言推理不作为最终事实来源——最终事实必须来自链上状态、签名结果和可验证证据。

#### 突破六：受控工具的安全分级策略

`engineering/agents/agent-specs.md` 将所有工具分为 **状态变更工具(state-changing tools)** 和 **只读工具(read-only tools)**，并对状态变更工具强制要求：

- `task_id` 和 `agent_id` 必填
- 中等及以上风险级别必须通过策略引擎审批
- 必须声明 idempotency 或补偿策略
- 必须写入审计证据

#### 突破七：OpenAPI 3.1 Intent-first API 规范

`engineering/api/openapi.yaml` 定义了完整的 RESTful API 表面，核心设计原则包括：

- 状态变更统一通过 `POST /agent/tasks` 创建 AgentTask
- 所有请求携带 `Idempotency-Key` 防重入
- `AgentTask` 状态机包含 `created → planning → policy_checking → tool_executing → chain_confirming → auditing → succeeded/failed/recovering/compensating/policy_rejected/cancelled` 共 12 种状态
- `AuditTrail` 响应包含 `audit_logs`、`tool_calls`、`transactions`、`chain_events` 四种证据维度

#### 突破八：生产级 PostgreSQL DDL

`engineering/database/schema.sql` 提供 22 张表的生产级关系型 schema，关键设计特征：

- **类型安全**：使用 PostgreSQL 枚举类型定义 `requester_type`、`risk_level`、`policy_result`、`task_status`、`plan_status`、`call_result`、`asset_status`、`tx_status`
- **引用完整性**：`agent_tasks` ↔ `agent_plans` ↔ `plan_steps` ↔ `tool_calls` ↔ `policy_evaluations` ↔ `transaction_records` ↔ `chain_events` ↔ `audit_logs` 形成完整的外键引用链
- **合规数据模型**：`licensed_institutions`、`kyc_aml_profiles`、`legal_documents`、`asset_rights_mappings`、`custody_wallets`、`oracle_attestations`、`signature_requests` 全部独立建模
- **事件溯源(outbox pattern)**：`outbox_events` 表支持事件驱动架构的可靠投递

#### 突破九：智能合约伪代码覆盖全生命周期

`engineering/contracts/AssetTokenization.pseudo.sol` 以实现中立的伪代码形式定义了完整的资产状态机，包括：

- 通用资产操作：`registerAsset`、`issueAsset`、`transferAsset`、`freezeAsset`、`unfreezeAsset`、`redeemAsset`、`burnAsset`
- 专用业务操作：`issueFundShareToken`（LP 基金份额）、`issuePortfolioEquityRWA`（GP 股权投资）、`recordComputeRevenue`（算力收益记录）
- `uniqueAction` 修饰器通过 `agentTaskHash + actionHash` 实现链上防重放
- `PolicyOracle` 接口实现链上策略审批回调
- Agent 角色授权通过 `onlyAuthorizedCaller(requiredRole)` 修饰器校验

---

## 模块三：Services — 生产化服务拆分蓝图

### 3.1 模块概述

`services/` 和 `engineering/services/service-skeleton.md` 定义了从单体 MVP 到分布式微服务架构的拆分方案。

### 3.2 技术突破

#### 突破十：十一服务微服务边界划分

每个服务的职责和"不可为"边界明确定义：

| 服务 | 拥有(Owns) | 不拥有(Does Not Own) |
|-----|-----------|---------------------|
| agent-orchestrator | AgentTask 生命周期、计划编排、handoff | 直接资产变更 |
| agent-runtime | 专业 Agent 执行、prompt/spec 加载、工具选择 | 工具权限的权威来源 |
| tool-registry | 工具 schema、角色、风险级别、超时、审计要求 | 业务执行 |
| policy-engine | 策略决策、策略版本、拒绝原因码 | 链上交易提交 |
| asset-service | 资产业务校验、索引查询、合约参数准备 | 链上最终状态 |
| transaction-service | 合约 payload、签名请求、交易提交、确认等待 | 私钥托管 |
| audit-service | AuditLog、evidence hash、生命周期审计轨迹 | 静默的 best-effort 审计 |
| chain-indexer | 链上事件订阅、链下索引同步 | 合约状态变更 |
| storage-service | 对象存储、哈希校验、Merkle 根 | 资产所有权 |
| monitor-service | 指标采集、卡死任务检测、链/索引一致性检测 | 恢复执行 |
| recovery-service | 补偿计划、恢复执行 | 绕过策略 |

#### 突破十一：跨服务事件驱动契约

定义了 11 种跨服务领域事件：`AgentTaskCreated` → `AgentPlanGenerated` → `PolicyEvaluated` → `ToolCallStarted` → `ToolCallCompleted` → `TransactionSubmitted` → `TransactionConfirmed` → `ChainEventObserved` → `AuditEvidenceWritten` → `TaskRecoveryRequested` → `TaskCompleted/Failed`

每个服务内部推荐采用六边形架构(ports and adapters)：`api/` → `domain/` → `adapters/` → `events/` → `config/` → `observability/`。

---

## 模块四：Skills — 可复用的 AI Agent 设计元能力

### 4.1 模块概述

`skills/agentic-consortium-chain-baseline/` 将"设计 AI Agent 原生联盟链方案"的能力封装为结构化 Skill，可被 Codex/Claude 等 AI 编码助手调用。

### 4.2 技术突破

#### 突破十二：架构设计能力的结构化封装

`SKILL.md` 定义了一套完整的设计工作流：

1. 识别目标产物类型（基线文档、架构方案、实现骨架、API/schema 设计、安全审查、实验设计或差距分析）
2. 从本地仓库收集上下文
3. 加载完整 baseline 参考文档生成详细方案
4. 输出前检查 Agent-native 设计约束

该 Skill 还内置了完整的架构检查清单（6 层架构覆盖）、安全审计清单（11 项控制点）和评估指标（13 项实验指标）。

#### 突破十三：完整中文 Baseline 参考实现

`references/baseline.md` 提供了 10 个章节的完整中文基线文档，涵盖：基线目标 → 设计原则(8 条) → 六层总体架构 → 核心模块(8 个) → 数据流(4 种场景) → 模块接口基线(4 类) → 安全基线(11 条) → 实验与评测指标(13 项) → 可扩展方向(7 个)。

该 baseline 核心设定是：用户和外部系统只提交目标、约束和授权，Agent 负责计划、调用工具、执行交易、校验结果和生成审计证据——这一范式贯穿本项目的所有五个模块。

---

## 模块五：ZKP — 零知识证明增强的隐私合规门控

### 5.1 模块概述

`zkp/` 是一个自包含的 PoC(Proof of Concept)，展示如何用 **Groth16 SNARK** 替换明文 KYC 查表，在保护 LP 隐私的前提下完成合规门控。

### 5.2 核心证明命题

> 一个有限合伙人(LP)在认购基金份额时，后端可以验证"该 LP 确实在 KYC 提供方核准的 Merkle 树中"，但**无法获知**该 LP 的专业投资者标志、AML 状态、风险评级和制裁检查结果。

后端仅保留 LP 的化名标识符(pseudonymous identifier)；所有其他 KYC 细节均隐藏于零知识证明之后。

### 5.3 技术突破

#### 突破十四：基于 Poseidon 哈希的 Merkle 成员证明电路

`circuits/kyc_membership.circom` 实现了一个 depth=16 的 Merkle 树成员证明电路，核心约束包括三条：

1. **身份承诺**：`identityCommitment = Poseidon(identitySecret)` — 将身份密钥散列为 Merkle 叶子
2. **Merkle 路径验证**：从 `identityCommitment` 出发的 Merkle 路径到达公开的 `merkleRoot`
3. **任务绑定 Nullifier**：`nullifierHash = Poseidon(identitySecret, taskHashCommitment)` — 将证明绑定到特定任务

电路选择 Poseidon 哈希函数而非 SHA-256 或 MiMC，因为 Poseidon 在 zk-SNARK 中的约束数远小于传统哈希函数（约 1/100），显著降低证明生成时间和电路规模。

#### 突破十五：可重放防护的三层绑定机制

| 绑定层 | 机制 | 防护目标 |
|-------|------|---------|
| Merkle Root 绑定 | 合约仅接受 `knownRoots` 中的根 | 拒绝过期/伪造的注册表 |
| TaskHash 绑定 | 电路约束 `nullifierHash = Poseidon(secret, taskCommitment)` | 同一证明无法跨任务复用 |
| Nullifier 消耗 | 合约维护 `consumedNullifiers` 映射 | 同一身份在同一任务上的重复提交被拒绝 |

**关键设计**：同一 identitySecret + 不同 taskCommitment → 不同 nullifier → LP 可参与多个任务；同一 identitySecret + 同一 taskCommitment → 相同 nullifier → 合约拒绝重放。

#### 突破十六：双层验证架构(Off-chain Pre-verification + On-chain Final Arbiter)

- **Python 后端 `ZkpVerifierService`**：通过子进程调用 snarkjs 进行 Groth16 验证，实现 fail-fast 的 off-chain 预验证，包括 taskCommitment 一致性检查和 Merkle Root 有效性检查
- **Solidity `Groth16Verifier.sol`**：snarkjs 自动生成的链上验证器，利用以太坊预编译合约 `ecPairing` 在常数 gas 成本下验证 Groth16 证明
- **`KycMembershipGate.sol`**：策略包装合约，在上层增加 root 检查、taskHash 绑定和 nullifier 消耗逻辑

后端预验证失败时快速拒绝（不消耗 gas）；链上终裁保证即使后端被攻破，也无法伪造一个有效的零知识证明。

#### 突破十七：5 处手术式集成 + 自动降级

`mvp/app.py` 仅需 **5 处精确修改**即可完成 ZKP 集成：

1. 文件顶部导入 `ZkpVerifierService`
2. 在 `Orchestrator.__init__` 中当 `build/verification_key.json` 存在时实例化
3. 通过 `create_task` 转发可选 `zkp` 字段到 `constraints["_zkp"]`
4. 在 `tool.compliance.verifyKycAml` 之前插入 `tool.privacy.verifyZkpProof` 步骤
5. 使 `ComplianceEvidenceService.verify` 对已被证明的主体跳过明文 KYC 查询

**降级策略**：当 `verification_key.json` 不存在时，Orchestrator 自动回退到原始明文合规路径，无行为变化。这保证了 ZKP 是一个可插拔的增强模块，而非硬依赖。

#### 突破十八：审计兼容性设计

虽然后端不读取明文 KYC 数据，但审计轨迹不丢失：

- `audit_log.details_json` 中保留 `proof_hash`、`nullifier_hash`、`merkle_root`
- 证明始终保持离线可验证性（任何人持有 `verification_key.json` 即可独立验证）
- 审计者可以通过 `merkle_root` 追溯 KYC 提供方的注册表快照

#### 突破十九：14 项断言的端到端验证

`scripts/run_demo.py` 实现了一套 14 项断言的自动化验证脚本，覆盖五个维度：

| 维度 | 断言组 | 验证内容 |
|-----|-------|---------|
| A — 基础功能 | A1/A2/A3 | 任务创建、执行完成、状态为 succeeded |
| B — 隐私保护 | B2/B3/B4 | 请求体无身份密钥、审计日志无明文 KYC、数据库无 identitySecret 泄露 |
| C — 攻击防御 | C1/C2/C3 | 重放攻击防御、篡改证明拒绝、taskHash 绑定强制 |
| D — 审计可追溯 | D1/D2/D3/D | proof_hash/nullifier_hash/merkle_root 存在于审计日志 |
| E — 性能基准 | E1 | 证明生成时间 < 5 秒 |

#### 突破二十：完整的工具链自动化

`Makefile` 和 `scripts/setup.sh` 实现一键式搭建：

- npm 依赖安装 → powers-of-tau 下载(ptau) → circom 编译 → Groth16 trusted setup(Phase 2) + contribution → zkey 导出 → Solidity 验证器生成 → forge 合约构建
- `make test` 运行电路单元测试 + Solidity 合约单元测试
- `make demo` 运行 14 项断言的端到端验证

---

## 跨模块的技术贡献总结

| 序号 | 突破 | 所属模块 | 学术关键词 |
|-----|------|---------|-----------|
| 1 | Intent-first 执行范式 | MVP | Agent-Native Architecture, Intent-Driven Execution |
| 2 | 三类异构资产业务闭环 | MVP | Multi-Asset Tokenization, Unified AgentTask Model |
| 3 | 合规控制项的执行化 | MVP | Compliance-by-Execution, Regulatory Toolchain |
| 4 | 可替换链适配器边界 | MVP | Chain Abstraction Layer, Pluggable Adapter Pattern |
| 5 | 九大 Agent 角色规格 | Engineering | Multi-Agent System, Role-Based Handoff Protocol |
| 6 | 受控工具安全分级 | Engineering | Controlled Tool Layer, State-Change Authorization |
| 7 | OpenAPI 3.1 Intent-first API | Engineering | API-First Design, Idempotency-Key Pattern |
| 8 | 生产级 PostgreSQL DDL | Engineering | Event Sourcing Schema, Regulatory Data Model |
| 9 | 合约伪代码全状态机 | Engineering | Asset State Machine, Replay Protection Modifier |
| 10 | 十一服务微服务边界 | Services | Microservice Decomposition, Bounded Context |
| 11 | 跨服务事件驱动契约 | Services | Domain Events, Hexagonal Architecture |
| 12 | 架构设计 Skill 封装 | Skills | Meta-Design Capability, AI-Assisted Architecture |
| 13 | 完整中文 Baseline | Skills | Reference Architecture, Agent-Native Baseline |
| 14 | Poseidon Merkle 成员证明 | ZKP | Zero-Knowledge Proof, Poseidon Hash, Merkle Tree |
| 15 | 三层重放防护机制 | ZKP | Nullifier-Based Replay Protection, Task Commitment Binding |
| 16 | 双层验证架构 | ZKP | Off-Chain Pre-Verification, On-Chain Final Arbiter |
| 17 | 5 处手术式集成 + 降级 | ZKP | Surgical Integration, Graceful Degradation |
| 18 | 审计兼容性设计 | ZKP | Audit Compatibility, Offline Verifiability |
| 19 | 14 项断言端到端验证 | ZKP | Property-Based Testing, End-to-End Verification |
| 20 | 完整工具链自动化 | ZKP | Reproducible Setup, Trusted Setup Ceremony |

---

## 项目目录结构

```
Tokenization-main/
├── README.md                              # 本文件
├── mvp/                                   # 模块一：可运行 Agent-Native MVP
│   ├── app.py                             #   后端主程序 (Python stdlib + SQLite)
│   ├── demo.py                            #   端到端自动演示脚本
│   ├── README.md                          #   MVP 说明
│   └── static/                            #   前端操作台
│       ├── index.html
│       ├── styles.css
│       └── app.js
├── engineering/                           # 模块二：工程化全链路设计
│   ├── agents/agent-specs.md              #   九大 Agent 角色规格
│   ├── api/openapi.yaml                   #   OpenAPI 3.1 API 规范
│   ├── contracts/AssetTokenization.pseudo.sol  # 合约伪代码
│   ├── database/schema.sql                #   生产级 PostgreSQL DDL
│   └── services/service-skeleton.md       #   服务拆分蓝图
├── services/                              # 模块三：生产化服务目录骨架
│   ├── README.md
│   ├── agent-orchestrator/
│   ├── agent-runtime/
│   ├── tool-registry/
│   ├── policy-engine/
│   ├── asset-service/
│   ├── transaction-service/
│   ├── audit-service/
│   ├── chain-indexer/
│   ├── storage-service/
│   ├── monitor-service/
│   └── recovery-service/
├── skills/                                # 模块四：AI Agent 设计元能力
│   └── agentic-consortium-chain-baseline/
│       ├── SKILL.md                       #   Skill 工作流定义
│       ├── agents/openai.yaml             #   Skill 接口配置
│       └── references/baseline.md         #   完整中文基线文档
└── zkp/                                   # 模块五：零知识证明 PoC
    ├── README.md
    ├── circuits/kyc_membership.circom     #   Poseidon Merkle 成员证明电路
    ├── contracts/
    │   ├── Groth16Verifier.sol            #   snarkjs 生成的链上验证器
    │   └── KycMembershipGate.sol          #   策略包装合约
    ├── backend/zkp_verifier_service.py    #   Python 验证服务
    ├── scripts/
    │   ├── setup.sh                       #   一键搭建脚本
    │   ├── run_demo.py                    #   14 项断言端到端验证
    │   ├── add_member.js                  #   KYC 提供方注册工具
    │   ├── lp_cli.js                      #   LP 侧证明生成 CLI
    │   ├── verify_offchain.js             #   snarkjs 验证子进程
    │   └── lib/tree.js                    #   Poseidon Merkle 树工具库
    ├── tests/
    │   ├── test_circuit.js                #   电路单元测试
    │   └── test_gate_contract.t.sol       #   Solidity 合约单元测试
    ├── registry.json                      #   KYC 注册表
    ├── wallets/                           #   LP 钱包(身份密钥)
    ├── Makefile                           #   自动化工作流
    └── foundry.toml                       #   Foundry 配置
```

---

## 快速开始

### MVP 演示

```bash
python3 mvp/app.py --host 127.0.0.1 --port 8080
# 打开 http://127.0.0.1:8080/
# 或运行端到端 demo: python3 mvp/demo.py
```

### ZKP 演示

```bash
cd zkp
make setup   # 首次需要 ~5 分钟
make test    # 电路 + 合约测试
make demo    # 14 项断言端到端验证
```

---

## 后续研究方向

1. **真实联盟链接入**：将 MockChainAdapter 替换为 Hyperledger Fabric / FISCO BCOS SDK
2. **分布式任务队列**：将进程内 task queue 替换为 Kafka / NATS / Celery
3. **链上 ZKP 验证**：在真实联盟链上部署 Groth16Verifier 和 KycMembershipGate 合约
4. **隐私增强扩展**：引入递归 SNARK(recursive proof composition)实现匿名集合大小隐藏
5. **合规增强接入**：对接真实 KYC/AML 提供商、制裁名单和监管报送接口
6. **多模型协作**：针对计划生成、合规校验和异常恢复使用不同模型或规则引擎协同
7. **治理增强**：实现 Governance Agent 驱动的联盟成员投票和合约升级审批