# ZKP — 零知识证明隐私合规门控

本模块是一个自包含 PoC，使用 **Groth16 SNARK** 替换明文 KYC 查表，在保护 LP 隐私的前提下完成合规门控。

## 目录结构

```
zkp/
├── circuits/
│   └── kyc_membership.circom      # Poseidon Merkle 成员证明电路 (depth=16)
├── contracts/
│   ├── Groth16Verifier.sol        # snarkjs 生成的链上验证器 (make setup 后重新生成)
│   └── KycMembershipGate.sol      # 策略包装合约
├── backend/
│   └── zkp_verifier_service.py    # Python 链下预验证服务
├── scripts/
│   ├── lib/tree.js                # Poseidon Merkle 树工具库
│   ├── add_member.js              # KYC 提供方注册 LP
│   ├── lp_cli.js                  # LP 生成 Groth16 证明
│   ├── verify_offchain.js         # snarkjs 验证子进程
│   ├── run_demo.py                # 14 项断言端到端验证
│   └── setup.sh                   # 一键环境搭建
├── tests/
│   ├── test_circuit.js            # 电路单元测试 (mocha)
│   └── test_gate_contract.t.sol   # 合约单元测试 (forge)
├── registry.json                  # KYC 注册表 (由 add_member.js 维护)
├── wallets/                       # LP 身份密钥钱包 (勿提交到 git)
├── Makefile
├── foundry.toml
└── package.json
```

## 快速开始

```bash
cd zkp

# 1. 安装依赖、编译电路、生成 trusted setup (~5 分钟)
make setup

# 2. 运行所有测试
make test

# 3. 运行 14 项断言端到端验证（需先启动 MVP 后端）
#    python3 ../mvp/app.py --port 8080
make demo
```

## 核心证明命题

> LP 在认购基金份额时，后端可以验证"该 LP 确实在 KYC 提供方核准的 Merkle 树中"，
> 但**无法获知**专业投资者标志、AML 状态、风险评级等明文 KYC 数据。

## 电路约束（三条）

| 约束 | 公式 | 目的 |
|-----|------|------|
| 身份承诺 | `identityCommitment = Poseidon(identitySecret)` | 将身份密钥散列为 Merkle 叶子 |
| Merkle 路径 | 从 `identityCommitment` 出发到达 `merkleRoot` | 证明 LP 在注册表中 |
| 任务绑定 | `nullifierHash = Poseidon(identitySecret, taskHashCommitment)` | 防止证明跨任务复用 |

## 三层重放防护

| 层 | 机制 | 防护目标 |
|----|------|---------|
| Merkle Root 绑定 | 合约仅接受 `knownRoots` 中的根 | 拒绝过期/伪造注册表 |
| TaskHash 绑定 | 电路约束 nullifier = Poseidon(secret, taskCommit) | 同一证明无法跨任务复用 |
| Nullifier 消耗 | 合约维护 `consumedNullifiers` 映射 | 同一身份同一任务不可重放 |

## 注意事项

- `wallets/lp_*.json` 包含 `identitySecret`，**绝对不要提交到 git**
- `build/` 目录下的 `.zkey` 和 `.wasm` 是 `make setup` 生成的产物，不需要提交
- `contracts/Groth16Verifier.sol` 在 `make setup` 后会被 snarkjs 自动覆盖为真实验证密钥版本
