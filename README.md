# 代码保护对抗知识库

VMP (VMProtect) 对抗与 OLLVM (Obfuscator-LLVM) 解混淆的系统化知识库。

## 目录结构

```
knowledge/
├── README.md                              ← 总览 (本文件)
├── vmp/                                   ← VMProtect 对抗
│   ├── 01-vmp-overview.md                 ← VMP 基础概述
│   ├── 02-vm-architecture.md              ← VM 架构深度分析
│   ├── 03-handler-analysis.md             ← Handler 分析方法
│   ├── 04-devirtualization.md             ← 去虚拟化技术
│   ├── 05-tools.md                        ← 工具集
│   └── 06-case-studies.md                 ← 实战案例
├── ollvm/                                 ← OLLVM 解混淆
│   ├── 01-ollvm-overview.md               ← OLLVM 基础概述
│   ├── 02-control-flow-flattening.md      ← 控制流平坦化
│   ├── 03-bogus-control-flow.md           ← 虚假控制流
│   ├── 04-instruction-substitution.md     ← 指令替换与 MBA
│   ├── 05-string-encryption.md            ← 字符串加密
│   ├── 06-deobfuscation-methods.md        ← 综合解混淆方法
│   ├── 07-tools.md                        ← 工具集
│   └── 08-case-studies.md                 ← 实战案例
└── common/                                ← 通用技术
    ├── symbolic-execution.md              ← 符号执行
    ├── taint-analysis.md                  ← 污点分析
    └── ida-scripts.md                     ← IDA 脚本集合
```

## 快速导航

### 按任务查找

| 我想要... | 阅读 |
|-----------|------|
| 了解 VMP 保护原理 | `vmp/01-vmp-overview.md` |
| 分析 VMP 虚拟机结构 | `vmp/02-vm-architecture.md` |
| 识别和分类 VMP Handler | `vmp/03-handler-analysis.md` |
| 将 VMP bytecode 还原为 x86 | `vmp/04-devirtualization.md` |
| 绕过 VMP 反调试 | `vmp/06-case-studies.md` → 案例 2 |
| 分析 Android SO 的 VMP 保护 | `vmp/06-case-studies.md` → 案例 4 |
| 了解 OLLVM 混淆机制 | `ollvm/01-ollvm-overview.md` |
| 解除控制流平坦化 | `ollvm/02-control-flow-flattening.md` |
| 消除虚假控制流 | `ollvm/03-bogus-control-flow.md` |
| 简化 MBA/指令替换 | `ollvm/04-instruction-substitution.md` |
| 解密混淆字符串 | `ollvm/05-string-encryption.md` |
| 使用 D-810 解混淆 | `ollvm/06-deobfuscation-methods.md` |
| CTF 逆向中对抗 OLLVM | `ollvm/08-case-studies.md` → 案例 5 |
| 用 angr 做符号执行 | `common/symbolic-execution.md` |
| 用 Triton 做精确分析 | `common/symbolic-execution.md` |
| 用污点分析过滤虚假代码 | `common/taint-analysis.md` |
| 找 IDA 自动化脚本 | `common/ida-scripts.md` |

### 按工具查找

| 工具 | 相关文档 |
|------|----------|
| IDA Pro | `common/ida-scripts.md`, `vmp/05-tools.md`, `ollvm/07-tools.md` |
| Ghidra | `vmp/05-tools.md`, `ollvm/07-tools.md` |
| Binary Ninja | `vmp/05-tools.md`, `ollvm/07-tools.md` |
| angr | `common/symbolic-execution.md`, `ollvm/06-deobfuscation-methods.md` |
| Triton | `common/symbolic-execution.md`, `vmp/05-tools.md` |
| Frida | `vmp/05-tools.md`, `ollvm/05-string-encryption.md` |
| x64dbg | `vmp/05-tools.md` |
| Unicorn | `vmp/05-tools.md`, `ollvm/07-tools.md` |
| D-810 | `ollvm/06-deobfuscation-methods.md`, `ollvm/07-tools.md` |
| Z3 | `ollvm/03-bogus-control-flow.md`, `common/symbolic-execution.md` |
| Miasm | `ollvm/06-deobfuscation-methods.md` |
| NoVmp / VTIL | `vmp/05-tools.md` |

## 核心概念速查

### VMP 核心组件

```
VMEntry     → 保存上下文，初始化 VM
VMDispatcher→ Fetch-Decode-Dispatch 循环
VMHandler   → 虚拟指令实现 (vAdd, vNand, vPush, ...)
VMContext   → 虚拟寄存器 + 虚拟栈 + VIP
VMExit      → 恢复上下文，返回原始执行流
```

### OLLVM 核心 Pass

```
CFF (控制流平坦化) → switch-case dispatcher 替代正常 CFG
BCF (虚假控制流)   → 不透明谓词 + 死代码注入
SUB (指令替换)     → 等价复杂表达式替换
StringEncryption   → 编译期加密，运行时解密 (Hikari)
```

### 解混淆方法论

```
VMP:   Trace → Handler 语义分析 → IR Lifting → 优化 → x86 重建
OLLVM: 类型识别 → BCF 消除 → MBA 简化 → CFF 解平坦化 → 重建 CFG
```

## 推荐学习路径

### 初学者

```
1. ollvm/01-ollvm-overview.md     (理解混淆概念)
2. ollvm/02-control-flow-flattening.md (最常见的混淆)
3. ollvm/03-bogus-control-flow.md (第二常见的混淆)
4. common/ida-scripts.md          (实用脚本)
5. ollvm/08-case-studies.md       (动手实践)
```

### 进阶

```
1. vmp/01-vmp-overview.md         (VMP 概述)
2. vmp/02-vm-architecture.md      (理解 VM)
3. vmp/03-handler-analysis.md     (Handler 分析)
4. common/symbolic-execution.md   (符号执行)
5. vmp/04-devirtualization.md     (去虚拟化)
```

### 高阶

```
1. vmp/04-devirtualization.md     (深入去虚拟化算法)
2. ollvm/04-instruction-substitution.md (MBA 数学)
3. common/taint-analysis.md       (高级分析方法)
4. vmp/06-case-studies.md         (复杂场景)
5. 阅读相关学术论文 (见各文档中的引用)
```

## 参考资源

### 学术论文
- "Deobfuscation: Reverse Engineering Obfuscated Code" (Yadegari et al.)
- "Symbolic Deobfuscation: from Virtualized Code Back to the Original" (Jonathan Salwan)
- "QSynth: A Program Synthesis based approach for Binary Code Deobfuscation"
- "Syntia: Synthesizing the Semantics of Obfuscated Code"
- "Generic Deobfuscation of OLLVM" (Quarkslab)
- "VMAttack: Deobfuscating Virtualization-Based Packed Binaries"

### 社区资源
- Quarkslab Blog (控制流解混淆系列)
- secret.club (VMP 分析文章)
- Can1357's VTIL 项目文档
- r2con / REcon 会议演讲
