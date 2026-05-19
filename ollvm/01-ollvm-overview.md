# OLLVM 基础概述

## 什么是 OLLVM

OLLVM (Obfuscator-LLVM) 是一个基于 LLVM 编译器框架的代码混淆项目，最初由瑞士西北应用科学与艺术大学 (HEIG-VD) 开发。它通过 LLVM Pass 在编译时对 LLVM IR 进行变换，实现代码混淆。

### 项目演进

```
OLLVM (原始)
├── 基于 LLVM 3.x-4.x
├── 三大核心 Pass: FLA, BCF, SUB
└── 2017 年后停止维护

衍生项目 (活跃):
├── Hikari (四季の風) — OLLVM 增强版，新增多种混淆
├── Armariris — 基于 LLVM 12+
├── Pluto — 现代 LLVM 版本支持
├── goron — 基于 LLVM 9-10
├── YANSOllvm — Yet Another OLLVM fork
├── llvm-msvc — Windows MSVC 兼容
└── 各厂商自研 (基于 OLLVM 思路的私有实现)
```

## 核心混淆 Pass

### 1. 控制流平坦化 (Control Flow Flattening, FLA/CFF)

将函数的正常控制流图 (CFG) 变换为一个大型 switch-case 分发结构。

```
原始 CFG:                    平坦化后:
                             
   ┌───┐                     ┌──────────┐
   │ A │                     │ Prologue │
   └─┬─┘                     │ state=A  │
     │                       └────┬─────┘
   ┌─▼─┐                         │
   │ B │──┐                 ┌────▼─────┐
   └─┬─┘  │                │Dispatcher│◄──────┐
     │    │                │ switch   │       │
   ┌─▼─┐ │                │ (state)  │       │
   │ C │ │                └──┬─┬─┬───┘       │
   └─┬─┘ │                   │ │ │           │
     │   │              ┌────┘ │ └────┐      │
   ┌─▼─┐ │              │     │      │      │
   │ D │◄┘         ┌────▼┐ ┌──▼──┐ ┌─▼───┐  │
   └───┘           │ A   │ │ B   │ │ C   │  │
                   │s→B  │ │s→C/D│ │s→D  │  │
                   └──┬──┘ └──┬──┘ └──┬──┘  │
                      └───────┴───────┘     │
                              │             │
                              └─────────────┘
```

### 2. 虚假控制流 (Bogus Control Flow, BCF)

在原始基本块前插入不透明谓词 (Opaque Predicate) 和虚假基本块。

```
原始:              混淆后:
                   
┌───────┐         ┌──────────────┐
│ Block │         │ 不透明谓词    │
│ A     │         │ if (x*x >= 0)│ ← 永真条件
└───────┘         └──┬───────┬───┘
                     │true   │false (永不执行)
                  ┌──▼──┐ ┌──▼──────┐
                  │真实  │ │ 垃圾代码 │
                  │Block│ │ (dead   │
                  │ A   │ │  code)  │
                  └─────┘ └─────────┘
```

### 3. 指令替换 (Instruction Substitution, SUB)

用等价但更复杂的指令序列替换简单指令。

```
原始:          替换后 (示例):
a + b    →    a - (-b)
             r = rand(); a + r + b - r
             (a ^ b) + 2*(a & b)

a - b    →    a + (-b)
             (a ^ b) - 2*(~a & b)

a ^ b    →    (~a & b) | (a & ~b)
             (a | b) & (~a | ~b)

a & b    →    (a | b) & ~(~a | ~b)
             ~(~a | ~b)

a | b    →    (a & b) | (a ^ b)
             ~(~a & ~b)
```

## OLLVM 衍生项目的附加 Pass

### Hikari 新增

| Pass | 说明 |
|------|------|
| StringEncryption | 字符串编译期加密，运行时解密 |
| FunctionCallObfuscation | 间接调用混淆 |
| FunctionWrapper | 函数包装器 |
| IndirectBranch | 间接跳转 |
| SplitBasicBlock | 基本块分裂 |
| AntiClassDump | Objective-C 类信息隐藏 |
| AntiDebugging | 编译期注入反调试 |
| AntiHooking | 反 Hook 检测 |

### 其他衍生项目的增强

| 特性 | 说明 |
|------|------|
| MBA (Mixed Boolean-Arithmetic) | 使用混合布尔算术表达式替换 |
| Constant Encryption | 常量加密 |
| Register Shuffling | 寄存器混淆 |
| Code Virtualization | 类 VMP 的轻量级虚拟化 |
| Opaque Predicate Enhancement | 增强不透明谓词 |

## OLLVM 在各平台的应用

### Android (NDK)

```
最常见的使用场景:
- 游戏反作弊 SO
- 金融 APP 的加密模块
- DRM 保护库
- 即时通讯协议加密

编译方式:
ndk-build NDK_TOOLCHAIN=ollvm-clang
或 CMake 指定自定义 toolchain
```

### iOS

```
保护 Mach-O 二进制:
- 越狱检测逻辑
- 支付验证模块
- 核心算法保护

编译:
使用 obfuscator-llvm 替换 Xcode 默认 clang
```

### Windows/Linux

```
- 软件授权验证
- DRM 模块
- 安全关键代码
```

## 混淆参数

### 编译时启用

```bash
# 控制流平坦化
clang -mllvm -fla input.c -o output

# 虚假控制流
clang -mllvm -bcf input.c -o output
clang -mllvm -bcf -mllvm -bcf_loop=3 input.c -o output  # 3轮

# 指令替换
clang -mllvm -sub input.c -o output
clang -mllvm -sub -mllvm -sub_loop=5 input.c -o output  # 5轮

# 全部启用
clang -mllvm -fla -mllvm -bcf -mllvm -sub input.c -o output

# Hikari 额外选项
clang -mllvm -enable-strcry     # 字符串加密
clang -mllvm -enable-indibran   # 间接跳转
clang -mllvm -enable-funcwra    # 函数包装
clang -mllvm -enable-splitobf   # 基本块分裂
```

### 函数级注解

```c
// 对特定函数启用混淆
__attribute__((annotate("fla")))
__attribute__((annotate("bcf")))
__attribute__((annotate("sub")))
void protected_function() {
    // ...
}

// 排除某函数
__attribute__((annotate("nofla")))
void performance_critical() {
    // ...
}
```

## OLLVM 混淆的识别特征

### 控制流平坦化特征
- 函数开头有一个大型 switch/dispatcher
- 大量基本块以修改 state 变量 + 跳转到 dispatcher 结尾
- CFG 呈现"星形"拓扑
- IDA 中 graph view 显示一个中心节点连接大量子节点

### 虚假控制流特征
- 不透明谓词: `(x * (x + 1)) % 2 == 0` (永真)
- 存在大量不可达的基本块
- 相同代码的克隆副本

### 指令替换特征
- 简单运算被异常复杂的等价表达式替代
- 大量位运算组合
- 代码体积显著膨胀
