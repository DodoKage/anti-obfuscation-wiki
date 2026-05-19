# OLLVM 解混淆知识库

## 文件索引

| 文件 | 内容 |
|------|------|
| `01-ollvm-overview.md` | OLLVM 概述、核心 Pass、衍生项目、编译参数、识别特征 |
| `02-control-flow-flattening.md` | CFF 实现原理、变体、解平坦化核心算法 (符号执行/数据流/Trace) |
| `03-bogus-control-flow.md` | BCF 原理、不透明谓词全集、Z3 证明、消除方法 |
| `04-instruction-substitution.md` | 替换规则全集、MBA 混淆、简化算法 (真值表/线性代数/重写规则) |
| `05-string-encryption.md` | 加密变体、解密方法 (动态/Hook/静态/Emulation/FLOSS) |
| `06-deobfuscation-methods.md` | 综合解混淆工作流、D-810/Miasm/angr 使用、手工技巧 |
| `07-tools.md` | 专用工具 (D-810/deflat/obpo)、通用框架、学术工具、工具选择矩阵 |
| `08-case-studies.md` | Android SO、BCF+字符串加密、综合混淆、Hikari、CTF 实战 |

## 快速开始

1. 先读 `01-ollvm-overview.md` 了解 OLLVM 全貌
2. 根据遇到的混淆类型选择对应章节
3. `06-deobfuscation-methods.md` 提供完整的解混淆流程
