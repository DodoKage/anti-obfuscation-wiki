# VMProtect 对抗知识库

## 文件索引

| 文件 | 内容 |
|------|------|
| `01-vmp-overview.md` | VMP 版本演进、保护机制一览、平台差异、准备工作 |
| `02-vm-architecture.md` | VMEntry/Dispatcher/Handler/Context 架构、Bytecode 编码、VM 嵌套 |
| `03-handler-analysis.md` | Handler 类型分类、核心 Handler 实现、分析策略、变异识别 |
| `04-devirtualization.md` | 基于 Trace/符号执行/抽象解释/模式匹配的去虚拟化、NAND 链还原、控制流恢复 |
| `05-tools.md` | NoVmp/VTIL/Triton/angr/Frida/Pin/Unicorn/IDA/Ghidra 工具使用 |
| `06-case-studies.md` | VMP 2.x 基础分析、3.x 反调试绕过、嵌套 VM、Android SO、恶意软件分析 |

## 快速开始

1. 先读 `01-vmp-overview.md` 了解 VMP 全貌
2. 再读 `02-vm-architecture.md` 理解 VM 内部结构
3. 根据实际需要选读后续章节
