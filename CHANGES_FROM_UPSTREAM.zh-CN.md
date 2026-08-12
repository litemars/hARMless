# 相对原版的差异与升级点

本文档说明本仓库相对上游
[`litemars/hARMless`](https://github.com/litemars/hARMless) 的维护差异。当前修改基于
上游提交 `46b3630`。

## 升级概览

本分支在上游 ARM64 实现基础上，补齐了可重复使用的交叉编译和加壳流程，使其可以
处理 ARM64 与 ARM32/EABI5 Linux ELF 可执行程序。

| 项目 | 上游基线 | 本仓库升级 |
| --- | --- | --- |
| 目标程序 | ARM64 及上游已有的 x86 工作 | 当前集成目标为 ARM64 和 ARM32/EABI5 |
| 编译平台 | 以目标平台原生编译为主 | 支持 x86_64 WSL 交叉编译和目标平台原生编译 |
| 产物目录 | 共用构建产物 | 按平台分为 `build/ARM64`、`build/ARM32_EABI5`、`build/X86_X64` |
| ARM32 ELF | 加载器和 stub 流程不支持 | 支持 ELF32 ARM/EABI5 检查、加壳、加载及符号处理 |
| 加密长度 | AES 模式可能改变密文长度 | AES-256-CTR 保持加密前后长度一致 |
| 运行持久性 | loader 启动时自删 | 加壳程序默认保留在磁盘上，自删改为显式可选 |
| payload 参数 | 进程伪装可能改写 `argv[0]` | 默认保留原始 `argv[0]`，兼容系统服务和依赖路径的程序 |
| 运行时校验 | payload 长度及加解密/文件错误处理不足 | 增加有界长度校验、2 GiB 输入限制和失败即停止处理 |
| 验证方式 | 项目基础测试 | 增加目录布局、运行保护、ARM64、ARM32/EABI5 冒烟测试 |
| 集成文档 | 通用 README | 增加分架构交接文档和中英文升级说明 |

## 主要差异

### ARM32/EABI5 支持

- 增加 ELF32 数据结构、ARM 机器类型识别和目标格式校验。
- 增加 ARM EABI 直接系统调用封装及 ARM32 系统调用表。
- `stubgen` 增加 ELF32 符号定位和节区清理能力。
- 使用 `arm-linux-gnueabihf` 构建静态链接的 ARM32/EABI5 loader。
- 增加可在 x86_64 Linux/WSL 运行的
  `build/X86_X64/packer-arm32`，用于处理 ARM32 输入文件。
- ARM32 loader 使用普通写入路径，不启用可选的 `io_uring` 写入路径。

当前验证过的 ARM32 ABI 是 hard-float ARMHF、EABI5。Android APK 和动态库封装不在
当前范围内。

### 分平台构建目录

Makefile 按可执行程序实际运行平台拆分产物：

```text
build/ARM64/packer
build/ARM64/loader
build/ARM64/stubgen
build/ARM32_EABI5/packer
build/ARM32_EABI5/loader
build/ARM32_EABI5/stubgen
build/X86_X64/packer
build/X86_X64/packer-arm32
build/X86_X64/stubgen
```

主要构建和加壳命令：

```bash
make all
make verify-build
make pack INPUT=/path/to/arm64.elf OUTPUT=/path/to/arm64.packed

make all32
make verify-build32
make pack32 INPUT=/path/to/arm32-eabi5.elf OUTPUT=/path/to/arm32-eabi5.packed
```

### 加密长度修正

AES 层改为使用零 IV 的 AES-256-CTR。CTR 模式能保证密文长度与原始数据长度一致，
避免 AES-ECB 块填充导致记录的 payload 长度、CRC 校验范围和实际密文长度不一致。
ChaCha20 和 RC4 仍作为附加加密层保留。

这项修改会改变加壳数据格式。必须使用同一版本的 packer 和 loader；采用本分支后，
建议重新生成以前的加壳文件。

### 审计边界

loader 现在会拒绝 `original_size > packed_size`，在复制前用有界减法验证
payload 范围，拒绝超过包头 32 位长度字段的输入，并在 OpenSSL 加解密或文件
读取失败时停止处理，不再继续使用可能未加密或只完成部分解密的缓冲区。

当前格式仍属于混淆层，不是强资产保密边界：每个包的密钥保存在包头中，loader
执行前必然会在内存中持有明文 ELF，CRC32 只能检查偶发损坏，不能替代认证加密。
后续高价值资产保护应使用设备绑定的外部密钥和 AEAD，同时为现有包保留独立兼容路径。

### 多态输出处理

原有输出随机化流程已扩展到 ELF32 和 ELF64 loader。每次生成的文件包含随机 magic、
填充和 padding，以及系统调用表和字符串表重新加密、头部字段隐藏、符号清理和节区头
移除。

### 测试和集成验证

本分支增加以下可重复执行的检查：

- 分平台构建产物和 ELF 格式检查。
- 运行测试的目标架构保护。
- 在 x86_64 WSL 中构建并加壳 ARM64 ELF。
- 在 x86_64 WSL 中构建、加壳并检查 ARM32/EABI5 ELF。

同时已在 ARM64 Linux 主机完成运行验证：

- 加壳后的 ARM64 `/bin/ls` 可以运行，行为与原程序一致。
- ARM32/EABI5 静态测试程序及其加壳版本均可通过主机的 32 位 ARM 兼容层运行，并
  生成预期标记。

`qemu-arm` 可用于未加壳程序的基础启动检查，但不作为加壳 loader 的最终验收环境，
因为用户态模拟下的自身镜像读取和反分析行为可能与原生环境不同。

## 新增文档

- `ARM64_PACKER_HANDOFF.md`：ARM64 构建、加壳、验证和项目集成说明。
- `ARM32_EABI5_HANDOFF.md`：ARM32/EABI5 构建、加壳、验证和项目集成说明。
- `CHANGES_FROM_UPSTREAM.md`：英文升级差异说明。
- `CHANGES_FROM_UPSTREAM.zh-CN.md`：中文升级差异说明。

## 后续同步上游

建议始终保留一个专门指向 `litemars/hARMless` 的远端。合并或变基上游更新后，需要
重新执行 ARM64 和 ARM32 两套测试，因为 packed header、加密顺序、loader 标记或符号
位置的变化都可能影响 packer 与 loader 之间的配套关系。
