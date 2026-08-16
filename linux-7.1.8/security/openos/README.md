# OPENOS Security (security/openos/)

OPENOS 内置强制启用安全模块 (LSM)。内部加密方法: **OAK**。

## 文件

| 文件 | 职责 |
|---|---|
| `oak_lsm.c` | LSM 主模块: task_kill 防 kill / 子安全主体 / 授权提权 / 白名单 |
| `oak_early.c` | OAK-Seal 启动完整性校验 (start_kernel 调用) |
| `oak_rsa.c` | OPEN RSA 握手 (内核 crypto API) |
| `Kconfig` | `CONFIG_SECURITY_OPENOS` (def_bool y, 强制启用) |
| `Makefile` | `obj-$(CONFIG_SECURITY_OPENOS) += oak_lsm.o oak_early.o oak_rsa.o` |

## 强制启用 (不可禁用)

1. Kconfig `def_bool y` (CONFIG_SECURITY=y 即编译进内核, 无 =n)
2. LSM order 强制: 本内核用 `LSM_ORDER_LAST` (6.12+) 或 `LSM_ORDER_FIRST` (5.15)
3. 构建校验 System.map 含 `oak_task_kill`/`openos_oak_early_init`

## 用户态接口

- `/proc/oak/watchdog`  登记 Security Watchdog PID
- `/proc/oak/builtin`   登记内置守护 PID (自动成为内置子主体)
- `/proc/oak/whitelist` 第三方白名单 add/del [capmask]
- `/proc/oak/subjects`  子安全主体 register/pubkey/unregister
- `/proc/oak/handshake` 握手 challenge/verify
- `/proc/oak/authorize` 进程自证身份并获内核权利 (capabilities)

## 完整文档

见 `../../Documentation/security/openos-security.rst`。

> 注意: 本目录代码是内核功能, 由 `obj-$(CONFIG_SECURITY_OPENOS)` 编译。
> 用户态配套 (oakctl / openos-securityd / openos-oak-seal) 位于
> 项目级 `OPENOS_CORE/src/`。
