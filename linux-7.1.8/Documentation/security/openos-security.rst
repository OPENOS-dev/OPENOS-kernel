====================
OPENOS Security (OAK)
====================

OPENOS Security 是 OPENOS 操作系统内置的强制启用 Linux 安全模块 (LSM)，
位于 ``security/openos/``。模块内部使用 **OAK** 加密/密钥体系
(``.oak`` 密钥文件、OAK-Seal 启动校验、OPEN RSA 握手)。

设计目标
========

- **强制启用、不可禁用**: 编译进内核后无法通过 ``lsm=`` 参数或
  ``CONFIG_LSM`` 列表关闭 (见下方"强制启用")。
- **保护安全子模块**: 永久保护 System/OPT/Application 三个内置安全守护进程
  及经 OAK 认证的第三方守护进程。
- **启动完整性校验 (OAK-Seal)**: 启动早期校验内核镜像哈希，防篡改。
- **安全连接**: OPEN RSA 握手 + 会话密钥，供系统内部组件建立安全连接。

模块文件
========

===================== ======================================================
文件                  职责
===================== ======================================================
``oak_lsm.c``         LSM 主模块: ``security_task_kill`` 钩子 (防 kill)、
                      子安全主体注册表、授权提权 (capabilities)、白名单。
``oak_early.c``       启动完整性校验 (OAK-Seal): 读取硬盘偏移 0x1000 的
                      封印块, 校验内核 SHA-256, 失败可凭据解锁或停机。
``oak_rsa.c``         OPEN RSA 握手: 客户端公钥验签 + 服务端私钥叠加签名,
                      毫秒时间戳 (ktime)。
``Makefile``          ``obj-$(CONFIG_SECURITY_OPENOS) += oak_lsm.o \\
                       oak_early.o oak_rsa.o``
``Kconfig``           ``CONFIG_SECURITY_OPENOS`` (def_bool y)
===================== ======================================================

强制启用
========

三层保证, 不可被禁用或修改:

1. **编译期**: ``Kconfig`` 用 ``def_bool y``, 只要 ``CONFIG_SECURITY`` 开启
   即自动编译进内核, 无 ``=n`` 选项。
2. **启动期**: LSM order 强制。5.15 用 ``LSM_ORDER_FIRST`` (其枚举唯一强制项);
   6.12+ 用 ``LSM_ORDER_LAST``。order 为 FIRST/LAST 的 LSM 无视 ``lsm=``
   参数与 ``CONFIG_LSM`` 列表。
3. **构建校验**: 构建体系在编译后校验 ``System.map`` 含 ``oak_task_kill`` /
   ``openos_oak_early_init`` 符号, 缺失则构建失败。

钩子 (security_task_kill)
=========================

拦截对受保护进程的 ``SIGKILL`` / ``SIGTERM``:

- 目标进程属于内置子模块 (System/OPT/Application) 或 OAK 白名单时受保护。
- 仅 Security Watchdog 可终止受保护进程; 其余发送者返回 ``-EPERM``。

子安全主体
==========

System/OPT/Application 三个内置守护与第三方认证守护统一为"子安全主体"，
每个主体 = name + kind + pid + capmask + 公钥 + 指纹。
用户态经 ``/proc/oak/subjects`` 管理 (register/pubkey/unregister)。

授权提权 (内核权利)
===================

受保护进程向 ``/proc/oak/authorize`` 写入自证 token, OAK 校验其 PID 后对其
credential 提权到角色能力集合 (prepare_creds + cap_raise + commit_creds)。
能力集合固定: watchdog=全权, system=看门狗, opt=包管理, application=生命周期。

OAK-Seal 启动校验
=================

由 ``init/main.c`` 的 ``start_kernel()`` 调用 ``openos_oak_early_init()``:

1. 从硬盘偏移 ``0x1000`` 读取 OAK-Seal 封印块。
2. 用 crypto API (``crypto_shash``) 计算内核镜像 ``_text.._end`` 的 SHA-256。
3. 与封印中 ``kernel_hash`` 比对; 失败则凭据解锁 (用户名+密码哈希), 否则
   ``machine_halt()`` 锁死系统。

跨版本说明
==========

- 5.15.215: ``blkdev_get_by_path`` + ``read_mapping_page`` 读封印块;
  LSM order 用 ``LSM_ORDER_FIRST``。
- 6.12.103 / 7.1.8 / 7.2-rc7: ``bdev_file_open_by_path`` + ``kernel_read``;
  ``DEFINE_LSM`` 7.x 用 ``.id`` 字段, 6.12 用 ``.name``。

配置
====

``CONFIG_SECURITY_OPENOS`` 由 ``def_bool y`` 自动启用, 无需额外配置。
如需内核参数, 可用 ``oak.seal_dev`` / ``oak.strict`` 等 (见 ``oak_early.c``)。

用户态配套 (不在内核)
=====================

- ``openos-oak-seal``: 封印工具 (写硬盘头)。
- ``openos-securityd``: OAK 协议守护进程 (Unix socket)。
- ``oakctl``: ``.oak`` 密钥管理工具。
