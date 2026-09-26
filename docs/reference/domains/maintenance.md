# 维护

域名：`maintenance`

运维与维护域，覆盖缓存、token 预算、环境诊断、产物清理、扩展管理与安全沙箱执行。

## Profile

- workflow
- full

## 典型场景

- 依赖诊断
- 产物清理
- 扩展热加载
- 安全脚本执行

## 常见组合

- maintenance + workflow
- maintenance + extensions

## 工具清单（17）

| 工具 | 说明 |
| --- | --- |
| `get_token_budget_stats` | 获取当前 token 预算使用情况统计。 |
| `manual_token_cleanup` | 手动触发 token 预算清理以释放上下文空间。 |
| `reset_token_budget` | 将全部 token 预算计数器重置为零。 |
| `get_cache_stats` | 获取所有内部缓存的统计信息。 |
| `smart_cache_cleanup` | 智能清理缓存，在释放内存的同时尽量保留热点数据。 |
| `clear_all_caches` | 彻底清空所有内部缓存。 |
| `cleanup_artifacts` | 按保留策略清理生成产物、截图和调试会话。 |
| `doctor_environment` | 检查可选依赖、桥接端点和平台限制等环境状态。 |
| `maintenance_detect_gpu` | 从 WebGL/WebGPU renderer 字符串检测 GPU 家族，分类为 NVIDIA、AMD、Intel、Apple、Mali、Adreno、PowerVR、Vivante、Broadcom、Qualcomm、Microsoft。纯 TS 分类器，无需浏览器。至少提供 webglRenderer、webgpuDescription 或 deviceName 之一。 |
| `snapshot_create` | 为扫描产物目录（artifacts、HAR、截图、debugger-sessions 等）创建 shadow-git 快照，便于日后回退。使用独立于目标目录的 git 对象库——绝不触碰项目 .git，也不会产生 commit。对象库保存完整文件内容，快照可能很大，请只对产物目录使用，不要对源码树使用。 |
| `snapshot_list` | 列出某目录已记录的 shadow-git 快照，最新的在前。 |
| `snapshot_restore` | 将目录还原到某个已记录的 shadow-git 快照。破坏性操作：快照之后被修改的文件会被覆盖、之后新建的文件会被删除、之后被删除的文件会被写回（完整回退语义）。独立对象库不会触碰项目 .git；若之后可能还需要当前状态，请先重新执行 snapshot_create。 |
| `list_extensions` | 列出本地已加载的插件、工作流和扩展工具。 |
| `reload_extensions` | 从已配置目录重新加载全部插件和工作流。 |
| `browse_extension_registry` | 浏览远程 jshookmcp 扩展注册表以发现可用插件和工作流。 |
| `install_extension` | 从远程注册表安装扩展到 jshook 的扩展目录。 |
| `execute_sandbox_script` | 在隔离沙箱中安全执行自定义 JavaScript 脚本。 |
