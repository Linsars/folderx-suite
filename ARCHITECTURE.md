# FolderX Suite

SpringBoard 美化与系统增强套件（rootless, Dopamine/TrollStore）。

## 组件

| 组件 | 注入目标 | 功能 |
|---|---|---|
| FolderX.dylib | SpringBoard | 文件夹主题变色、充电限制、Wi-Fi 永连 |
| AppHooks.dylib | appstored/installd/TestFlight | 商店应用版本伪装、TestFlight 增强 |
| CompatPatcher.dylib | 全局 UIKit | iOS 18+ SDK 向下兼容运行时修复 |
| FolderX.bundle | 系统设置 | 设置面板（TweakSettings → MinisFix） |
| minisfixd | LaunchDaemon | 充电限制特权写入（powersource-write） |

## 构建

GitHub Actions（macOS runner + theos）。产物：`deb-packages` artifact。

## 状态

Archived — 个人学习项目，已停止维护。核心功能已合并至上游（[folderx](https://github.com/example/folderx)）。

## License

MIT
