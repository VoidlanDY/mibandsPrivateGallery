# 私密图库 - 小米手环9 Pro

双密码私密图库，支持在不暴露隐私模式的前提下，通过不同密码查看不同图库。

## 核心隐私原理

```
手表端（所有界面完全相同）              管理端（仅手机/电脑可见）
┌──────────────────────┐                ┌─────────────────────┐
│       图库            │                │  📁 普通图库         │
│                      │                │  导入/设置密码       │
│    ○ ○ ○ ○ ○ ○      │                │                     │
│                      │                │  🔒 私密图库         │
│  1  2  3             │                │  导入/设置密码       │
│  4  5  6             │                └─────────────────────┘
│  7  8  9             │
│  ← 0  OK             │    输入普通密码 → 看到普通图片
└──────────────────────┘    输入私密密码 → 看到私密图片
                            界面永远相同，无法区分模式
```

## 项目结构

```
PrivateGallery/
├── quickapp/                    # ★ Vela 快应用（推荐）
│   ├── src/
│   │   ├── manifest.json        # 项目配置
│   │   ├── app.ux               # 应用入口
│   │   ├── common/
│   │   │   ├── style.css        # 全局样式
│   │   │   └── utils.js         # SHA-256 + 密码逻辑
│   │   ├── pages/
│   │   │   ├── Lock/index.ux    # 密码输入页
│   │   │   ├── Gallery/index.ux # 图库浏览页
│   │   │   └── Viewer/index.ux  # 图片查看器
│   │   ├── components/
│   │   │   └── PinPad/index.ux  # 数字键盘组件
│   │   └── assets/
│   └── README.md
├── tools/
│   └── companion.py             # Python管理工具（ADB）
├── watch_app/                   # C原生应用（备选方案）
├── android_app/                 # Android管理端
└── .github/workflows/           # CI/CD
```

## 快速开始

### 1. 使用 AIoT-IDE 打开快应用

- 下载 [AIoT-IDE](https://iot.mi.com/vela/quickapp/)
- 打开 `quickapp/` 项目目录
- 选择手表设备 → 运行模拟器预览

### 2. 使用 Python 管理工具

```bash
pip install -r tools/requirements.txt  # 如果没有 adb
python tools/companion.py
```

交互式菜单：
- 设置普通/私密密码
- 导入图片到普通/私密图库
- 验证密码对应模式

### 3. Android APK (GitHub Actions编译)

推送代码到 GitHub 后自动编译，在 Actions → Artifacts 下载 APK。

## 安全特性

| 特性 | 实现 |
|------|------|
| 手表端零暴露 | 所有UI完全相同，无模式提示 |
| SHA-256哈希 | 密码不可逆存储 |
| 常量时间比较 | 防时序攻击 |
| 5次锁30秒 | 防暴力破解 |
| 退出即锁定 | 离开需重新输密码 |

## 默认密码

- 普通密码: `000000`
- 私密密码: 未设置（任何密码都不匹配，需通过管理端设置）
