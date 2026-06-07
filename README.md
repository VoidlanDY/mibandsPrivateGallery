# 私密图库 (Private Gallery) - 小米手环9 Pro

一个专为小米手环9 Pro设计的私密图库应用，支持双密码机制实现极致隐私保护。

## 核心隐私设计

```
手表端界面（完全一致，绝不暴露模式）       Android手机端（唯一可见两种模式的地方）
┌─────────────────────┐                    ┌─────────────────────┐
│       图库           │                    │   📁 普通图库        │
│                     │                    │   导入 / 设置密码    │
│   ○ ○ ○ ○ ○ ○      │                    │                     │
│                     │                    │   🔒 私密图库        │
│   1  2  3           │                    │   导入 / 设置密码    │
│   4  5  6           │                    │                     │
│   7  8  9           │                    │   🔍 密码验证        │
│   ←  0  OK          │                    │   验证密码对应模式    │
└─────────────────────┘                    └─────────────────────┘

输入普通密码 → 看到普通图片            ✅ 界面完全相同
输入私密密码 → 看到私密图片            ✅ 无法区分处于哪种模式
                                       ✅ 无法知道存在另一种模式
```

### 关键特性

| 特性 | 说明 |
|------|------|
| **手表端零暴露** | 任何界面、任何提示、任何交互中，都不存在"普通"/"私密"相关文字或暗示 |
| **双密码隔离** | 输入不同密码进入不同图库，界面完全相同 |
| **常量时间比较** | 密码验证使用常量时间比较，防止时序攻击 |
| **SHA-256哈希** | 密码以不可逆哈希存储，不存明文 |
| **自动锁定** | 连续5次错误锁定30秒 |
| **退出即锁定** | 离开图库后，再次进入需重新输入密码 |
| **目录隔离** | 普通和私密图片存储在文件系统不同目录 |
| **不提供设置入口** | 手表端无法修改密码、切换模式（只能通过手机端管理） |

## 项目结构

```
PrivateGallery/
├── watch_app/                     # 手表端 openvela 应用
│   ├── private_gallery/
│   │   ├── private_gallery.h      # 头文件（数据结构、API声明）
│   │   ├── private_gallery.c      # 核心实现（界面、密码、图片）
│   │   ├── private_gallery_main.c # 主入口
│   │   ├── Kconfig                # 构建配置
│   │   ├── CMakeLists.txt         # CMake构建脚本
│   │   └── Makefile               # 传统Makefile（兼容）
│   └── res/                       # 资源文件
│       ├── fonts/                 # 字体资源
│       └── icons/                 # 图标资源
├── android_app/                   # Android 手机端应用
│   ├── app/
│   │   ├── build.gradle
│   │   ├── proguard-rules.pro
│   │   └── src/main/
│   │       ├── AndroidManifest.xml
│   │       ├── java/com/privategallery/
│   │       │   └── MainActivity.java
│   │       └── res/
│   │           ├── layout/activity_main.xml
│   │           ├── values/
│   │           └── xml/
│   ├── build.gradle
│   ├── settings.gradle
│   ├── gradle.properties
│   └── gradle/wrapper/
└── README.md
```

## 技术架构

### 手表端 (openvela / NuttX RTOS)

- **UI框架**: LVGL (Light and Versatile Graphics Library)
- **屏幕分辨率**: 194×368 像素（竖屏）/ 368×194（横屏）
- **开发语言**: C
- **构建系统**: CMake + Kconfig
- **运行环境**: NuttX RTOS 任务

### Android 手机端

- **最低SDK**: Android 8.0 (API 26)
- **目标SDK**: Android 14 (API 34)
- **开发语言**: Java (Android)
- **通信方式**: ADB (Android Debug Bridge)
- **权限**: 存储读取权限（导入照片）

## 编译与部署

### 手表端编译

1. 将 `watch_app/private_gallery/` 目录放入 openvela 源码树的适当位置：
   ```
   apps/packages/demos/private_gallery/
   ```

2. 配置并启用应用：
   ```bash
   ./build.sh vendor/openvela/boards/vela/configs/<your-board> menuconfig
   ```
   搜索并启用 `LVX_USE_DEMO_PRIVATE_GALLERY`

3. 编译：
   ```bash
   ./build.sh vendor/openvela/boards/vela/configs/<your-board> -j8
   ```

4. 推送资源并启动：
   ```bash
   adb push apps/packages/demos/private_gallery/res /data/
   ```

5. 在手表上运行：
   ```bash
   pgallery &
   ```

### Android 手机端编译

使用 Android Studio 打开 `android_app/` 目录，或命令行编译：

```bash
cd android_app
./gradlew assembleDebug
```

安装 APK：
```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

## 使用流程

### 首次使用

1. 安装 Android 手机端 App
2. 确保手表通过 USB/WiFi ADB 连接到手机
3. 在手机端设置**普通密码**（默认初始密码为 `000000`）
4. 在手机端设置**私密密码**（建议与普通密码不同）
5. 导入图片到**普通图库**
6. 导入图片到**私密图库**
7. 在手表上打开图库，输入对应密码查看图片

### 日常使用

- **查看普通图片**: 在手表上输入普通密码
- **查看私密图片**: 在手表上输入私密密码
- **管理图片**: 只能通过手机端 App 导入/删除
- **修改密码**: 只能通过手机端 App 操作

## 安全性分析

### 攻击模型与防护

| 攻击场景 | 防护措施 |
|---------|---------|
| 他人拿到手表，猜测密码 | 5次错误锁定30秒，6位数字有100万种组合 |
| 通过UI差异推断模式 | 所有UI完全相同，任何状态都无差异 |
| 时序攻击推测密码正确性 | 常量时间密码比较 |
| 读取存储获取图片 | 密码以SHA-256哈希存储，无法反推 |
| 通过文件系统发现私密图库 | 图片目录命名无敏感信息(normal/private) |
| 暴力枚举密码 | 锁定机制+只有6位数字需要在手表上手动输入 |

### 威胁模型

```
假设攻击者拿到了你的手表：
  ✅ 攻击者可以看到图库App存在（无法隐藏App存在本身）
  ✅ 攻击者可以输入密码尝试
  ❌ 攻击者无法知道存在两种图库模式
  ❌ 攻击者无法通过UI判断当前模式
  ❌ 攻击者输入错误密码无法知道是"密码错误"还是"这是普通密码但想看私密"
  ❌ 攻击者无法从文件系统区分普通/私密图片（除非知道文件名）
  ✅ 如果攻击者知道两种密码，可以看到所有图片
```

### 最佳实践建议

1. **使用不同的密码**: 普通密码和私密密码必须不同
2. **避免使用简单密码**: 不要使用 `000000`、`123456`、生日等
3. **定期更换密码**: 建议每3个月更换一次
4. **手机端App独立保护**: 手机端App本身也应设置锁屏保护
5. **手表物理安全**: 手表不在身边时请锁定

## 接口规范

### 密码文件格式 (.pw)

```
偏移量    大小    内容
0x00      32     SHA-256(普通密码) - 6位数字的UTF-8字节
0x20      32     SHA-256(私密密码) - 6位数字的UTF-8字节
```

### 图片目录结构

```
/data/gallery/
├── .pw              # 密码哈希文件
├── normal/          # 普通图片目录
│   ├── photo1.png
│   ├── photo2.jpg
│   └── ...
└── private/         # 私密图片目录
    ├── secret1.png
    ├── secret2.jpg
    └── ...
```

### 支持的图片格式

- PNG (.png)
- BMP (.bmp)
- JPEG (.jpg, .jpeg)
- 二进制图片 (.bin) - LVGL原生格式

## 许可证

本项目仅供个人学习和研究使用。使用本软件即表示您同意自行承担所有风险和法律责任。

## 免责声明

本软件按"原样"提供，不提供任何明示或暗示的保证。作者不对因使用本软件而导致的任何数据丢失、隐私泄露或其他损害承担责任。

使用者应自行遵守所在地区的法律法规。请勿将本软件用于非法目的。
