# 私密图库 - Vela 快应用

小米手环9 Pro（Xiaomi Mi Band 9 Pro）快应用版本。

## 项目结构

```
src/
├── manifest.json          # 项目配置（包名、路由、权限）
├── app.ux                 # 应用入口（全局共享方法）
├── common/
│   ├── style.css          # 全局样式
│   └── utils.js           # 核心安全逻辑（SHA-256、密码验证）
├── pages/
│   ├── Lock/index.ux      # 密码输入页面（入口）
│   ├── Gallery/index.ux   # 图库浏览页面
│   └── Viewer/index.ux    # 图片查看器
├── components/
│   └── PinPad/index.ux    # 数字键盘组件
└── assets/
    └── icon.png           # 应用图标 (192x192)
```

## 开发方式

使用 AIoT-IDE 打开此项目目录即可：

1. 下载安装 [AIoT-IDE](https://iot.mi.com/vela/quickapp/)
2. 打开项目目录 `quickapp/`
3. 选择目标设备：手表（watch）
4. 点击运行 → 模拟器预览

## 编译打包

在 AIoT-IDE 中：
1. 点击"构建" → "打包"
2. 生成 .rpk 文件
3. 通过 ADB 安装到手表：`adb install xxx.rpk`

## 隐私设计

| 特性 | 说明 |
|------|------|
| 手表端零暴露 | 所有页面标题统一"图库"，无模式提示 |
| 双密码隔离 | 输入不同密码进入不同图库 |
| SHA-256哈希 | 密码不可逆存储 |
| 常量时间比较 | 防止时序攻击 |
| 5次锁定30秒 | 防暴力破解 |
| 退出即锁定 | 任何页面按返回键回到密码输入 |
| 无设置入口 | 密码修改只能通过手机端 |
