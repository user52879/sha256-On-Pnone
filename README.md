# 🔐 RSA 签名工具 (Android)

一个安卓 App，用于使用 RSA 私钥对任意内容进行签名，等效于以下 Python 逻辑：

- 算法：SHA-256 with RSA PKCS#1 v1.5
- 支持 PKCS#8（`BEGIN PRIVATE KEY`）和 PKCS#1（`BEGIN RSA PRIVATE KEY`）格式
- 私钥**长期保存**在本地（SharedPreferences）
- 签名结果输出为 **Base64** 字符串

---

## 📦 在线打包（GitHub Actions）

### 方法一：推送代码自动触发

1. 将本项目上传到你的 GitHub 仓库
2. 每次 push 到 `main` 或 `master` 分支，自动编译
3. 编译完成后，进入仓库的 **Actions** 标签页
4. 点击最新的 workflow run → 在页面底部 **Artifacts** 下载 APK

### 方法二：手动触发

1. 进入 GitHub 仓库 → **Actions** 标签
2. 左侧选择 **Build Android APK**
3. 点击右侧 **Run workflow** 按钮
4. 等待约 3~5 分钟后下载 APK

---

## 📱 使用说明

1. 打开 App
2. 在「私钥」框中粘贴你的 PEM 格式私钥
3. 点击「💾 保存私钥」→ 私钥将永久保存，下次打开 App 自动填入
4. 在「待签名内容」框中输入机器码或其他数据
5. 点击「✍️ 执行签名」
6. 复制 Base64 签名结果

---

## 🔧 本地编译

```bash
# 需要 JDK 17 和 Android SDK
chmod +x gradlew
./gradlew assembleDebug
# APK 输出路径：app/build/outputs/apk/debug/app-debug.apk
```

---

## ⚠️ 安全提示

- 私钥保存在 App 私有存储区，其他 App 无法访问
- 建议仅在个人设备使用
- 如需删除私钥，点击 App 内「🗑 清除私钥」按钮
