# Terminal Network Scanner

一个轻量级的终端网络扫描工具，用于快速发现本地网络中的活跃主机

## 功能特性

- 🖥️ 跨平台支持（Windows/Linux/macOS）
- 📶 自动检测本地网络接口
- ⚡ 多线程并发扫描
- 📊 实时进度显示（进度条+统计信息）
- 📋 支持CIDR格式输入（如192.168.1.0/24）
- 📈 网络质量分析（延迟统计）
- 🎨 彩色终端输出
- 📑 按IP顺序排列的扫描结果

## 安装要求

### 基本依赖
- Python 3.6+
- pip包管理工具

### 安装依赖库
```bash
# Linux/macOS
pip install ping3 netifaces
# Windows
pip install ping3
```
## 使用方法
1. 启动程序
```bash
python main.py
```
2. 选择网络接口
```
可用网络接口:
--------------------------------------------------
1. eth0: 192.168.1.100
2. wlan0: 10.0.0.5
请选择网络接口 [1-2]: 
```
3. 输入扫描范围
```
请输入要扫描的CIDR (默认 192.168.1.0/24): 
```
4. 查看扫描结果
```
| IP地址         | 状态       | 延迟 (ms)     |
|----------------|------------|---------------|
| 192.168.1.1    | ●         | 2.34          |
| 192.168.1.100  | ●         | 1.85          |
| 192.168.1.101  | ×         | -             |
```
## 功能演示
```plaintext
网络扫描进度: [████████████████████░░░░░░░░░] 230/256 (89.8%)
已发现活跃主机: 15
```
## 技术实现
- **网络检测**：混合使用系统命令和`netifaces`库
- **Ping检测**：
  - Windows：系统ping命令
  - Unix系：`ping3`库+系统命令回退
- **并发模型**：`ThreadPoolExecutor`线程池
- **进度显示**：独立线程更新+ANSI转义码
- **结果排序**：自然IP地址排序算法
## 贡献指南
欢迎通过以下方式参与贡献：
1. Fork本项目
2. 创建功能分支（git checkout -b feature/xxx）
3. 提交修改（git commit -am 'Add some feature'）
4. 推送分支（git push origin feature/xxx）
5. 新建Pull Request
## 许可证
[MIT License](LICENSE)
