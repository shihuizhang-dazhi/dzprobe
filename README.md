# DZProbe v1.0
<img width="1130" height="587" alt="截屏2026-03-29 19 47 16" src="https://github.com/user-attachments/assets/ecd5f4aa-62af-4723-a288-49554695e591" />

轻量、可扩展、面向批量资产的 TCP/UDP 存活探测与服务指纹识别工具。


## 功能概览

- TCP 探测：默认 connect，可选 `--tcp-syn`（权限允许时）
- UDP 探测：`--udp`，支持 `--udp-only`
- 服务探针：被动 banner + 主动协议探针
- Web 富化：自动补充状态码、标题、Server
- 指纹识别：支持 `finger.json` 外部规则与 favicon hash
- 导出结果：CSV / JSON


## 安装与运行

### 方式 1：pip 安装（推荐）

```bash
pip install dzprobe
DZProbe -u example.com
```

### 方式 2：从源码安装

```bash
git clone git@github.com:shihuizhang-dazhi/dzprobe.git
cd dzprobe
pip install .
DZProbe -u example.com
```

### 方式 3：不安装直接运行

```bash
chmod +x DZProce.py
./DZProce.py -u example.com
```

## 快速开始

### 1. 单目标快速探测

```bash
./DZProce.py -u 43.143.254.245 -p 22,80,443,8080,8232
```

### 2. 文件批量探测

```bash
./DZProce.py -f targets.txt -p 1-1024
```

### 3. 全端口快速摸底

```bash
./DZProce.py -f targets.txt -p - -t 400 --tcp-timeout 0.25 --tcp-retries 1
```

### 4. 开启完整指纹识别

```bash
./DZProce.py -f targets.txt --finger
```

### 5. 导出结果

```bash
./DZProce.py -f targets.txt -o result.csv
./DZProce.py -f targets.txt -o result.json
```

### 6. 一键扫描档位（推荐）

```bash
# 防火墙友好（低速稳妥）
./DZProce.py -f targets.txt -p 1-1024 --scan-profile stealth

# 均衡模式（推荐）
./DZProce.py -f targets.txt -p 1-1024 --scan-profile balanced

# 激进模式（高速摸底）
./DZProce.py -f targets.txt -p - --scan-profile aggressive

# 自适应限速 + 抖动（防火墙友好）
./DZProce.py -f targets.txt -p 1-1024 --scan-profile stealth \
	--adaptive-pacing --submit-jitter-ms 20
```

## 默认行为

- 默认线程：`100`
- 默认超时：`3.0s`
- 默认探测：TCP connect
- 默认仅显示存活：`--only-alive`
- 默认开启服务探针：`--service-probe`
- 默认开启 Web 富化：`--web-enrich`
- 默认服务探针预算：`0.8s`
- 默认 Web 富化超时：`0.8s`

## 常用调优模板

### 模板 A：极致速度（先摸底）

```bash
./DZProce.py -f targets.txt -p - -t 500 \
	--tcp-timeout 0.2 --tcp-retries 1 \
	--service-probe-budget 0.3 --web-enrich-timeout 0.3
```

### 模板 B：速度与完整度平衡（推荐）

```bash
./DZProce.py -f targets.txt -p - -t 220 \
	--tcp-timeout 0.5 --tcp-retries 1 \
	--service-probe-budget 0.6 --web-enrich-timeout 0.6
```

### 模板 C：高准确（允许更慢）

```bash
./DZProce.py -f targets.txt -p - -t 120 \
	--tcp-timeout 1.0 --tcp-retries 2 \
	--service-probe-budget 1.2 --web-enrich-timeout 1.2 \
	--finger
```

## 参数说明

### 目标与端口

- `-u, --url`：单目标（域名/IP/URL）
- `-f, --file`：目标文件，每行一个目标
- `-p, --ports`：端口范围，支持 `80,443`、`1-1024`、`-`（全端口）

### 并发与超时

- `-t, --threads`：并发线程数（默认 `100`）
- `--scan-profile`：扫描参数预设 `custom|stealth|balanced|aggressive`（默认 `custom`）
- `--adaptive-pacing`：基于超时比例动态降低/恢复在途任务数（默认开启）
- `--submit-jitter-ms`：任务提交随机抖动上限（毫秒），降低固定节奏特征
- `--adaptive-window`：自适应统计窗口大小（默认 `80`）
- `--timeout`：通用超时（默认 `3.0` 秒）
- `--tcp-timeout`：TCP 专用超时
- `--udp-timeout`：UDP 专用超时
- `--web-enrich-timeout`：Web 富化超时（默认 `0.8` 秒）

### TCP / UDP

- `--tcp-syn`：SYN 扫描（权限不足时自动回退 connect）
- `--tcp-retries` / `--tcp-retry-interval`：TCP 重试配置
- `--udp`：开启 UDP 探测
- `--udp-only`：仅做 UDP 探测
- `--udp-retries` / `--udp-retry-interval`：UDP 重试配置

### 服务与 Web 富化

- `--service-probe` / `--no-service-probe`：服务探针开关
- `--service-probe-budget`：服务探针总预算（默认 `0.8` 秒）
- `--web-enrich` / `--no-web-enrich`：Web 富化开关

### 指纹识别

- `--finger`：开启完整指纹识别
- `--finger-db`：外部指纹库路径（默认 `finger.json`）
- `--finger-strict` / `--finger-loose`：严格模式开关
- `--finger-deny`：忽略指纹名称（逗号分隔）
- `--max-finger-hits`：每目标最多输出指纹数

### 输出

- `--only-alive` / `--no-only-alive`：仅显示存活结果或显示全部
- `-o, --output`：导出文件路径
- `--format`：导出格式 `auto|csv|json`
- v2.0.0：已加宽终端表格的“目标”和“Server”列，减少长域名与长 Server Banner 被截断的情况

## 目标文件格式

`targets.txt` 示例：

```text
example.com
https://www.xxx.edu.cn
127.0.0.1:8080
# this is a comment
```

## 可扩展数据文件

- `services.json`：端口与服务名映射
- `probe_signatures.json`：协议识别正则规则
- `finger.json`：外部 Web 指纹规则库

## 常见问题

### 1. 为什么扫描会慢？

常见原因是防火墙丢包导致超时等待。建议：

- 降低 `--tcp-timeout`
- 提高 `-t`
- 降低 `--service-probe-budget` 与 `--web-enrich-timeout`
- 先快扫（摸底）再二次精扫

### 2. 不加 `--finger` 也看到“指纹”列？

这是 v3 的轻量特征提示（非完整指纹库匹配），用于提升可读性和信息量。
完整规则识别需显式开启 `--finger`。

### 3. macOS / Linux 下 SYN 扫描失败？

SYN 扫描通常需要更高权限。权限不足时工具会自动回退到 connect 模式。


