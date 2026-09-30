# 弱网与长时间运行测试（路线图 5.5）

在 Linux 测试机上，用两个网络命名空间和 `tc netem` 模拟各种网络条件，让被测客户端（sail 或 sing-box）经 SOCKS 入站转发带校验的流量，并记录它的内存、CPU、文件描述符和 TCP 状态。

```
nc5 (10.95.0.1)                                  ns5 (10.95.0.2)
netgen 客户端 --SOCKS--> 被测客户端 ==veth, netem==> sing-box 服务端 --> netgen serve
```

- `netns.sh`：建立、整形、断开这对命名空间。所有操作都只在这两个命名空间里进行，不动宿主机自己的路由和防火墙。
- `netgen/`：流量工具（Go）。双方发送的每个字节都来自带种子的生成器，由对端校验，所以数据损坏、截断、错序都会被计数，不会漏掉。模式包括大块上下行、回显往返、建连延迟、大量并发、短连接高频开关、两个方向的半关闭，以及断网期间的连通性探测。
- `run.py`：编排。每组（协议 × 客户端）按场景依次整形、跑负载、采样，结果写到 `<work>/results/<时间>/summary.json`；只有出现失败的组才保留压缩后的原始记录。

## 运行

测试机上需要 root，以及 `tc`、`ss`、`ethtool`、sing-box（作服务端和对照客户端）。

```sh
# 本机交叉编译 netgen，连同 sail 的 release 版放到测试机
(cd netgen && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o netgen .)
# 测试机上（sail 在临时 target 里编译，限制并行，编完删掉 target）
python3 run.py --work WORK --sail WORK/sail --netgen WORK/netgen
python3 run.py --protocols direct --clients sail-server --only baseline --quick   # 冒烟
```

`--protocols` 取 `direct,ss,trojan,reality,hy2,tuic,mux`（默认前三个；`reality` 是 vless+REALITY+vision，握手目标是服务端 netns 里的 `openssl s_server`；`mux` 是开了 sing-mux 的 trojan）；`--clients` 取 `sail-server,sail-mobile,sing-box`（sail 的运行档位，或 sing-box 作对照）；`--only` 只跑名字含该子串的场景；`--quick` 缩短每项负载。

## 场景

| 场景 | 条件 |
| --- | --- |
| baseline | 不整形 |
| rtt50 / rtt150 / rtt300 | 往返延迟，±10% 正态抖动 |
| loss0.5 / loss2 / loss5 | 随机丢包，10ms 单向延迟 |
| burst2 | Gilbert-Elliott 突发丢包，平均约 2% |
| reorder5 / reorder25 | 乱序，20ms 单向延迟 |
| rate10m / rate2m | 限速，20ms 单向延迟 |
| blackhole5 / blackhole30 | 双向全丢 5s / 30s，链路保持 up |
| linkdown10 | 客户端一侧链路 down 10s |
| server_restart | 服务端进程重启 |
| concurrency | 2000 条并发连接保持后逐条验证；200/s、500/s 的短连接 |
| halfclose | 两个方向的半关闭各 50 次，无损和 2% 丢包下 |

## 判定

| 判定 | 标准 | 来源 |
| --- | --- | --- |
| 数据 | 零损坏、零截断 | 绝对要求 |
| 进程 | 不崩溃、不退出 | 绝对要求 |
| 断网恢复 | 链路恢复后 3 秒内新连接成功；超过的报告原因，不直接判失败 | 路线图 2.12 的验收（"3 秒内恢复新连接"） |
| 半关闭 | 两个方向都完整送达 | 绝对要求 |
| 并发 | 2000 条全部建立并存活 | bench/core-compare 的 2000 并发 |
| 资源泄漏 | 每个场景后内存、fd、TCP 连接回到空闲基线附近 | 阈值待首轮基线测量后定 |
| 吞吐与延迟 | 与 sing-box 作客户端在同一场景下比较 | 阈值待首轮测量后定 |

所有进程以 `ulimit -n 65536` 运行，与实际部署一致：Go 程序启动时会自己把文件描述符软限制提到硬限制。

## 共享测试机上的约定

- 只在 `nc5`/`ns5` 和 10.95.0.0/24 里工作；名字或网段已被占用时 `netns.sh up` 拒绝启动，退出时删除命名空间。
- 编译和每次运行前检查 `df -h /`；可用空间不足 2 GiB 时 `run.py` 不启动。
- sail 在临时 target 里用 `CARGO_BUILD_JOBS=2` 编译（默认并行度在这台机器上会被 OOM 杀掉），编完删除 target。
- 24 小时长跑前先与机器上正在运行的其他长任务协调。
