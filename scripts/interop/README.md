# 互通矩阵：sail 对 sing-box 与 Mihomo，双向

发布前的互通检查：sail 支持的每个协议，以及它在两边都支持的传输层、TLS、REALITY、ECH 与多路复用组合，分别和 sing-box、Mihomo 的发布版对接，客户端与服务端两个方向都跑。

```
一个网络命名空间（--netns，默认 iop1），没有通往外面的路由
  检查程序 --SOCKS--> 客户端 ==协议==> 服务端 --> 回显 / 大块目标（10.233.0.1，dummy 网卡）
  127.0.0.1                127.0.0.1             TLS 1.3 握手目标（127.0.0.1:9443，REALITY 与 ShadowTLS 用）
```

- 一行（case）是协议 × 传输层 × TLS × 多路复用，id 形如 `vless/grpc/reality/-`、`ss(aes-256-gcm)/tcp/off/smux`；一格（cell）是一行在一个方向上的运行，方向写成 `客户端>服务端`。
- 方向的两边取 `sail`、`sb`（sing-box）、`mh`（Mihomo），以及 `sailY`：读 Mihomo 那份 Clash YAML 的 sail，检查 sail 的 Clash 前端（服务端只有 ss、socks、http、mixed 的 listener）。默认方向 `sail>sb,sb>sail,sail>mh,mh>sail`；`sb>mh`、`mh>mh` 之类的组合也能跑，用来判断一个失败是不是对端自己的问题。
- sail 和 sing-box 读同一份 sing-box JSON，Mihomo 读 Clash YAML（脚本自己生成，块格式，字符串按 JSON 加引号）。每格的两份配置、两边的日志和 `result.json` 都在该格的目录里。
- 每格的检查，都经客户端的 SOCKS 入站：TCP 回显（1 字节到 200000 字节的 6 条消息，逐字节比对）；协议承载 UDP 时的 UDP 回显（16 到 1200 字节的 5 个数据报，各最多发 4 次）；大块传输上行、下行各一次（默认 64 MiB，按 1 MiB 块编号的确定性数据，SHA-256 校验，上行由目标回送摘要）。最后确认服务端日志里出现过目标地址，即流量确实经过了被测服务端。
- 有 Mihomo 参与的格子，检查前先等一个字节能往返（最多 10 秒，记为 `warmup_s`）：Mihomo 先打开 listener，再加载 provider，最后才让隧道开始处理连接（`hub/executor/executor.go`），其间到达的连接被直接丢弃（`tunnel/tunnel.go` 的 `isHandle`）。只有 sail 与 sing-box 的格子不等，sail 启动后第一个连接就算数。
- 某一边不支持的组合不跑，列为 skip 并写明原因（`unsupported()`、`dir_skip()`）；协议支持的组合都跑，不因已知失败而跳过。

## 运行

测试机上需要 root、`ip`、`openssl`、Python 3.9+；sail、sing-box、Mihomo 三个二进制按路径给出（sing-box 还用来生成 REALITY、ECH、WireGuard 密钥）。证书与密钥在 `WORK/materials/` 里生成一次，之后复用。

```sh
python3 run.py --list                                  # 只列出各格与 skip 的原因
python3 run.py --work WORK --sail SAIL --sing-box SING_BOX --mihomo MIHOMO
python3 run.py ... --only '^vmess/ws/' --dirs 'sail>mh' --repeat 10 --log-level debug --keep-logs
```

选项：`--dirs` 方向列表；`--only` / `--skip` 按 case id 的正则选取；`--part K/N` 把各行平分成 N 份只跑第 K 份（整行分配，表格完整）；`--jobs N` 同时跑的格数（默认 2；每个 worker 用自己的一对端口，服务端 `20000+100k`、SOCKS `20001+100k`）；`--repeat N` 每格重复 N 次，表里记成 `P(N)` 或 `F(通过数/N)`；`--bulk-mib`、`--bulk-timeout` 大块的大小与时限；`--log-level debug` 所有进程用 debug 日志（默认 info，判定流量经过服务端要用它）；`--keep-logs` 通过的格子也保留日志（默认只留失败格的）。

结果在 `WORK/results/<时间>/`：`summary.md`（每行一个 case、每列一个方向，P / F / skip，其后是每个失败格的错误与 skip 原因汇总）、`summary.json`（`{"schema": 1, "meta": ..., "results": [...], "skips": [...]}`，`meta` 记三方版本）、`targets.log`（每条大块连接在目标一侧收到或发出了多少字节，用来判断丢字节的是哪一段）、`cells/<格>/`。有失败时退出码为 1。

## 共享测试机上的约定

- 命名空间名先用 `ip netns list` 查空闲的，用 `--netns` 指定；已存在时脚本拒绝启动，结束时（包括出错）杀掉命名空间里剩下的进程并删除它。所有进程只在这个命名空间里，宿主机的路由、防火墙不动。命名空间里有一条指向 dummy 网卡的默认路由（包到那里就没了），否则 sing-box 认为没有默认网卡而把 WireGuard 设备关掉。
- 目标服务器都在本机，不访问任何外部地址；脚本本身不产生出口流量。
- 一次完整矩阵（约 500 格、`--jobs 2`）在 4 个 CPU 上约 4 分钟。
