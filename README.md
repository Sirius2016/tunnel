## Tunnel是一个简单的代理工具

- 使用用场：**适合大文件下载加速**

###  编译生成二进制文件
```bash
git clone https://github.com/Sirius2016/tunnel.git
cd tunnel
go build ./
```

默认配置文件 (src/conf/tunnel.yaml).

* 代理规则，需要GeoLite2-Country.mmdb数据库:
    - geoip: based on country
    - whitelist/blacklist: based on regular expression matching
* 支持的协议(监听本地端口)
    * socks4
    * socks5
    * http
    * https
* 通讯协议支持: kcp+aes(UDP), tcp+tls(TCP)
    - 推荐使用TCP协议，实际测试速度最大可以达5MB
    - kcp协议，实际测试速度只有200KB
* 传输压缩支持: disable, snappy, zlib
    - 推荐使用：snappy

### 服务器端使用

```bash
./tunnel -server -conf tunnel-server.yaml
```

### 客户端使用

```bash
./tunnel -client -conf tunnel-client.yaml
```

