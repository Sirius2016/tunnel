## Tunnel是一个简单的代理工具

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
    
* 通讯协议支持: kcp+aes(UDP), tcp+tls(TCP).

* 传输压缩支持: disable, snappy, zlib

### 服务器端使用

```bash
./tunnel -server -conf tunnel-server.yaml
```

### 客户端使用

```bash
./tunnel -client -conf tunnel-client.yaml
```

