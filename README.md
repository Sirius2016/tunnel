Tunnel is a simple proxy tool.

# Binary/config file 
both server/client are compiled in one binary file and share same config file.

config file sample is [here](/conf/tunnel.yaml).

* proxy rule:
    - geoip: based on country
    - whitelist/blacklist: based on regular expression matching
     
* protocols supported(on same local port)
    * socks4
    * socks5
    * http
    * https
    
* protocols supported: kcp+aes(UDP), tcp+tls(TCP).
* compression: disable, zstd, flate, s2
    see [https://github.com/klauspost/compress](https://github.com/klauspost/compress) for more details

# License
MIT.