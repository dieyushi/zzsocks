## zzsocks
A Socks5 Proxy For Myself
### build
```sh
git clone git@github.com:dieyushi/zzsocks.git
./compile.sh
```
### usage
#### client
```sh
./zzsocksc 7000 70001
```
- 7000: pac http file server. http://127.0.0.1:7000/proxy.pac
- 7001: use as a local socks5 proxy server

#### server
```sh
./zzsockss 465
```
- 465: server port, deploy in a vps outside

