## zzsocks
[![Build Status](https://magnum.travis-ci.com/dieyushi/zzsocks.svg?token=s6xxY2qssnWNqsUwWYZZ&branch=dev)](https://magnum.travis-ci.com/dieyushi/zzsocks)

A Socks5 Proxy For Myself
### build
```sh
git clone git@github.com:dieyushi/zzsocks.git
./compile.sh
```
### usage
#### client
```sh
./zzsocksc 7000 70001 127.0.0.1 465 123456
```
- 7000: pac http file server. http://127.0.0.1:7000/proxy.pac
- 7001: use as a local socks5 proxy server
- 127.0.0.1: ip of your vps server
- 465: server port, deploy in a vps outside
- 123456: password used for encrypt commucation

#### server
```sh
./zzsockss 465 123456
```
- 465: server port, deploy in a vps outside
- 123456: password used for encrypt commucation

