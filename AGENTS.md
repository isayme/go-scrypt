# Agents Documentation

## Project Overview

go-scrypt 是一个轻量级的 scrypt 密码哈希和校验库，基于 golang.org/x/crypto/scrypt 实现。

## Core Components

### scrypt.go

- `Params` 结构体：定义 scrypt 参数 (N, R, P, KeyLen)
- `DefaultParams`：默认参数 (N=16384, R=8, P=1, KeyLen=32)
- `Hash(password, params)`：生成密码哈希，自动生成 salt
- `Verify(password, hashed)`：校验密码是否匹配，使用 constant-time 比较防止时序攻击
- `parseHashed()`：内部函数，解析哈希字符串提取参数和原始数据

### Hash Format

```
$scrypt$n=<N>,r=<R>,p=<P>$<salt>$<key>
```

- salt: 8 字节随机数据，base64 编码
- key: 32 字节派生密钥，base64 编码

## Key Design Decisions

- 使用 base64 编码存储 salt 和 key，便于存储和传输
- 参数顺序可灵活解析（如 `n=16384,r=8,p=1` 或 `r=8,p=1,n=16384`）
- 依赖 golang.org/x/crypto/scrypt，不引入额外依赖
- 使用 `crypto/subtle.ConstantTimeCompare` 防止时序攻击

## Testing

使用 testify 框架，运行测试：

```bash
go test -v ./...
```
