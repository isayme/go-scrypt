# go-scrypt

[![Go Doc](https://godoc.org/github.com/isayme/go-scrypt?status.svg)](https://pkg.go.dev/github.com/isayme/go-scrypt)
[![Coverage Status](https://coveralls.io/repos/github/isayme/go-scrypt/badge.svg?branch=master)](https://coveralls.io/github/isayme/go-scrypt?branch=master)

scrypt password hashing and verification for Go.

## Install

```bash
go get github.com/isayme/go-scrypt
```

## Usage

### Hash a password

```go
hashed, err := scrypt.Hash("your plain password", scrypt.DefaultParams)
if err != nil {
    log.Fatal(err)
}
```

### Verify a password

```go
ok, err := scrypt.Verify("your plain password", hashed)
if err != nil {
    log.Fatal(err)
}
if !ok {
    log.Fatal("invalid password")
}
```

### Custom params

```go
params := scrypt.Params{
    N:      16384,
    R:      8,
    P:      1,
    KeyLen: 32,
}

hashed, err := scrypt.Hash("password", params)
```

## Hash format

```
$scrypt$n=<N>,r=<R>,p=<P>$<salt>$<key>
```

| Field | Description                        |
|-------|-------------------------------------|
| N     | CPU/memory cost parameter           |
| r     | Block size parameter                |
| p     | Parallelization parameter           |
| salt  | Random salt (base64 encoded)       |
| key   | Derived key (base64 encoded)       |

## Test

```bash
go test -v ./...
```
