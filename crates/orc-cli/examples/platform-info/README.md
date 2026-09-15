# platform-info

Tiny ORC example app that demonstrates a shared payload, a per-platform
payload, config interpolation, and platform-specific `vars`.

Build all platforms:

```sh
orc build -t localhost/acme/platform-info:1.0.0
```

Build one platform:

```sh
orc build --platform linux/amd64 -t localhost/acme/platform-info:linux-amd64
```

Write an OCI layout for inspection:

```sh
orc build -t localhost/acme/platform-info:1.0.0 --output ./out
```
