# nginx-sni-certs-module

nginx 动态模块 `ngx_http_ssl_cert_dir_module`：在 TLS 握手时按客户端请求的域名（SNI）选择证书。
支持两种证书来源，可以单独用，也可以一起用：

| | 证书清单 `ssl_cert_registry` | 证书目录 `ssl_cert_dir` |
|---|---|---|
| 怎么找证书 | JSON 清单里记录 域名 → 证书路径 | 按文件名约定：`<域名>.crt` |
| 一张证书多个域名（SAN） | 支持 | 不支持，要复制多份文件 |
| 证书路径 | 随意 | 必须放在同一个目录 |
| 握手时读磁盘 | **不读**，证书预先读进内存 | 每次握手读一次 |
| 新增证书 | 改清单，1 个检查周期内生效，**不用 reload** | 放进目录立即生效 |
| 证书续期 | 改写或 `touch` 清单后生效 | 立即生效 |

另一种实现（只用 nginx 自带功能）在 `/data/nginx-sni-certs-native/`。

## 文件

```
nginx-sni-certs-module/
├── README.md
├── test.sh                                   # 在 Docker 里编译 nginx 和模块并测试
└── ngx_http_ssl_cert_dir_module/
    ├── config
    └── ngx_http_ssl_cert_dir_module.c
```

## 指令

```
Syntax:  ssl_cert_registry file;
Default: —
Context: http, server
```

JSON 证书清单的路径。启动时整体加载，任何错误都会让 `nginx -t` / 启动失败。

```
Syntax:  ssl_cert_registry_interval time;
Default: ssl_cert_registry_interval 5s;
Context: http
```

每个 worker 每隔多久检查一次清单文件（inode、修改时间、大小）是否变化，变化了就重新加载。
清单顶层写了 `"interval"` 时，以清单里的值为准（每个清单可以不同）；没有写才用这个指令的值。

```
Syntax:  ssl_cert_dir path;
Default: —
Context: http, server
```

证书目录。

```
Syntax:  ssl_cert_unmatched default | reject;
Default: ssl_cert_unmatched default;
Context: http, server
```

清单和目录都匹配不上（包括没有 SNI、SNI 不合法）时怎么办：

- `default`：使用默认证书（清单里的 `isDefault` 证书，没有就用 `ssl_certificate`）。
- `reject`：直接拒绝握手，不返回任何证书，别人也就没法通过默认证书知道这台机器上有哪些网站。
  `isDefault` 证书此时不起作用。没有 SNI 的客户端（很老的客户端、一些健康检查）也会被拒绝。

只对配置了 `ssl_cert_registry` 或 `ssl_cert_dir` 的 server 生效。

优先级：只要 nginx 配置里显式写了本指令（写在 http{} 或 server{} 都算），就以指令为准；
没写时使用清单顶层的 `"unmatched"`；清单也没写就是 `default`。
一个 server 只有一套策略，清单里的策略对目录模式未命中的情况同样生效。

相对路径都按配置文件所在目录解析。server 里必须同时配置 `ssl_certificate`，作为默认证书。

## 查找顺序

1. 证书清单：精确域名 → `*.上一级域名`
2. 证书目录：`<dir>/<域名>.crt` → `<dir>/wildcard.<上一级域名>.crt`
3. 证书清单里 `"isDefault": true` 的证书
4. `ssl_certificate` 配置的证书

没有 SNI、或者 SNI 不合法时，直接从第 3 步开始。配置了 `ssl_cert_unmatched reject` 时没有第 3、4 步，直接拒绝握手。

第 1、2 步都没匹配上时，会在 error.log 里写一条 **info** 级别的日志，方便找出哪些域名还没配证书
（`error_log` 设成 `info` 才看得到；默认的 `error` 级别不会写，也没有性能开销）：

```
[info] ... ssl_cert_dir: no certificate for "new.example.com", using the "isDefault" certificate while SSL handshaking, client: 1.2.3.4, server: 0.0.0.0:443
[info] ... ssl_cert_dir: no server name, handshake rejected while SSL handshaking, client: 5.6.7.8, server: 0.0.0.0:443
```

结尾是 `using the "isDefault" certificate`、`using "ssl_certificate"` 或 `handshake rejected`。
不合法的 SNI 里的控制字符和引号会替换成 `?` 再写进日志，防止伪造日志行。
`reject` 造成的握手失败，nginx 自己也只记 info 级别，不会因为扫描器刷屏。

- 通配符只向上找一级，和 TLS 通配符语义一致（`*.example.com` 不匹配 `a.b.example.com`）。
- SNI 先严格校验（只允许字母、数字、`-`、`.`，不允许连续或首尾的点）并转成小写，再查表或拼路径。
- 设置证书前会先清掉默认证书（`SSL_certs_clear`），避免默认证书和新证书密钥类型不同（ECDSA / RSA）时仍然选中默认证书。

## 证书清单格式

清单**只记录域名和证书文件路径**，证书内容仍然放在各自的 `.crt` / `.key` 文件里：

```json
{
  "interval": 5,
  "unmatched": "default",
  "certificates": [
    {
      "domains": ["example.com", "www.example.com", "*.example.com"],
      "cert": "/root/.acme.sh/example.com_ecc/fullchain.cer",
      "key":  "/root/.acme.sh/example.com_ecc/example.com.key"
    },
    {
      "domains": ["old.example.org"],
      "cert": "certs/old.crt",
      "key":  "certs/old.key",
      "enabled": false
    },
    {
      "cert": "certs/default.crt",
      "key":  "certs/default.key",
      "isDefault": true
    }
  ]
}
```

顶层还有两个可选字段：

| 顶层字段 | 说明 |
|---|---|
| `interval` | 检查间隔。整数表示秒，也可以写成 `"5s"`、`"1m"` 这样的时间字符串；`0` 表示每次握手都检查。覆盖 `ssl_cert_registry_interval` |
| `unmatched` | `default` 或 `reject`。作为这个清单的默认策略；nginx 配置里显式写了 `ssl_cert_unmatched` 时以指令为准 |

每条证书记录：

| 字段 | 说明 |
|---|---|
| `domains` | 必填，非空数组。支持 `*.example.com` 形式的通配符。`isDefault` 为 `true` 时可以省略 |
| `cert` | 必填，完整证书链（PEM，叶子证书在前）。相对路径按清单文件所在目录解析 |
| `key` | 必填，私钥（PEM，不能有密码） |
| `enabled` | 可选，默认 `true`；`false` 表示暂时停用这一条（它的 `isDefault` 也不生效） |
| `isDefault` | 可选，默认 `false`；`true` 表示匹配不上时使用这张证书 |

- 同一个域名出现在多条记录里时，以第一条为准，并在日志里给出警告。
- **最多只能有一条 `isDefault: true`**。写了多条时整份清单视为错误，继续使用旧的证书表。
- 清单里没有默认证书时，回退到 `ssl_certificate`。
- 默认证书也能热更新：改清单就能切换，不用改 nginx 配置。
- 把真实网站的证书设为默认证书，任何人用 IP 或随便一个域名访问都能拿到它，也就知道了这台机器上的网站。
  不想暴露的话，用一张自签名证书（如 `CN=default.invalid`）、不写 `domains`，专门当默认证书。

### 重新加载的规则

- **新清单有任何错误**（JSON 格式、证书读不出来、证书和私钥不匹配、`interval` / `unmatched` 取值非法……），
  整份新清单都不生效，**继续使用旧的证书表**，错误写进 error.log，下一个检查周期再试。
- 清单顶层的 `interval` 和 `unmatched` 也随清单一起更新；加载失败时旧的检查间隔和策略继续生效。
- 更新清单要**先写临时文件再 `mv` 替换**，避免 worker 读到只写了一半的文件：

  ```bash
  jq '...' certs.json > certs.json.tmp && mv certs.json.tmp certs.json
  ```

- 证书续期后，清单内容没变，需要 `touch` 一下清单文件，让模块重新读取证书：

  ```bash
  acme.sh --install-cert -d example.com ... --reloadcmd "touch /opt/module/nginx/conf/certs.json"
  ```

- 每个 worker 各自检查、各自加载，所以多个 worker 生效的时间可能相差一个检查周期。

## 编译

依赖 jansson（解析 JSON）：

```bash
dnf install jansson-devel        # Rocky / RHEL
apt install libjansson-dev       # Debian / Ubuntu
```

用原来的编译参数，加上 `--with-compat` 和本模块：

```bash
/opt/module/nginx/sbin/nginx -V          # 记下 configure arguments
cd nginx-1.30.5
./configure <原来的参数> --with-compat \
    --add-dynamic-module=/data/nginx-sni-certs-module/ngx_http_ssl_cert_dir_module
make -j"$(nproc)" && make install
# 以后只改了模块代码：make modules，再把 objs/ngx_http_ssl_cert_dir_module.so 复制到 modules/
```

其他依赖：`--with-http_ssl_module`，OpenSSL 1.1.1+。动态模块必须和 nginx 用同一版本的源码编译。
运行的机器上也要装 jansson 的运行库（Rocky：`jansson`，Debian：`libjansson4`）。

## 使用

```nginx
load_module modules/ngx_http_ssl_cert_dir_module.so;

http {
    ssl_cert_registry_interval 5s;

    server {
        listen 443 ssl;
        ssl_certificate     /opt/module/nginx/certs/default.crt;   # 默认证书，必须配置
        ssl_certificate_key /opt/module/nginx/certs/default.key;
        ssl_cert_registry   /opt/module/nginx/conf/certs.json;
        ssl_cert_dir        /opt/module/nginx/certs;               # 可选
        ssl_cert_unmatched  default;                               # 可选，default | reject
        ...
    }
}
```

### 文件权限

启动时由 master（root）加载，**运行中的重新加载由 worker 进程完成**，目录模式的证书也是 worker 在握手时读的，
而 worker 不是 root。所以清单文件、证书、私钥都要对 worker 可读：

```bash
chown root:nobody /path/to/*.key   # 编译时指定了 --group=nginx 就换成 nginx
chmod 640 /path/to/*.key
```

**启动检查**：`nginx -t`、启动、reload 时，master 会临时切换成 worker 的用户（`user` 指令，没写就是编译时的默认用户），
把清单文件、清单里的每个证书和私钥、证书目录里的每个 `.crt` / `.key` 都实际打开一次，打不开就写警告：

```
nginx: [warn] ssl_cert_registry: "/etc/nginx/certs/a.key" is not readable by worker processes (user "nobody") (13: Permission denied)
nginx: [warn] ssl_cert_registry: directory "/root" is not accessible to worker processes (user "nobody"), files under it such as "/root/.acme.sh/a.com_ecc/a.com.key" cannot be read
```

- 是真的用 worker 的身份去打开，附加组、ACL、每一级目录的 `x` 权限都算在内，结果和 worker 实际运行时一致。
- 问题出在某一级目录时直接指出是哪个目录（常见的是 `/root`，Rocky 上权限是 `550`），同一个目录只报一次。
- 只是警告，不会让启动失败。
- 不是 root 启动、`master_process off`、`user root` 时，worker 和 master 是同一个用户，不检查。
- 证书放在 `/root/.acme.sh` 下的话，建议用 `acme.sh --install-cert` 把证书复制到 `/etc/nginx/certs` 这类目录再引用。

### 证书有效期

加载证书时会检查有效期，**30 天内到期**或**已经过期**的写一条警告，证书照常使用：

```
nginx: [warn] ssl_cert_registry: certificate "/etc/nginx/certs/a.crt" expires in 9 days
nginx: [warn] ssl_cert_dir: certificate "/etc/nginx/certs/old.test.crt" has expired
```

- 清单里的证书：启动时、每次重新加载清单时检查。
- 目录里的证书：`nginx -t`、启动、reload 时检查（握手时不检查，避免每次握手都写日志）。
- 只检查叶子证书的到期时间，不检查中间证书。

## 限制 / 后续可以做的

- 不要和使用变量的 `ssl_certificate` 写在同一个 server 里（两者都会设置 cert_cb）。
- 动态加载的证书没有 OCSP stapling。
- 只支持 http，不支持 stream 模块。
- 清单只在内容（inode、修改时间、大小）变化时重新加载；证书文件单独变化需要 `touch` 清单。
- 数据源目前只有 JSON。加载逻辑已经和握手逻辑分开（`ngx_http_ssl_cert_registry_build`），
  以后加 SQLite 只需要再写一个读取函数，产出同样的 域名 → 证书 表。

## 测试

```bash
./test.sh                        # 默认 nginx 1.30.5
NGINX_VERSION=1.31.6 ./test.sh   # 指定版本
```

在临时的 `alpine` 容器里编译 nginx 和模块（nginx 默认 `-Werror`，有编译警告会直接失败），然后测试：

- 目录模式（9443）：精确匹配、RSA / ECDSA 混用、通配符、多级子域名、默认证书、无 SNI、非法 SNI
- 清单模式（9444）：上面这些，加上一张证书多个域名、相对路径、`enabled: false`、`isDefault` 占位证书
- `ssl_cert_unmatched reject`（9445）：匹配上的照常，匹配不上 / 无 SNI / 非法 SNI 都拒绝握手，`isDefault` 不起作用
- 清单顶层配置（9447）：`interval` 支持整数和 `"5s"` 形式、`interval: 0` 时下一次握手即生效；
  清单里的 `unmatched` 生效；非法取值整份清单不生效；nginx 指令显式配置时优先于清单
- 匹配不上的 info 日志：三种结尾都有、非法 SNI 里的引号被替换、带客户端地址、没有 crit 日志
- 启动检查（单独的配置跑 `nginx -t`）：私钥不可读、目录进不去（同一目录只报一次）、
  30 天内到期、已过期、目录模式的证书；`user root` 时不检查权限；正常配置没有误报
- 热更新：不 reload nginx，往清单里加证书后生效
- 清单写坏：继续使用旧的证书表，error.log 有记录
- 证书续期：替换证书文件并重写清单后生效
- 默认证书热切换：改成某个真实证书兼做默认；两条 `isDefault` 时拒绝新清单；去掉后回退到 `ssl_certificate`
- 整个过程中 nginx master 进程没有重启
