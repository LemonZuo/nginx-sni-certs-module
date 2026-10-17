# nginx-sni-certs-module

`ngx_http_ssl_cert_dir_module`：nginx 动态模块，在 TLS 握手时按客户端请求的域名（SNI）选择证书。

支持两种证书来源，可以单独使用，也可以同时使用：

| | 证书清单 `ssl_cert_registry` | 证书目录 `ssl_cert_dir` |
|---|---|---|
| 怎么找证书 | JSON 清单里记录 域名 → 证书路径 | 按文件名约定：`<域名>.crt` |
| 一张证书多个域名（SAN） | 支持 | 不支持，要复制多份文件 |
| 证书路径 | 随意 | 必须放在同一个目录 |
| 握手时读磁盘 | **不读**，证书预先读进内存 | 每次握手读一次 |
| 新增证书 | 改清单，一个检查周期内生效，**不用 reload** | 放进目录立即生效 |
| 证书续期 | 改写或 `touch` 清单后生效 | 立即生效 |

主要特性：

- 精确域名 + 单级通配符匹配，语义与 TLS 证书一致；
- 未匹配时可以回退默认证书，也可以直接拒绝握手；
- 清单支持 `isDefault`、`enabled`、一张证书多个域名；
- 清单和证书热更新，不需要 reload nginx；
- 启动时按 worker 的真实身份检查文件权限，并检查证书有效期；
- 只支持 HTTP，不支持 stream 模块。

## 文件

```text
nginx-sni-certs-module/
├── README.md
├── test.sh                                   # 在 Docker 里编译 nginx 和模块并测试
└── ngx_http_ssl_cert_dir_module/
    ├── config
    └── ngx_http_ssl_cert_dir_module.c
```

## 工作原理

### 查找顺序

1. 证书清单：精确域名 → `*.上一级域名`
2. 证书目录：`<dir>/<域名>.crt` → `<dir>/wildcard.<上一级域名>.crt`
3. 证书清单里 `"isDefault": true` 的证书
4. `ssl_certificate` 配置的证书

没有 SNI、或者 SNI 不合法时，直接从第 3 步开始。配置了 `ssl_cert_unmatched reject`（或清单里
`"unmatched": "reject"`）时没有第 3、4 步，直接拒绝握手。

补充说明：

- 通配符只向上找一级，和 TLS 通配符语义一致：`*.example.com` 不匹配 `a.b.example.com`；
- 清单和目录同时配置时，先查清单，再查目录；
- 目录模式的证书由 worker 在握手时读取，文件存在但加载失败（私钥缺失、读不出、和证书不配对）会**直接终止握手**，
  不会回退到默认证书；
- SNI 先严格校验（只允许字母、数字、`-`、`.`，不允许连续或首尾的点）并转成小写，再查表或拼路径；
- 设置证书前会先清掉默认证书（`SSL_certs_clear`），避免默认证书和新证书密钥类型不同（ECDSA / RSA）时仍然选中默认证书。

### 未匹配时的日志

第 1、2 步都没匹配上时，会在 error.log 里写一条 **info** 级别的日志，方便找出哪些域名还没配证书
（`error_log` 设成 `info` 才看得到；默认的 `error` 级别不会写，也没有性能开销）：

```text
[info] ... ssl_cert_dir: no certificate for "new.example.com", using the "isDefault" certificate while SSL handshaking, client: 1.2.3.4, server: 0.0.0.0:443
[info] ... ssl_cert_dir: no server name, handshake rejected while SSL handshaking, client: 5.6.7.8, server: 0.0.0.0:443
```

结尾是 `using the "isDefault" certificate`、`using "ssl_certificate"` 或 `handshake rejected`。
不合法的 SNI 里的控制字符、引号会替换成 `?` 再写进日志，防止伪造日志行。
`reject` 造成的握手失败，nginx 自己也只记 info 级别，不会因为扫描器刷屏。

日志前缀统一是 `ssl_cert_dir`（历史原因），清单模式和目录模式都一样。

## 编译与安装

依赖 jansson（解析 JSON 清单）：

```bash
dnf install jansson-devel        # Rocky / RHEL
apt install libjansson-dev       # Debian / Ubuntu
```

用 nginx 原来的编译参数，再加 `--with-compat` 和本模块。动态模块必须和 nginx 用**同一版本的源码**编译：

```bash
/opt/module/nginx/sbin/nginx -V          # 记下 configure arguments
cd nginx-1.30.5

# 动态模块
./configure <原来的参数> --with-compat \
    --add-dynamic-module=/data/nginx-sni-certs-module/ngx_http_ssl_cert_dir_module
make -j"$(nproc)" && make install

# 只改了模块代码时可以只重编模块
make modules
# 再把 objs/ngx_http_ssl_cert_dir_module.so 复制到 modules/
```

如果整套编译 nginx，也可以静态编入，此时不需要 `load_module`：

```bash
./configure <原来的参数> --add-module=/data/nginx-sni-certs-module/ngx_http_ssl_cert_dir_module
```

其他要求：

- `--with-http_ssl_module`；
- OpenSSL 1.1.1 或更新版本；
- 运行机器上要有 jansson 运行库（Rocky：`jansson`，Debian：`libjansson4`）；
- 动态模块要在 `nginx.conf` 的 main 上下文加载，通常放在最顶部：

  ```nginx
  load_module modules/ngx_http_ssl_cert_dir_module.so;
  ```

  路径相对 nginx 的 `--prefix`，也可以写绝对路径。不加载时使用本模块的指令会报
  `unknown directive "ssl_cert_registry"`。

## 指令

| 指令 | 上下文 | 默认值 | 说明 |
|---|---|---|---|
| `ssl_cert_registry file` | http, server | — | JSON 证书清单 |
| `ssl_cert_registry_interval time` | http | `5s` | 默认检查间隔；清单里写了 `interval` 时以清单为准 |
| `ssl_cert_dir path` | http, server | — | 证书目录 |
| `ssl_cert_unmatched default \| reject` | http, server | `default` | 未匹配时的策略；显式配置的指令优先于清单里的 `unmatched` |

### ssl_cert_registry

```nginx
Syntax:  ssl_cert_registry file;
Default: —
Context: http, server
```

JSON 证书清单的路径。启动时整体加载，任何错误都会让 `nginx -t` / 启动失败。

### ssl_cert_registry_interval

```nginx
Syntax:  ssl_cert_registry_interval time;
Default: 5s;
Context: http
```

每个 worker 每隔多久检查一次清单文件（inode、修改时间、大小）是否变化，变化了就重新加载。

清单顶层写了 `"interval"` 时，以清单里的值为准（每个清单可以不同）；没有写才用这个指令的值。
清单里删掉 `"interval"` 后，会回落到这个指令的值。

### ssl_cert_dir

```nginx
Syntax:  ssl_cert_dir path;
Default: —
Context: http, server
```

证书目录，文件名约定见下文。

### ssl_cert_unmatched

```nginx
Syntax:  ssl_cert_unmatched default | reject;
Default: default;
Context: http, server
```

清单和目录都匹配不上（包括没有 SNI、SNI 不合法）时怎么办：

- `default`：使用默认证书（清单里的 `isDefault` 证书，没有就用 `ssl_certificate`）；
- `reject`：直接拒绝握手，不返回任何证书，别人也就没法通过默认证书知道这台机器上有哪些网站。
  `isDefault` 证书此时不起作用；没有 SNI 的客户端（很老的客户端、一些健康检查）也会被拒绝。

只对配置了 `ssl_cert_registry` 或 `ssl_cert_dir` 的 server 生效。

优先级：只要 nginx 配置里显式写了本指令（写在 http{} 或 server{} 都算），就以指令为准；
没写时使用清单顶层的 `"unmatched"`；清单也没写就是 `default`。
一个 server 只有一套策略，清单里的策略对目录模式未命中的情况同样生效。

### 配置示例

#### 1. 只用证书清单

最常见的用法：证书由脚本或 acme.sh 管理，清单只记录路径。匹配不上时回退 `ssl_certificate`。

```nginx
load_module modules/ngx_http_ssl_cert_dir_module.so;

http {
    ssl_cert_registry_interval 5s;

    server {
        listen 443 ssl;

        # nginx 强制要求，必须配置
        ssl_certificate     /etc/nginx/ssl/default.crt;
        ssl_certificate_key /etc/nginx/ssl/default.key;

        ssl_cert_registry /etc/nginx/ssl/certs.json;
    }
}
```

#### 2. 只用证书目录

证书按 `<域名>.crt` / `<域名>.key` 放好即可，新增证书不用改配置，也不用 reload。

```nginx
http {
    server {
        listen 443 ssl;

        ssl_certificate     /etc/nginx/ssl/default.crt;
        ssl_certificate_key /etc/nginx/ssl/default.key;

        ssl_cert_dir /etc/nginx/ssl/certs;
    }
}
```

#### 3. 清单 + 目录同时使用

先查清单，再查目录。适合从目录模式逐步迁移到清单，或者一部分证书由脚本直接放进目录的场景。

```nginx
http {
    server {
        listen 443 ssl;

        ssl_certificate     /etc/nginx/ssl/default.crt;
        ssl_certificate_key /etc/nginx/ssl/default.key;

        ssl_cert_registry /etc/nginx/ssl/certs.json;   # 优先
        ssl_cert_dir      /etc/nginx/ssl/certs;        # 兜底
    }
}
```

#### 4. 不暴露默认证书

`reject` 会直接拒绝未匹配的 SNI、没有 SNI 的客户端以及用 IP 直接访问的请求。

```nginx
http {
    ssl_cert_unmatched reject;      # 也可以只写在某个 server 里

    server {
        listen 443 ssl;
        server_name _;

        ssl_certificate     /etc/nginx/ssl/default.crt;
        ssl_certificate_key /etc/nginx/ssl/default.key;

        ssl_cert_registry /etc/nginx/ssl/certs.json;
    }
}
```

注意：`ssl_cert_unmatched` 一旦显式写在 http{} 或 server{}，就会覆盖所有清单里的 `unmatched`。

#### 5. 多个 server 使用不同清单和策略

每个清单可以有自己的检查间隔和未匹配策略，写在清单顶层，互不影响：

```nginx
http {
    server {
        listen 443 ssl;
        server_name a.example.com;

        ssl_certificate     /etc/nginx/ssl/default.crt;
        ssl_certificate_key /etc/nginx/ssl/default.key;

        ssl_cert_registry /etc/nginx/ssl/certs-a.json;
    }

    server {
        listen 443 ssl;
        server_name b.example.com;

        ssl_certificate     /etc/nginx/ssl/default.crt;
        ssl_certificate_key /etc/nginx/ssl/default.key;

        ssl_cert_registry /etc/nginx/ssl/certs-b.json;
        ssl_cert_unmatched reject;
    }
}
```

`certs-a.json`：2 秒检查一次，未匹配用默认证书。

```json
{
  "interval": 2,
  "unmatched": "default",
  "certificates": [
    {
      "domains": ["a.example.com"],
      "cert": "/etc/nginx/ssl/a.example.com.crt",
      "key":  "/etc/nginx/ssl/a.example.com.key"
    }
  ]
}
```

`certs-b.json`：30 秒检查一次，未匹配拒绝（server 里显式写了 `reject`，以指令为准）。

```json
{
  "interval": "30s",
  "unmatched": "reject",
  "certificates": [
    {
      "domains": ["b.example.com"],
      "cert": "/etc/nginx/ssl/b.example.com.crt",
      "key":  "/etc/nginx/ssl/b.example.com.key"
    }
  ]
}
```

#### 6. http 级统一配置，server 级覆盖

```nginx
http {
    ssl_cert_registry_interval 5s;
    ssl_cert_registry /etc/nginx/ssl/certs.json;   # 所有 server 继承
    ssl_cert_unmatched default;

    server {
        listen 443 ssl;
        server_name www.example.com;

        ssl_certificate     /etc/nginx/ssl/default.crt;
        ssl_certificate_key /etc/nginx/ssl/default.key;
    }

    server {
        listen 8443 ssl;
        server_name admin.example.com;

        ssl_certificate     /etc/nginx/ssl/default.crt;
        ssl_certificate_key /etc/nginx/ssl/default.key;

        ssl_cert_registry  /etc/nginx/ssl/certs-admin.json;  # 覆盖
        ssl_cert_unmatched reject;                           # 覆盖
    }
}
```

http{} 里的指令会被所有 server 继承，包括没有启用 SSL 的 server；后者用不到本模块，会在
error.log 里写一条 warn（`... ignored in a server without "ssl_certificate"`）。

### 配置注意事项

- 只有配置了 `ssl_cert_registry` 或 `ssl_cert_dir` 的 server 才会启用本模块；
- 写在 http{} 里的指令会被所有 server 继承，server{} 里写了就覆盖；
- `ssl_cert_registry_interval` 只能写在 http{}；需要每个清单不同间隔时，把 `interval` 写进清单；
- 不要和使用变量的 `ssl_certificate` / `ssl_certificate_key` 写在同一个 server 里（两者都会设置 cert_cb）；
- 相对路径按 nginx 配置文件所在目录解析；清单里证书的相对路径按**清单文件所在目录**解析。

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

### 顶层字段

| 字段 | 必填 | 说明 |
|---|---|---|
| `certificates` | 是 | 证书数组，可以为空 |
| `interval` | 否 | 检查间隔。整数表示秒，也可以写成 `"5s"`、`"1m"`；`0` 表示每次握手都检查。覆盖 `ssl_cert_registry_interval` |
| `unmatched` | 否 | `default` 或 `reject`。作为这个清单的默认策略；nginx 配置里显式写了 `ssl_cert_unmatched` 时以指令为准 |

### 每条证书记录

| 字段 | 必填 | 说明 |
|---|---|---|
| `domains` | 是* | 非空数组。支持 `*.example.com` 形式的通配符。`isDefault` 为 `true` 时可以省略 |
| `cert` | 是 | 完整证书链（PEM，叶子证书在前）。相对路径按清单文件所在目录解析 |
| `key` | 是 | 私钥（PEM，不能有密码） |
| `enabled` | 否 | 默认 `true`；`false` 表示暂时停用这一条（它的 `isDefault` 也不生效） |
| `isDefault` | 否 | 默认 `false`；`true` 表示匹配不上时使用这张证书 |

说明：

- 同一个域名出现在多条记录里时，以第一条为准，并在日志里给出警告；
- **最多只能有一条 `isDefault: true`**。写了多条时整份清单视为错误，继续使用旧的证书表；
- 清单里没有默认证书时，回退到 `ssl_certificate`；
- 默认证书也能热更新：改清单就能切换，不用改 nginx 配置；
- 把真实网站的证书设为默认证书，任何人用 IP 或随便一个域名访问都能拿到它，也就知道了这台机器上的网站。
  不想暴露的话，用一张自签名证书（如 `CN=default.invalid`）、不写 `domains`，专门当默认证书。

### 重新加载规则

- **新清单有任何错误**（JSON 格式、证书读不出来、证书和私钥不匹配、`interval` / `unmatched` 取值非法……），
  整份新清单都不生效，**继续使用旧的证书表**，错误写进 error.log，下一个检查周期再试；
- 清单顶层的 `interval` 和 `unmatched` 也随清单一起更新；删掉 `interval` 时回落到
  `ssl_cert_registry_interval`；加载失败时旧的检查间隔和策略继续生效；
- 更新清单要**先写临时文件再 `mv` 替换**，避免 worker 读到只写了一半的文件：

  ```bash
  jq '...' certs.json > certs.json.tmp && mv certs.json.tmp certs.json
  ```

- 证书续期后，清单内容没变，需要 `touch` 一下清单文件，让模块重新读取证书：

  ```bash
  acme.sh --install-cert -d example.com ... --reloadcmd "touch /opt/module/nginx/conf/certs.json"
  ```

- 每个 worker 各自检查、各自加载，所以多个 worker 生效的时间可能相差一个检查周期；
- 检查只在有握手时发生：没有新连接就不会触发重新加载。

## 证书目录格式

`ssl_cert_dir` 指向一个目录，按文件名约定匹配：

```text
/opt/module/nginx/certs/
├── example.com.crt            # 完整证书链
├── example.com.key
├── wildcard.example.org.crt   # 给 *.example.org 用
├── wildcard.example.org.key
└── ...
```

规则：

- 文件名就是域名：`<域名>.crt` / `<域名>.key`；
- 通配符证书命名为 `wildcard.<上一级域名>.crt` / `.key`，例如 `*.example.org` 用 `wildcard.example.org.crt`；
- 域名必须是小写 ASCII（与 SNI 规范化后的形式一致）；
- 一张证书有多个 SAN 时，目录模式不会自动覆盖所有名字，需要为每个名字复制一份文件；
- 匹配不上的域名仍然使用清单里的 `isDefault` 证书或 `ssl_certificate`；
- 目录里的 `default.crt` **不会**自动成为默认证书——默认证书来自 `ssl_certificate` 或清单的 `isDefault`；
- 目录模式每次握手都会 `stat` 并读取 `.crt` / `.key`，高并发场景下开销明显，证书多时建议用清单模式；
- 放置文件后立即生效，不需要 reload。

## 文件权限与启动检查

启动时由 master（root）加载，**运行中的重新加载由 worker 进程完成**，目录模式的证书也是 worker 在握手时读的，
而 worker 不是 root。所以清单文件、证书、私钥都要对 worker 可读：

```bash
chown root:nobody /path/to/*.key   # 编译时指定了 --group=nginx 就换成 nginx
chmod 640 /path/to/*.key
```

### 启动检查

`nginx -t`、启动、reload 时，master 会临时切换成 worker 的用户（`user` 指令，没写就是编译时的默认用户），
把清单文件、清单里的每个证书和私钥、证书目录里的每个 `.crt` / `.key` 都实际打开一次，打不开就写警告：

```text
nginx: [warn] ssl_cert_registry: "/etc/nginx/certs/a.key" is not readable by worker processes (user "nobody") (13: Permission denied)
nginx: [warn] ssl_cert_registry: directory "/root" is not accessible to worker processes (user "nobody"), files under it such as "/root/.acme.sh/a.com_ecc/a.com.key" cannot be read
```

- 是真的用 worker 的身份去打开，附加组、ACL、每一级目录的 `x` 权限都算在内，结果和 worker 实际运行时一致；
- 问题出在某一级目录时直接指出是哪个目录（常见的是 `/root`，Rocky 上权限是 `550`），同一个目录只报一次；
- 只是警告，不会让启动失败；
- 不是 root 启动、`master_process off`、`user root` 时，worker 和 master 是同一个用户，不检查；
- 证书放在 `/root/.acme.sh` 下的话，建议用 `acme.sh --install-cert` 把证书复制到 `/etc/nginx/certs` 这类目录再引用。

### 证书有效期

加载证书时会检查有效期，**30 天内到期**或**已经过期**的写一条警告，证书照常使用：

```text
nginx: [warn] ssl_cert_registry: certificate "/etc/nginx/certs/a.crt" expires in 9 days
nginx: [warn] ssl_cert_dir: certificate "/etc/nginx/certs/old.test.crt" has expired
```

- 清单里的证书：启动时、每次重新加载清单时检查；
- 目录里的证书：`nginx -t`、启动、reload 时检查（握手时不检查，避免每次握手都写日志）；
- 只检查叶子证书的到期时间，不检查中间证书。

## 限制

- 不要和使用变量的 `ssl_certificate` / `ssl_certificate_key` 写在同一个 server 里（两者都会设置 cert_cb）；
- 动态选择的证书没有 OCSP stapling。**不要在使用本模块的 server 上开启 `ssl_stapling`**：
  nginx 会按 `ssl_certificate` 那张证书准备 OCSP 响应，而握手时证书被替换，客户端可能收到不匹配的响应；
- 只支持 http，不支持 stream 模块；
- 清单只在内容（inode、修改时间、大小）变化时重新加载；证书文件单独变化需要 `touch` 清单；
- 目录模式每次握手读盘并解析 PEM，不适合证书很多或 TLS 并发很高的场景；
- 数据源目前只有 JSON。加载逻辑已经和握手逻辑分开（`ngx_http_ssl_cert_registry_build`），
  以后加 SQLite 只需要再写一个读取函数，产出同样的 域名 → 证书 表。

## 测试

```bash
./test.sh                        # 默认 nginx 1.30.5
NGINX_VERSION=1.31.6 ./test.sh   # 指定版本
```

在临时的 `alpine` 容器里编译 nginx 和模块（nginx 默认 `-Werror`，有编译警告会直接失败），然后测试：

- 目录模式（9443）：精确匹配、RSA / ECDSA 混用、通配符、多级子域名、默认证书、无 SNI、非法 SNI；
- 清单模式（9444）：上面这些，加上一张证书多个域名、相对路径、`enabled: false`、`isDefault` 占位证书；
- `ssl_cert_unmatched reject`（9445）：匹配上的照常，匹配不上 / 无 SNI / 非法 SNI 都拒绝握手，`isDefault` 不起作用；
- 清单顶层配置（9447）：`interval` 支持整数和 `"5s"` 形式、`interval: 0` 时下一次握手即生效；
  清单里的 `unmatched` 生效；非法取值整份清单不生效；nginx 指令显式配置时优先于清单；
- 匹配不上的 info 日志：三种结尾都有、非法 SNI 里的引号被替换、带客户端地址、没有 crit 日志；
- 启动检查（单独的配置跑 `nginx -t`）：私钥不可读、目录进不去（同一目录只报一次）、
  30 天内到期、已过期、目录模式的证书；`user root` 时不检查权限；正常配置没有误报；
- 热更新：不 reload nginx，往清单里加证书后生效；
- 清单写坏：继续使用旧的证书表，error.log 有记录；
- 证书续期：替换证书文件并重写清单后生效；
- 默认证书热切换：改成某个真实证书兼做默认；两条 `isDefault` 时拒绝新清单；去掉后回退到 `ssl_certificate`；
- 整个过程中 nginx master 进程没有重启。
