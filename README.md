# nginx-sni-certs-module

`ngx_http_ssl_cert_dir_module`：nginx 动态模块，在 TLS 握手时按客户端请求的域名（SNI）选择证书。

整个模块只有一条指令 `ssl_cert_registry`，指向一份 JSON 清单。证书从哪来、怎么匹配、多久检查一次，都写在清单里。

## 两种证书来源

清单里可以只写一种，也可以两种都写。

| | 清单里的 `certificates` | 清单里的 `directory` |
|---|---|---|
| 怎么找证书 | 记录 域名 → 证书路径 | 按文件名约定：`<域名>.crt` |
| 一张证书多个域名（SAN） | 支持 | 不支持，要复制多份文件 |
| 证书路径 | 随意 | 必须放在同一个目录 |
| 握手时读磁盘 | 不读，证书预先解析好放在内存里 | 缓存命中时只 `stat` 一次 |
| 新增证书 | 改清单，一个检查周期内生效，不用 reload | 放进目录立即生效 |
| 证书续期 | 改写或 `touch` 清单后生效 | 立即生效 |
| 服务端开销 | 无（哈希查找） | 测不出（缓存命中，见[性能](#性能)） |

## 主要特性

- **零外部依赖**：JSON 由模块自带的解析器处理，编译只需要 nginx 源码和 OpenSSL
- 精确域名 + 单级通配符匹配，语义与 TLS 证书一致
- 未匹配时可以回退默认证书，也可以直接拒绝握手
- 支持 `isDefault`、`enabled`、一张证书多个域名
- 清单热更新，不需要 reload nginx；清单写错时继续用旧的证书表
- 启动时按 worker 的真实身份检查文件权限，并检查证书有效期

## 文件

```text
nginx-sni-certs-module/
├── README.md
├── test.sh                                     # 在 Docker 里编译 nginx 和模块并测试
├── bench.sh                                    # 在 Docker 里做 TLS 握手性能对比
├── .github/workflows/release.yml               # 打标签时编译并发布 .so
└── ngx_http_ssl_cert_dir_module/
    ├── config                                  # 构建描述
    ├── ngx_http_ssl_cert_dir_module.c          # 模块主体：配置、启动检查、握手、清单加载
    ├── ngx_http_ssl_cert_json.h
    └── ngx_http_ssl_cert_json.c                # 自带的极简 JSON 解析器
```

## 工作原理

### 查找顺序

1. 清单里的 `certificates`：精确域名 → `*.上一级域名`
2. 清单里的 `directory`：`<dir>/<域名>.crt` → `<dir>/wildcard.<上一级域名>.crt`
3. 清单里 `"isDefault": true` 的证书
4. `ssl_certificate` 配置的证书

清单里写了 `"unmatched": "reject"` 时没有第 3、4 步，直接拒绝握手。没有 SNI、或者 SNI 不合法时，直接从第 3 步开始。

其他规则：

- 通配符只向上找一级：`*.example.com` 不匹配 `a.b.example.com`，也不匹配 `example.com` 本身
- 同时配了两种来源时，先查清单，再查目录
- SNI 先严格校验（只允许字母、数字、`-`、`.`，不允许连续或首尾的点）并转成小写，再查表或拼路径
- 设置证书前先清掉默认证书（`SSL_certs_clear`），避免默认证书和新证书密钥类型不同（ECDSA / RSA）时仍然选中默认证书
- 目录模式的证书由 worker 在握手时读取，文件存在但加载失败（私钥缺失、读不出、和证书不配对）会**直接终止握手**，不回退到默认证书

### 未匹配时的日志

第 1、2 步都没匹配上时，会写一条 **info** 级别的日志，方便找出哪些域名还没配证书。默认的 `error` 级别不会写，也没有性能开销。

```text
[info] ... ssl_cert_dir: no certificate for "new.example.com", using the "isDefault" certificate while SSL handshaking, client: 1.2.3.4, server: 0.0.0.0:443
[info] ... ssl_cert_dir: no server name, handshake rejected while SSL handshaking, client: 5.6.7.8, server: 0.0.0.0:443
```

结尾有三种：`using the "isDefault" certificate`、`using "ssl_certificate"`、`handshake rejected`。

- 日志前缀：清单里的证书用 `ssl_cert_registry`，目录模式的证书用 `ssl_cert_dir`（历史原因，两者其实是同一套代码）
- 不合法 SNI 里的控制字符、引号会替换成 `?`，防止伪造日志行
- `reject` 造成的握手失败，nginx 自己也只记 info 级别，不会因为扫描器刷屏

## 编译与安装

只需要 nginx 源码和 OpenSSL，**不需要装任何第三方库**。动态模块必须和 nginx 用**同一版本的源码**编译：

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

整套编译 nginx 时也可以静态编入，此时不需要 `load_module`：

```bash
./configure <原来的参数> --add-module=/data/nginx-sni-certs-module/ngx_http_ssl_cert_dir_module
```

其他要求：

- 编译时带 `--with-http_ssl_module`，OpenSSL 1.1.1 或更新版本
- 用动态模块时，要在 `nginx.conf` 的 main 上下文加载（通常放在最顶部），路径相对 nginx 的 `--prefix`，也可以写绝对路径：

```nginx
load_module modules/ngx_http_ssl_cert_dir_module.so;
```

不加载时使用本模块的指令会报 `unknown directive "ssl_cert_registry"`。

## 指令

只有一条：

```nginx
Syntax:  ssl_cert_registry file;
Default: —
Context: http, server
```

JSON 证书清单的路径。启动时整体加载，任何错误都会让 `nginx -t` / 启动失败。

- 只有配置了本指令的 server 才会启用模块
- 写在 http{} 里会被所有 server 继承，server{} 里写了就覆盖
- 相对路径按 nginx 配置文件所在目录解析
- 策略和目录都在清单里，**同一份清单被多个 server 引用时共用同一套配置**，需要区分就拆成多份清单

### 配置示例

**1. 只用清单**

```nginx
load_module modules/ngx_http_ssl_cert_dir_module.so;

http {
    server {
        listen 443 ssl;

        # nginx 强制要求，必须配置
        ssl_certificate     /etc/nginx/ssl/default.crt;
        ssl_certificate_key /etc/nginx/ssl/default.key;

        ssl_cert_registry /etc/nginx/ssl/certs.json;
    }
}
```

**2. 只用目录**

nginx 配置和示例 1 一样，只把指令指向另一份清单 `dir.json`；清单里只写 `directory`：

```json
{
  "directory": "/etc/nginx/ssl/certs"
}
```

**3. 清单 + 目录**

```json
{
  "mode": "both",
  "interval": 5,
  "directory": "certs",
  "certificates": [
    {
      "domains": ["example.com", "www.example.com", "*.example.com"],
      "cert": "example.com/fullchain.pem",
      "key":  "example.com/privkey.pem"
    },
    {
      "cert": "default.pem",
      "key":  "default.key",
      "isDefault": true
    }
  ]
}
```

`certs`、`example.com/fullchain.pem` 这些相对路径都按**清单文件所在目录**解析。

**4. 不暴露默认证书**

加上 `"unmatched": "reject"`，拒绝未匹配的 SNI、没有 SNI 的客户端，以及用 IP 直接访问的请求：

```json
{
  "unmatched": "reject",
  "certificates": [
    {
      "domains": ["example.com", "www.example.com"],
      "cert": "example.com/fullchain.pem",
      "key":  "example.com/privkey.pem"
    }
  ]
}
```

**5. 多个 server 用不同清单**

```nginx
http {
    server {
        listen 443 ssl;
        server_name a.example.com;
        ssl_certificate     /etc/nginx/ssl/default.crt;
        ssl_certificate_key /etc/nginx/ssl/default.key;
        ssl_cert_registry   /etc/nginx/ssl/certs-a.json;   # 内部站点，未匹配用默认证书
    }

    server {
        listen 8443 ssl;
        server_name b.example.com;
        ssl_certificate     /etc/nginx/ssl/default.crt;
        ssl_certificate_key /etc/nginx/ssl/default.key;
        ssl_cert_registry   /etc/nginx/ssl/certs-b.json;   # 对外站点，未匹配直接拒绝
    }
}
```

## 证书清单格式

```json
{
  "mode": "both",
  "interval": 5,
  "unmatched": "default",
  "directory": "certs",
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
| `certificates` | 否 | 证书数组。和 `directory` 至少要有一个 |
| `directory` | 否 | 证书目录。相对路径按清单文件所在目录解析 |
| `mode` | 否 | `certificates` / `directory` / `both`，显式指定用哪种来源；默认按配了哪些字段推断 |
| `cache` | 否 | 目录模式的证书缓存条数，默认 1024；`0` 表示不缓存 |
| `interval` | 否 | 检查间隔。整数表示秒，也可以写成 `"5s"`、`"1m"`；`0` 表示每次握手都检查；默认 5 |
| `unmatched` | 否 | `default` 或 `reject`，默认 `default` |

### mode：显式指定用哪种来源

不写 `mode` 时按字段推断：只配 `certificates` 就是清单模式，只配 `directory` 就是目录模式，两个都配就都用。写了 `mode` 就完全以它为准：

| `mode` | 生效的来源 | 另一份配置 |
|---|---|---|
| `"certificates"` | `certificates` | `directory` 被忽略，写一条 warn |
| `"directory"` | `directory` | `certificates` 被忽略，写一条 warn |
| `"both"` | 两者 | — |

被忽略的那份配置**不是错误**，可以放心留着：想临时从"清单 + 目录"切到"只用清单"，把 `mode` 改成 `"certificates"` 就行，不用把 `directory` 删掉。

| 情况 | 结果 |
|---|---|
| 有配置被忽略 | 写 warn，清单正常生效：`[warn] ... "mode" is "certificates", "directory" is ignored` |
| `mode` 选中的来源没有配置 | 报错，整份清单不生效（没有任何证书可用） |
| 加载成功 | 写 notice，打印生效的 mode、目录、缓存条数等 |

```text
[error] ssl_cert_registry: "/etc/nginx/ssl/certs.json": "mode" is "certificates" but "certificates" is not present
[error] ssl_cert_registry: "/etc/nginx/ssl/certs.json": "mode" is "both" but "certificates" and "directory" must both be present

[notice] ssl_cert_registry: "/etc/nginx/ssl/certs.json" loaded: 2 certificates, 3 domains, default: yes, mode: both, directory: /etc/nginx/ssl/certs, cache: 1024, interval: 5, unmatched: default
```

### 每条证书记录

| 字段 | 必填 | 说明 |
|---|---|---|
| `domains` | 是* | 非空数组。支持 `*.example.com` 形式的通配符。`isDefault` 为 `true` 时可以省略 |
| `cert` | 是 | 完整证书链（PEM，叶子证书在前）。相对路径按清单文件所在目录解析 |
| `key` | 是 | 私钥（PEM，不能有密码） |
| `enabled` | 否 | 默认 `true`；`false` 表示暂时停用这一条（它的 `isDefault` 也不生效） |
| `isDefault` | 否 | 默认 `false`；`true` 表示匹配不上时使用这张证书 |

- 同一个域名出现在多条记录里时，**以 JSON 里先出现的为准**，并写一条警告
- 被忽略的那条仍然会被读取和解析，它上面的 `isDefault: true` **依然生效**（日志只提示域名重复，不会提示它成了默认证书）
- **最多只能有一条 `isDefault: true`**，写了多条时整份清单视为错误，继续使用旧的证书表
- 清单里没有默认证书时，回退到 `ssl_certificate`
- 默认证书也能热更新：改清单就能切换，不用改 nginx 配置

> **默认证书会暴露网站信息。** 把真实网站的证书设为默认证书，任何人用 IP 或随便一个域名访问都能拿到它。不想暴露的话，用一张自签名证书（如 `CN=default.invalid`）、不写 `domains`，专门当默认证书。

### 支持的 JSON 写法

清单由模块自带的解析器处理，只实现需要的那部分 JSON。**遇到不支持的写法会直接报错**（带行号），而不是勉强接受：

| 支持 | 不支持 |
|---|---|
| 对象、数组、字符串、非负整数、`true` / `false` | 小数、指数、负数、`null`、`\uXXXX` 转义 |

硬性限制：

- 嵌套最多 8 层（清单实际只用到 4 层）
- 对象的成员名不能重复
- 顶层必须是一个对象
- 解析完之后文件末尾不能有多余内容

域名和路径都是 ASCII，用不到 `\u` 转义；真要写非 ASCII 字符，直接写 UTF-8 即可。

### 重新加载规则

- **新清单有任何错误**（JSON 格式、证书读不出来、证书和私钥不匹配、`interval` / `unmatched` 取值非法……），整份新清单都不生效，**继续使用旧的证书表**，错误写进 error.log，下一个检查周期再试
- 清单顶层的 `interval`、`unmatched`、`directory` 随清单一起更新；加载失败时旧值继续生效
- 清单里删掉 `interval` 时回落到默认的 5 秒，而不是沿用上一份清单的值
- 每个 worker 各自检查、各自加载，多个 worker 生效的时间可能相差一个检查周期
- 检查只在有握手时发生：没有新连接就不会触发重新加载

更新清单要**先写临时文件再 `mv` 替换**，避免 worker 读到只写了一半的文件：

```bash
jq '...' certs.json > certs.json.tmp && mv certs.json.tmp certs.json
```

证书续期后清单内容没变，需要 `touch` 一下清单文件，让模块重新读取证书：

```bash
acme.sh --install-cert -d example.com ... --reloadcmd "touch /opt/module/nginx/conf/certs.json"
```

## 证书目录格式

`directory` 指向一个目录，按文件名约定匹配：

```text
/opt/module/nginx/certs/
├── example.com.crt            # 完整证书链
├── example.com.key
├── wildcard.example.org.crt   # 给 *.example.org 用
├── wildcard.example.org.key
└── ...
```

- 文件名就是域名：`<域名>.crt` / `<域名>.key`，域名必须是小写 ASCII（与 SNI 规范化后的形式一致）
- 通配符证书命名为 `wildcard.<上一级域名>.crt` / `.key`，例如 `*.example.org` 用 `wildcard.example.org.crt`
- 一张证书有多个 SAN 时，不会自动覆盖所有名字，需要为每个名字复制一份文件
- 匹配不上的域名仍然使用清单里的 `isDefault` 证书或 `ssl_certificate`
- 目录里的 `default.crt` **不会**自动成为默认证书，默认证书只来自 `ssl_certificate` 或清单的 `isDefault`
- 放置文件后立即生效，不需要 reload
- 解析结果会缓存，条数由清单里的 `cache` 决定（默认 1024）

### 证书缓存

目录模式每次握手都要打开并解析证书链和私钥，实测这部分约 50 µs，其中 PEM / ASN.1 解析占 95% 以上，磁盘 I/O 只占 2 µs 左右（整条链路端到端的开销见[性能](#性能)）。所以解析结果会缓存起来：

| 情况 | 行为 |
|---|---|
| 缓存命中 | 证书文件的 inode、修改时间、大小都没变，把解析好的对象直接挂到连接上，只花一次 `stat` |
| 未命中 / 文件变了 | 重新解析，然后替换缓存项 |
| 缓存满了 | 淘汰最早插入的那一条（FIFO，环形数组） |

设计取舍：

- **FIFO 而不是 LRU**：证书集合通常稳定（每个域名固定用一张证书），LRU 多出来的链表维护在命中路径上不划算
- **缓存挂在证书表的内存池上**：清单重新加载时缓存跟着旧表一起释放，不会出现"清单已经换了、缓存里还是旧证书"
- **只 `stat` 证书文件，不 `stat` 私钥**：两者总是成对更新，检查一个就够，省一次系统调用
- **`cache: 0` 关掉缓存**：行为和以前一致（每次握手读盘解析），给"证书经常原地改写"这类场景留一个退路

`cache` 按域名数设置即可：命中才省开销，条数小于实际域名数时会来回淘汰，退化成"每次都重新解析"。

替换缓存项时释放旧对象是安全的：`SSL_use_cert_and_key()` 会给证书和私钥加引用计数，正在握手的连接持有自己的引用（在 OpenSSL 3.5 上实测验证过）。

## 文件权限与启动检查

启动时由 master（root）加载，**运行中的重新加载由 worker 进程完成**，目录模式的证书也是 worker 在握手时读的，而 worker 不是 root。所以清单文件、证书、私钥都要对 worker 可读：

```bash
chown root:nobody /path/to/*.key   # 编译时指定了 --group=nginx 就换成 nginx
chmod 640 /path/to/*.key
```

### 启动检查

`nginx -t`、启动、reload 时，master 会临时切换成 worker 的用户（`user` 指令，没写就是编译时的默认用户），把清单文件、清单里的每个证书和私钥、清单里配置的证书目录下的每个 `.crt` / `.key` 都实际打开一次，打不开就写警告：

```text
nginx: [warn] ssl_cert_registry: "/etc/nginx/certs/a.key" is not readable by worker processes (user "nobody") (13: Permission denied)
nginx: [warn] ssl_cert_registry: directory "/root" is not accessible to worker processes (user "nobody"), files under it such as "/root/.acme.sh/a.com_ecc/a.com.key" cannot be read
```

- 是真的用 worker 的身份去打开，附加组、ACL、每一级目录的 `x` 权限都算在内，结果和 worker 实际运行时一致
- 问题出在某一级目录时直接指出是哪个目录（常见的是 `/root`，Rocky 上权限是 `550`），同一个目录只报一次
- 只是警告，不会让启动失败
- 不是 root 启动、`master_process off`、`user root` 时，worker 和 master 是同一个用户，不检查
- 证书放在 `/root/.acme.sh` 下的话，建议用 `acme.sh --install-cert` 把证书复制到 `/etc/nginx/certs` 这类目录再引用
- 启动检查扫描的是启动那一刻清单里的 `directory`；运行中改了 `directory`，只影响启动检查的覆盖面，握手时用的始终是清单里的新值

### 证书有效期

加载证书时会检查有效期，**30 天内到期**或**已经过期**的写一条警告，证书照常使用：

```text
nginx: [warn] ssl_cert_registry: certificate "/etc/nginx/certs/a.crt" expires in 9 days
nginx: [warn] ssl_cert_dir: certificate "/etc/nginx/certs/old.test.crt" has expired
```

- 清单里的证书：启动时、每次重新加载清单时检查
- 目录里的证书：`nginx -t`、启动、reload 时检查（握手时不检查，避免每次握手都写日志）
- 只检查叶子证书的到期时间，不检查中间证书

## 性能

`./bench.sh` 可以在容器里复现这组数据。

测试方法：

- 环境：8 vCPU 容器，ECDSA P-256，TLS 1.3，关闭会话复用（每个请求一次完整握手）
- 每个场景预热后跑 7 轮，每轮把场景顺序轮转一位，抵消宿主机负载随时间的漂移
- 每轮的开头和结尾各测一次静态证书（基线），取平均当作这一轮的基线；各场景减去**同一轮**的基线，再对 7 轮取中位数
- 服务端 CPU 取自 worker 的 `/proc/<pid>/stat`（utime + stime，含内核网络开销），所以看**差值**比看绝对值有意义
- 下面是把两次独立运行合起来的结果（每个场景 14 个轮次样本），「逐轮范围」是这些差值的 min ~ max

| 场景 | 服务端 CPU | 相对静态 | 逐轮范围 | 吞吐 |
|---|---:|---:|---:|---:|
| 静态证书（基线，不使用本模块） | 386 µs | — | — | 7380 req/s |
| 清单命中 | 393 µs | −2 µs | −25 ~ +33 | 7342 req/s |
| 清单通配符命中 | 389 µs | +4 µs | −34 ~ +33 | 7172 req/s |
| 清单未命中（用默认证书） | 395 µs | +1 µs | −40 ~ +54 | 7297 req/s |
| 清单 1000 条 | 381 µs | 0 µs | −29 ~ +78 | 7430 req/s |
| 清单 `interval: 0` | 381 µs | 0 µs | −37 ~ +39 | 7520 req/s |
| 目录命中（缓存生效） | 386 µs | −4 µs | −44 ~ +42 | 7360 req/s |
| 目录通配符命中（缓存生效） | 370 µs | −5 µs | −55 ~ +16 | 7678 req/s |
| 目录未命中 | 376 µs | −5 µs | −38 ~ +56 | 7583 req/s |
| **目录命中（`cache: 0`）** | 458 µs | **+76 µs** | **+43 ~ +194** | 7069 req/s |

结论：

- **清单模式测不出开销**：命中、通配符、未命中、1000 条、`interval: 0` 的差值都在噪声范围内。1000 条与 2 条一致，确认是哈希查找，与条目数无关
- **目录模式加了缓存之后也测不出开销**：差值的范围正负都有，和噪声无法区分。剩下的是每个连接一次 `stat` 加 `SSL_certs_clear` + `SSL_use_cert_and_key`
- **关掉缓存则明确可测**：`cache: 0` 时每轮都慢 43 µs 以上，中位 +76 µs——这是读盘加解析 PEM 的代价，也是缓存省下来的部分
- **目录未命中几乎免费**：失败的文件查找走 VFS 负缓存，与静态证书无差异

绝对值受宿主机负载影响会整体漂移（两次运行之间差 10% 以上很常见），所以只有同一轮内相减出来的差值有意义。

### 重新加载清单的开销

| 清单条目 | reload 耗时 | worker 内存 |
|---:|---:|---:|
| 100 | 13 ms | 7.7 MB |
| 1000 | 68 ms | 15.1 MB |
| 5000 | 324 ms | 45.4 MB |
| 10000 | 645 ms | 82.3 MB |

每个条目约 70 µs、7.6 KB，基本线性。

- reload 在 worker 的事件循环里**同步**执行，证书很多时该 worker 上的其他连接要等：1000 条约 70 ms 基本无感，10000 条接近 0.7 s 就需要注意了
- 内存是**每个 worker 一份**（各自 reload 之后不再共享）
- reload 只在清单文件变化时发生，也就是续期或改配置的时候

### 规模建议

- **几百个域名以内随便用**，两种模式的开销都测不出来
- 域名多、并发高时优先用清单模式；域名来自"同一主域的多个子域"时，一张通配符证书就能把条目数压到个位数
- 目录模式现在的开销也很小，主要优势是"放文件即生效"；代价是每次握手一次 `stat`，以及缓存条数要按域名数配够

## 限制

- 只支持 http，不支持 stream 模块
- 不要和使用变量的 `ssl_certificate` / `ssl_certificate_key` 写在同一个 server 里（两者都会设置 cert_cb）
- **不要在使用本模块的 server 上开启 `ssl_stapling`**：nginx 会按 `ssl_certificate` 那张证书准备 OCSP 响应，而握手时证书被替换，客户端可能收到不匹配的响应
- 清单只在内容（inode、修改时间、大小）变化时重新加载；证书文件单独变化需要 `touch` 清单。修改时间精度到秒，原地改写且大小不变、又发生在同一秒内可能漏检，用 `mv` 原子替换可以避免
- 同一份清单被多个 server 引用时共用策略和目录，需要区分就拆清单
- 目录模式每次握手至少一次 `stat`，缓存未命中时还要读盘解析；缓存条数不够时会来回淘汰，退化成"每次都重新解析"

## 测试

```bash
./test.sh                        # 默认 nginx 1.30.5
NGINX_VERSION=1.31.6 ./test.sh   # 指定版本
```

在临时的 `alpine` 容器里编译 nginx 和模块（nginx 默认 `-Werror`，有编译警告会直接失败），然后跑 166 项断言：

| 覆盖 | 内容 |
|---|---|
| 目录模式（9443） | 精确匹配、RSA / ECDSA 混用、通配符、多级子域名、默认证书、无 SNI、非法 SNI |
| 清单模式（9444） | 同上，另加一张证书多个域名、相对路径、`enabled: false`、`isDefault` 占位证书 |
| `unmatched: reject`（9445） | 匹配上的照常；匹配不上 / 无 SNI / 非法 SNI 都拒绝握手，`isDefault` 不起作用 |
| 清单顶层配置（9447） | `interval` 支持整数和 `"5s"`；`interval: 0` 时下一次握手即生效；删除 `interval` 后回落到默认值 |
| JSON 解析（19 项） | 语法错误（缺冒号 / 逗号、字符串没有结束、对象或数组没有结束）；不支持的写法（`null`、负数、小数、前导零、数字溢出、`\u` 转义、未知转义、控制字符）；结构错误（顶层不是对象、成员名重复、嵌套太深、末尾有多余内容）。每种都必须整份清单不生效并保留旧表 |
| `directory` | 只有 `directory` 的清单、相对路径按清单目录解析、空字符串、`certificates` 和 `directory` 都缺失 |
| `mode`（13 项） | 三种取值正常加载、不写时按字段推断；`mode` 选中的来源缺失、取值非法、不是字符串时整份清单不生效；`mode` 之外的多余字段被忽略并告警，且确实不生效 |
| 目录模式的缓存（6 项） | 缓存命中、证书文件变化后自动重新解析、`cache: 0` 时不缓存、缓存条数为 1 时来回淘汰仍然正确、非法 `cache` 值整份清单不生效 |
| 匹配不上的 info 日志 | 三种结尾都有、非法 SNI 里的引号被替换、带客户端地址、没有 crit 日志 |
| 启动检查（单独的配置跑 `nginx -t`） | 私钥不可读、目录进不去（同一目录只报一次）、30 天内到期、已过期、目录模式的证书；`user root` 时不检查权限；正常配置没有误报 |
| 热更新 | 不 reload nginx，往清单里加证书后生效；清单写坏时继续使用旧的证书表，error.log 有记录；替换证书文件并重写清单后生效 |
| 默认证书热切换 | 改成某个真实证书兼做默认；两条 `isDefault` 时拒绝新清单；去掉后回退到 `ssl_certificate` |

整个过程中 nginx master 进程没有重启。

## 发布

推一个 `v<主>.<次>` 形式的标签，GitHub Actions 会自动编译并发布到 Releases：

```bash
git tag -a v1.0 -m "首个发布" -m "支持清单和目录两种来源。"
git push origin v1.0
```

工作流（`.github/workflows/release.yml`）做三件事：

- 按矩阵逐个 nginx 版本编译。动态模块和 nginx 版本是**严格绑定**的，所以每个版本单独出一份 `.so`，发不出一份通用的；
- 每个版本都真的加载起来、按 SNI 走一次握手，比对证书指纹，确认选中的是清单里那张证书、没有 SNI 时回退到 `ssl_certificate`；
- 把 `.so` 和 SHA256 挂到 Release 上。

发布说明分两段：**安装段**由工作流生成，列出实际编出来的产物、加载方式和校验和；**变更段**取标签注释，标签没写注释就由 GitHub 从提交记录生成。想手写发布说明，就在 `git tag -a` 的注释里写。

要增删支持的 nginx 版本，改工作流里的 `matrix.nginx` 一行即可。产物依赖 glibc ≥ 2.33（Ubuntu 22.04+、Debian 12+、RHEL 9+）；更老的系统需要自行编译。
