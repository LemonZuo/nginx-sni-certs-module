#!/bin/sh
# 在临时 Docker 容器里编译 nginx 和 ssl_cert_dir 动态模块，验证：
#   9443 端口：证书目录模式（ssl_cert_dir）
#   9444 端口：证书清单模式（ssl_cert_registry，JSON），包括不 reload 的热更新和 isDefault
#   9445 端口：证书清单模式 + ssl_cert_unmatched reject
#   nginx -t：启动检查（worker 能否读到文件、证书有效期）
#
# 用法：./test.sh
#       NGINX_VERSION=1.31.6 ./test.sh

set -eu
cd "$(dirname "$0")"
NGINX_VERSION=${NGINX_VERSION:-1.30.5}

docker run --rm -i -e NGINX_VERSION="$NGINX_VERSION" -v "$PWD":/work:ro alpine:3 sh -s <<'SCRIPT'
set -eu
apk add --no-cache build-base pcre2-dev zlib-dev openssl-dev openssl jansson-dev >/dev/null

echo "== 编译 nginx $NGINX_VERSION（带 ssl_cert_dir 动态模块）"
cd /tmp
wget -q "https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"
tar xf "nginx-$NGINX_VERSION.tar.gz"
cd "nginx-$NGINX_VERSION"
./configure --prefix=/tmp/ng --with-http_ssl_module --with-compat \
    --add-dynamic-module=/work/ngx_http_ssl_cert_dir_module >/dev/null
make -j"$(nproc)" >/tmp/build.log 2>&1 || { tail -40 /tmp/build.log; exit 1; }
make install >/dev/null

echo "== 生成测试证书"
# 有效期默认 365 天（30 天内到期会触发警告），可以用 DAYS=10 ec ... 指定
ec()  { openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days "${DAYS:-365}" \
            -subj "$3" ${4:+-addext "$4"} -keyout "$1/$2.key" -out "$1/$2.crt" 2>/dev/null; }
rsa() { openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
            -subj "$3" -keyout "$1/$2.key" -out "$1/$2.crt" 2>/dev/null; }

# 目录模式用的证书；default 同时是两个 server 的 ssl_certificate
mkdir -p /certs
ec  /certs default         /CN=default.invalid
ec  /certs a.test          /CN=a.test
rsa /certs b.test          /CN=b.test
ec  /certs wildcard.c.test '/CN=*.c.test'

# 清单模式额外用的证书，放在清单文件旁边，用相对路径引用
mkdir -p /registry/certs
ec /registry/certs multi      /CN=multi.test    "subjectAltName=DNS:multi.test,DNS:alias.test"
ec /registry/certs disabled   /CN=disabled.test
ec /registry/certs d          /CN=d.test
ec /registry/certs regdefault /CN=registry-default.invalid

# 运行中重新加载证书由 worker 进程（nobody）完成，私钥必须对它可读
chown root:nobody /certs/*.key /registry/certs/*.key
chmod 640 /certs/*.key /registry/certs/*.key

# 证书清单：只记录域名和证书路径，不记录证书内容
#   $1 = 是否包含 d.test（yes/no）
#   $2 = 默认证书：placeholder（只当默认的自签名证书）| a（a.test 兼做默认）| two（两条都标默认）| none
#   $3 = 额外的顶层字段（可选），例如 '"unmatched": "default",'
write_registry() {
    a_def=""; [ "$2" = a ] || [ "$2" = two ] && a_def=', "isDefault": true'
    {
        echo '{'
        [ -n "${3:-}" ] && echo "  $3"
        echo '  "certificates": ['
        echo "    { \"domains\": [\"a.test\"],   \"cert\": \"/certs/a.test.crt\", \"key\": \"/certs/a.test.key\"$a_def },"
        echo '    { "domains": ["b.test"],   "cert": "/certs/b.test.crt", "key": "/certs/b.test.key" },'
        echo '    { "domains": ["*.c.test"], "cert": "/certs/wildcard.c.test.crt", "key": "/certs/wildcard.c.test.key" },'
        echo '    { "domains": ["multi.test", "alias.test"], "cert": "certs/multi.crt", "key": "certs/multi.key" },'
        if [ "$1" = yes ]; then
        echo '    { "domains": ["d.test"],   "cert": "certs/d.crt", "key": "certs/d.key" },'
        fi
        if [ "$2" = placeholder ] || [ "$2" = two ]; then
        echo '    { "cert": "certs/regdefault.crt", "key": "certs/regdefault.key", "isDefault": true },'
        fi
        echo '    { "domains": ["disabled.test"], "cert": "certs/disabled.crt", "key": "certs/disabled.key", "enabled": false, "isDefault": true }'
        echo '  ]'
        echo '}'
    } > /registry/certs.json.tmp
    mv /registry/certs.json.tmp /registry/certs.json      # 原子替换
}

# 独立清单：测试 JSON 顶层的 interval / unmatched
#   $1 = interval 片段，例如 '"interval": 0,'
#   $2 = unmatched 片段，例如 '"unmatched": "reject",'
#   $3 = 是否包含 d.test（yes/no）
write_policy_registry() {
    {
        echo '{'
        [ -n "${1:-}" ] && echo "  $1"
        [ -n "${2:-}" ] && echo "  $2"
        echo '  "certificates": ['
        echo '    { "domains": ["a.test"], "cert": "/certs/a.test.crt", "key": "/certs/a.test.key" }'
        if [ "${3:-no}" = yes ]; then
        echo '    , { "domains": ["d.test"], "cert": "certs/d.crt", "key": "certs/d.key" }'
        fi
        echo '  ]'
        echo '}'
    } > /registry/policy.json.tmp
    mv /registry/policy.json.tmp /registry/policy.json    # 原子替换
}

write_registry no placeholder
# interval 0：每次握手都检查，方便测试；unmatched 由清单决定（server 里没写指令）
write_policy_registry '"interval": 0,' '"unmatched": "reject",' no

cat > /tmp/ng/conf/nginx.conf <<'EOF'
load_module modules/ngx_http_ssl_cert_dir_module.so;

error_log logs/error.log info;      # info：能看到"匹配不上"的日志

events {}

http {
    ssl_cert_registry_interval 1s;

    # 证书目录模式
    server {
        listen 9443 ssl;
        ssl_certificate     /certs/default.crt;
        ssl_certificate_key /certs/default.key;
        ssl_cert_dir        /certs;
        return 200 "ok\n";
    }

    # 证书清单模式
    server {
        listen 9444 ssl;
        ssl_certificate     /certs/default.crt;
        ssl_certificate_key /certs/default.key;
        ssl_cert_registry   /registry/certs.json;
        return 200 "ok\n";
    }

    # 证书清单模式，匹配不上时拒绝握手
    server {
        listen 9445 ssl;
        ssl_certificate     /certs/default.crt;
        ssl_certificate_key /certs/default.key;
        ssl_cert_registry   /registry/certs.json;
        ssl_cert_unmatched  reject;
        return 200 "ok\n";
    }

    # 清单顶层 interval / unmatched（server 里不写 ssl_cert_unmatched）
    server {
        listen 9447 ssl;
        ssl_certificate     /certs/default.crt;
        ssl_certificate_key /certs/default.key;
        ssl_cert_registry   /registry/policy.json;
        return 200 "ok\n";
    }
}
EOF
/tmp/ng/sbin/nginx -t 2>&1 | tail -1
/tmp/ng/sbin/nginx
sleep 1

pass=0
fail=0
REGDEF=CN=registry-default.invalid

subject() {
    openssl s_client -connect "127.0.0.1:$1" $2 </dev/null 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null | sed 's/^subject=//; s/ //g'
}

check() {    # $3 = 期望的证书 subject，或者"握手失败"
    port=$1; sni=$2; want=$3
    if [ "$sni" = "(无SNI)" ]; then opt="-noservername"; else opt="-servername $sni"; fi
    got=$(subject "$port" "$opt")
    got=${got:-握手失败}
    if [ "$got" = "$want" ]; then r=PASS; pass=$((pass + 1)); else r=FAIL; fail=$((fail + 1)); fi
    printf '%-4s  %-5s %-14s  期望 %-27s 实际 %s\n' "$r" "$port" "$sni" "$want" "$got"
}

assert() {   # $1 = 描述，其余 = 命令
    desc=$1; shift
    if "$@" >/dev/null 2>&1; then r=PASS; pass=$((pass + 1)); else r=FAIL; fail=$((fail + 1)); fi
    printf '%-4s  %s\n' "$r" "$desc"
}

echo "== 目录模式（9443）：没有清单，匹配不上时用 ssl_certificate"
check 9443 a.test         CN=a.test
check 9443 b.test         CN=b.test              # 和默认证书密钥类型不同，验证 SSL_certs_clear
check 9443 x.c.test       'CN=*.c.test'
check 9443 deep.x.c.test  CN=default.invalid     # 只向上找一级
check 9443 unknown.test   CN=default.invalid
check 9443 "(无SNI)"      CN=default.invalid
check 9443 bad..name      CN=default.invalid

echo "== 清单模式（9444）：清单里有 isDefault 的占位证书"
check 9444 a.test         CN=a.test
check 9444 b.test         CN=b.test
check 9444 x.c.test       'CN=*.c.test'
check 9444 deep.x.c.test  "$REGDEF"
check 9444 multi.test     CN=multi.test          # 一张证书对应多个域名
check 9444 alias.test     CN=multi.test
check 9444 disabled.test  "$REGDEF"              # enabled: false，它的 isDefault 也不生效
check 9444 d.test         "$REGDEF"              # 还没加进清单
check 9444 unknown.test   "$REGDEF"
check 9444 "(无SNI)"      "$REGDEF"
check 9444 bad..name      "$REGDEF"

echo "== 匹配不上时拒绝握手（9445，ssl_cert_unmatched reject）"
check 9445 a.test         CN=a.test              # 匹配上的照常
check 9445 multi.test     CN=multi.test
check 9445 unknown.test   握手失败
check 9445 deep.x.c.test  握手失败
check 9445 "(无SNI)"      握手失败
check 9445 'x"y.test'     握手失败               # 不合法的 SNI，日志里引号被替换成 ?

echo "== 匹配不上时的 info 日志"
LOG=/tmp/ng/logs/error.log
assert '目录模式：回退到 ssl_certificate'  grep -q 'no certificate for "unknown.test", using "ssl_certificate"' $LOG
assert '清单模式：使用 isDefault 证书'      grep -q 'no certificate for "unknown.test", using the "isDefault" certificate' $LOG
assert 'reject：记录拒绝的域名'            grep -q 'no certificate for "unknown.test", handshake rejected' $LOG
assert 'reject：没有 SNI'                  grep -q 'no server name, handshake rejected' $LOG
assert '不合法的 SNI 去掉了引号'           grep -q 'invalid server name "x?y.test", handshake rejected' $LOG
assert '日志里带客户端地址'                grep -q 'handshake rejected while SSL handshaking, client: 127.0.0.1' $LOG
assert '拒绝握手没有产生 crit 日志'        sh -c "! grep -q '\[crit\]' $LOG"
assert '启动检查：正常配置没有权限警告'    sh -c "! grep -q 'not readable\|not accessible' $LOG"
assert '启动检查：正常配置没有到期警告'    sh -c "! grep -q 'expires in\|has expired' $LOG"

echo "== 清单顶层的 interval / unmatched"
check 9447 a.test         CN=a.test
check 9447 unknown.test   握手失败               # 清单里的 unmatched: reject 生效
check 9447 "(无SNI)"      握手失败

# 改成 default；interval: 0 让下一次握手立即重新加载，不需要 sleep
write_policy_registry '"interval": 0,' '"unmatched": "default",' no
check 9447 unknown.test   CN=default.invalid
check 9447 "(无SNI)"      CN=default.invalid

# 同样不需要 sleep：往清单里加 d.test 后，下一次握手就能拿到
write_policy_registry '"interval": 0,' '"unmatched": "default",' yes
check 9447 d.test         CN=d.test

# 非法的 unmatched / interval：整份清单不生效，继续用旧的证书和策略
write_policy_registry '"interval": 0,' '"unmatched": "bogus",' yes
check 9447 a.test         CN=a.test
assert '清单：非法 unmatched 值被拒绝' \
    grep -q '"unmatched" must be "default" or "reject"' $LOG

write_policy_registry '"interval": "abc",' '"unmatched": "default",' yes
check 9447 a.test         CN=a.test
assert '清单：非法 interval 值被拒绝' \
    grep -q 'invalid "interval" "abc"' $LOG

# 时间字符串形式
write_policy_registry '"interval": "2s",' '"unmatched": "reject",' yes
check 9447 a.test         CN=a.test
check 9447 unknown.test   握手失败
assert '清单：interval 支持时间字符串' \
    grep -q '"/registry/policy.json" reloaded:.*interval: 2, unmatched: reject' $LOG

# 清单里删掉 interval：应回落到 ssl_cert_registry_interval（这里是 1s），
# 而不是继续沿用上一份清单的 2
write_policy_registry '' '"unmatched": "reject",' yes
sleep 2                                            # 上一份清单的间隔是 2s
check 9447 a.test         CN=a.test
assert '清单：删除 interval 后回落到指令值' \
    sh -c "grep 'policy.json\" reloaded' $LOG | tail -1 | grep -q 'interval: 1,'"

echo "== 热更新：往清单里加入 d.test（不 reload nginx）"
write_registry yes placeholder
sleep 2
check 9444 d.test         CN=d.test

echo "== 清单写坏了：继续使用旧的证书表"
printf '{ "certificates": [ broken' > /registry/certs.json.tmp
mv /registry/certs.json.tmp /registry/certs.json
sleep 2
check 9444 a.test         CN=a.test
check 9444 d.test         CN=d.test
check 9444 unknown.test   "$REGDEF"
assert "error.log 记录了清单加载失败" grep -q 'not reloaded, keeping current certificates' /tmp/ng/logs/error.log

echo "== 证书续期：替换 a.test 的证书文件，再重写清单触发重新加载"
ec /certs a.test /CN=a.test/O=renewed
chown root:nobody /certs/a.test.key && chmod 640 /certs/a.test.key
check 9443 a.test         CN=a.test,O=renewed    # 目录模式每次握手读文件，立即生效
write_registry yes placeholder
sleep 2
check 9444 a.test         CN=a.test,O=renewed
check 9444 d.test         CN=d.test

echo "== 默认证书热切换：改成 a.test 兼做默认证书"
write_registry yes a
sleep 2
check 9444 unknown.test   CN=a.test,O=renewed
check 9444 "(无SNI)"      CN=a.test,O=renewed
check 9444 a.test         CN=a.test,O=renewed    # 自己的域名照常匹配
check 9445 unknown.test   握手失败               # reject 时不使用 isDefault 证书

echo "== 两条都标了 isDefault：整份清单不生效，继续使用旧的"
write_registry yes two
sleep 2
check 9444 unknown.test   CN=a.test,O=renewed
assert "error.log 记录了重复的 isDefault" grep -q 'more than one certificate has "isDefault": true' /tmp/ng/logs/error.log

echo "== 清单里没有默认证书：回退到 ssl_certificate"
write_registry yes none
sleep 2
check 9444 unknown.test   CN=default.invalid
check 9444 "(无SNI)"      CN=default.invalid
check 9444 a.test         CN=a.test,O=renewed

echo "== ssl_cert_unmatched 指令优先于清单里的 unmatched"
# 9445 显式写了 ssl_cert_unmatched reject；清单里写 default 也不应改变它
write_registry yes none '"unmatched": "default",'
sleep 2
check 9445 unknown.test   握手失败               # 指令 reject 优先
check 9444 unknown.test   CN=default.invalid     # 9444 没写指令，用清单里的 default

echo "== 启动检查：用一份单独的配置跑 nginx -t"
# worker 以 nobody 运行；这些文件有的它读不到，有的快到期了
# （到期天数向下取整：证书刚生成就检查是 10 天，过了一秒就是 9 天，两种都算对）
mkdir -p /check/dir /check/hidden
(DAYS=10 ec /check soon /CN=soon.test)            # 清单：10 天后到期（子 shell，DAYS 不影响后面）
ec /check private         /CN=private.test       # 清单：私钥只有 root 能读
ec /check/hidden h1       /CN=h1.test            # 清单：所在目录 nobody 进不去
ec /check/hidden h2       /CN=h2.test
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -not_before 20200101000000Z -not_after 20200201000000Z -subj /CN=expired.test \
    -keyout /check/expired.key -out /check/expired.crt 2>/dev/null \
    || echo "  （openssl 不支持 -not_after，过期证书的测试会失败）"     # 清单：已经过期
(DAYS=5 ec /check/dir dsoon.test /CN=dsoon.test)  # 目录：5 天后到期
ec /check/dir dpriv.test        /CN=dpriv.test   # 目录：私钥只有 root 能读
chown root:nobody /check/*.key /check/dir/*.key
chmod 640 /check/*.key /check/dir/*.key
chown root:root /check/private.key /check/dir/dpriv.test.key
chmod 600 /check/private.key /check/dir/dpriv.test.key
chmod 700 /check/hidden

cat > /check/certs.json <<'EOF'
{
  "certificates": [
    { "domains": ["soon.test"],    "cert": "soon.crt",      "key": "soon.key" },
    { "domains": ["private.test"], "cert": "private.crt",   "key": "private.key" },
    { "domains": ["h1.test"],      "cert": "hidden/h1.crt", "key": "hidden/h1.key" },
    { "domains": ["h2.test"],      "cert": "hidden/h2.crt", "key": "hidden/h2.key" },
    { "domains": ["expired.test"], "cert": "expired.crt",   "key": "expired.key" }
  ]
}
EOF

cat > /tmp/ng/conf/check.conf <<'EOF'
load_module modules/ngx_http_ssl_cert_dir_module.so;
pid       logs/check.pid;
error_log logs/check.log notice;
events {}
http {
    server {
        listen 9446 ssl;
        ssl_certificate     /certs/default.crt;
        ssl_certificate_key /certs/default.key;
        ssl_cert_registry   /check/certs.json;
        ssl_cert_dir        /check/dir;
    }
}
EOF
/tmp/ng/sbin/nginx -t -c /tmp/ng/conf/check.conf >/tmp/check.out 2>&1 || true
grep 'ssl_cert' /tmp/check.out | sed 's/^nginx: //'
OUT=/tmp/check.out
assert 'nginx -t 仍然通过（只是警告）'   grep -q 'test is successful' $OUT
assert '清单：10 天后到期'               grep -q 'certificate "/check/soon.crt" expires in \(9\|10\) days' $OUT
assert '清单：已经过期'                   grep -q 'certificate "/check/expired.crt" has expired' $OUT
assert '目录：5 天后到期'                 grep -q 'ssl_cert_dir: certificate "/check/dir/dsoon.test.crt" expires in \(4\|5\) days' $OUT
assert '清单：私钥不可读'                 grep -q '"/check/private.key" is not readable by worker processes (user "nobody")' $OUT
assert '目录：私钥不可读'                 grep -q 'ssl_cert_dir: "/check/dir/dpriv.test.key" is not readable' $OUT
assert '目录进不去：指出是哪个目录'       grep -q 'directory "/check/hidden" is not accessible' $OUT
assert '同一个目录只报一次'               test "$(grep -c 'directory "/check/hidden"' $OUT)" -eq 1
assert '可读的文件不报'                   sh -c "! grep -q 'soon.key\|/check/certs.json\|dsoon.test.key' $OUT"

sed -i '1a user root;' /tmp/ng/conf/check.conf
/tmp/ng/sbin/nginx -t -c /tmp/ng/conf/check.conf >/tmp/check.out 2>&1 || true
assert 'user root 时不检查权限'           sh -c "! grep -q 'not readable\|not accessible' $OUT"
assert 'user root 时仍然检查有效期'       grep -q 'expires in \(9\|10\) days' $OUT

echo "== nginx 进程没有重启过"
assert "master 进程 PID 没变" test "$(cat /tmp/ng/logs/nginx.pid)" = "$(pgrep -o nginx)"

echo "== error.log（模块相关）"
grep ssl_cert_registry /tmp/ng/logs/error.log | sed 's/ while SSL handshaking.*//'
echo "  ……匹配不上的 info 日志（前 4 条）："
grep 'ssl_cert_dir: \(no \|invalid\)' /tmp/ng/logs/error.log | head -4

echo "== 合计：PASS $pass，FAIL $fail"
[ "$fail" -eq 0 ]
SCRIPT
