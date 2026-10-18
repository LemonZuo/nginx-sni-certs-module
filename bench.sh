#!/bin/sh
# 性能测试：比较静态证书、清单模式、目录模式的 TLS 握手开销。
#
# 用法：./bench.sh
#       REQUESTS=40000 ROUNDS=7 BIG=1000 ./bench.sh
#
# ab 不启用 keep-alive，每个请求都是一次完整的 TLS 握手；用多个 ab 进程
# 同时压，避免单个 ab 进程先成为瓶颈。同时读取 nginx worker 的
# /proc/<pid>/stat，算出服务端平均每个请求消耗的 CPU 时间。
#
# 每个场景先预热，再跑 ROUNDS 轮（默认 5）：每轮都跑一遍所有场景，并把
# 场景顺序轮转一位，抵消宿主机负载随时间的漂移。每轮的开头和结尾各测
# 一次 static 作为该轮的基线，各场景减去同一轮的基线再取中位数——宿主
# 机负载会让绝对值整体漂移（两次运行之间差 10% 很常见），只有同一轮内
# 相减出来的差值才是模块本身的开销。噪声大时加大 REQUESTS 和 ROUNDS，
# 代价是跑得更久。

set -eu
cd "$(dirname "$0")"

NGINX_VERSION=${NGINX_VERSION:-1.30.5}
REQUESTS=${REQUESTS:-8000}
CONCURRENCY=${CONCURRENCY:-30}
CLIENTS=${CLIENTS:-4}
BIG=${BIG:-1000}
ROUNDS=${ROUNDS:-5}

docker run --rm -i \
    -e NGINX_VERSION="$NGINX_VERSION" \
    -e REQUESTS="$REQUESTS" \
    -e CONCURRENCY="$CONCURRENCY" \
    -e CLIENTS="$CLIENTS" \
    -e BIG="$BIG" \
    -e ROUNDS="$ROUNDS" \
    -v "$PWD":/work:ro alpine:3 sh -s <<'SCRIPT'
set -eu

apk add --no-cache build-base pcre2-dev zlib-dev openssl-dev openssl \
    apache2-utils >/dev/null

# 从 stdin 读一列已经排好序的数字，输出中位数

median() {
    awk '{ v[NR] = $1 } END { if (NR) print v[int((NR + 1) / 2)] }'
}

echo "== 编译 nginx $NGINX_VERSION（带 ssl_cert_dir 动态模块）"
cd /tmp
wget -q "https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"
tar xf "nginx-$NGINX_VERSION.tar.gz"
cd "nginx-$NGINX_VERSION"
./configure --prefix=/tmp/ng --with-http_ssl_module --with-compat \
    --add-dynamic-module=/work/ngx_http_ssl_cert_dir_module >/dev/null
make -j"$(nproc)" >/tmp/build.log 2>&1 || { tail -40 /tmp/build.log; exit 1; }
make install >/dev/null

echo "== 生成证书"
ec() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
        -subj "$3" -keyout "$1/$2.key" -out "$1/$2.crt" 2>/dev/null
}
mkdir -p /certs /registry
ec /certs default           /CN=default.invalid
ec /certs a.test            /CN=a.test
ec /certs wildcard.c.test  '/CN=*.c.test'

# worker（nobody）在运行中重新加载时也要能读私钥
chown root:nobody /certs/*.key
chmod 640 /certs/*.key

cat > /registry/bench.json <<'EOF'
{
  "certificates": [
    { "domains": ["a.test"],   "cert": "/certs/a.test.crt", "key": "/certs/a.test.key" },
    { "domains": ["*.c.test"], "cert": "/certs/wildcard.c.test.crt", "key": "/certs/wildcard.c.test.key" }
  ]
}
EOF

# interval: 0：每次握手都检查清单文件（stat），用来衡量这项开销
sed '1a\  "interval": 0,' /registry/bench.json > /registry/bench0.json

# 目录模式：清单里只有 directory（证书缓存默认 1024 条）
echo '{ "directory": "/certs" }' > /registry/dir.json

# 目录模式，关掉缓存（cache: 0）：每次握手都读盘并解析
echo '{ "directory": "/certs", "cache": 0 }' > /registry/dir0.json

# 大清单：BIG 条无关域名 + a.test，用来验证哈希查找不会随条目数变慢
{
    echo '{'
    echo '  "certificates": ['
    echo '    { "domains": ["a.test"], "cert": "/certs/a.test.crt", "key": "/certs/a.test.key" },'
    i=1
    while [ "$i" -le "$BIG" ]; do
        printf '    { "domains": ["d%04d.test"], "cert": "/certs/a.test.crt", "key": "/certs/a.test.key" }' "$i"
        [ "$i" -lt "$BIG" ] && echo ','
        i=$((i + 1))
    done
    echo
    echo '  ]'
    echo '}'
} > /registry/big.json

cat > /tmp/ng/conf/nginx.conf <<'EOF'
load_module modules/ngx_http_ssl_cert_dir_module.so;

worker_processes auto;
error_log logs/error.log warn;
pid logs/nginx.pid;

events {
    worker_connections 8192;
}

http {
    access_log off;
    log_format sni '$ssl_server_name';

    # 强制完整握手，避免会话复用影响对比
    ssl_session_cache   off;
    ssl_session_tickets off;

    # 基准：静态证书，不使用本模块
    server {
        listen 9440 ssl;
        ssl_certificate     /certs/a.test.crt;
        ssl_certificate_key /certs/a.test.key;
        return 200 "ok\n";
    }

    # 清单模式：正常命中
    server {
        listen 9441 ssl;
        ssl_certificate     /certs/default.crt;
        ssl_certificate_key /certs/default.key;
        ssl_cert_registry   /registry/bench.json;
        return 200 "ok\n";
    }

    # 目录模式：每次握手读证书文件
    server {
        listen 9442 ssl;
        ssl_certificate     /certs/default.crt;
        ssl_certificate_key /certs/default.key;
        ssl_cert_registry   /registry/dir.json;
        return 200 "ok\n";
    }

    # 清单模式 + interval: 0：每次握手 stat 清单文件
    server {
        listen 9443 ssl;
        ssl_certificate     /certs/default.crt;
        ssl_certificate_key /certs/default.key;
        ssl_cert_registry   /registry/bench0.json;
        return 200 "ok\n";
    }

    # 目录模式 + cache: 0：每次握手读盘并解析证书
    server {
        listen 9445 ssl;
        ssl_certificate     /certs/default.crt;
        ssl_certificate_key /certs/default.key;
        ssl_cert_registry   /registry/dir0.json;
        return 200 "ok\n";
    }

    # 清单模式：BIG 条记录
    server {
        listen 9444 ssl;
        ssl_certificate     /certs/default.crt;
        ssl_certificate_key /certs/default.key;
        ssl_cert_registry   /registry/big.json;
        return 200 "ok\n";
    }

    # 只用来确认 ab 确实发送了 SNI
    server {
        listen 9446 ssl;
        ssl_certificate     /certs/a.test.crt;
        ssl_certificate_key /certs/a.test.key;
        access_log /tmp/verify.log sni;
        return 200 "ok\n";
    }
}
EOF

echo "== 启动 nginx（大清单 $BIG 条）"
/tmp/ng/sbin/nginx -t 2>&1 | tail -1
/tmp/ng/sbin/nginx
sleep 1

echo "127.0.0.1 a.test unknown.test x.c.test" >> /etc/hosts

# 确认 ab 会发送 SNI；不发的话清单模式实际走的是默认证书，结果没有意义
ab -n 10 -c 1 https://a.test:9446/ >/dev/null 2>&1
if ! grep -qx 'a.test' /tmp/verify.log; then
    echo "ab 没有发送 SNI，终止测试" >&2
    exit 1
fi
echo "== ab 已确认发送 SNI"

# 所有 nginx worker 的 utime + stime（单位：10ms）
cpu_ticks() {
    master=$(cat /tmp/ng/logs/nginx.pid)
    awk -v m="$master" '$4 == m { t += $14 + $15 } END { print t + 0 }' \
        /proc/[0-9]*/stat
}

# 并发压测一轮，输出 "服务端CPU(us) 吞吐(req/s)"。
# 基线必须和被比较的场景用同样的并发方式跑，否则吞吐不可比。

measure() {    # $1 = SNI，$2 = 端口
    before=$(cpu_ticks)

    i=1
    while [ "$i" -le "$CLIENTS" ]; do
        ab -n $((REQUESTS / CLIENTS)) -c "$CONCURRENCY" -s 60 \
            "https://$1:$2/" >"/tmp/ab.$i" 2>&1 &
        i=$((i + 1))
    done
    wait

    after=$(cpu_ticks)

    ok=$(grep -l 'Requests per second' /tmp/ab.[0-9]* | wc -l | tr -d ' ')
    if [ "$ok" -ne "$CLIENTS" ]; then
        echo "$1:$2: ab 失败" >&2
        cat /tmp/ab.1 >&2
        exit 1
    fi

    rps=$(awk '/Requests per second/ { s += $4 } END { printf "%.2f", s }' \
          /tmp/ab.[0-9]*)

    echo "$(( (after - before) * 10000 / REQUESTS )) $rps"
}

run_one() {    # $1 = 名称，$2 = SNI，$3 = 端口
    name=$1 host=$2 port=$3

    set -- $(measure "$host" "$port")
    us=$1 rps=$2

    # 单连接再跑一遍，避免并发排队影响延迟数字
    ab -n 500 -c 1 -s 60 "https://$host:$port/" >/tmp/ab_lat 2>&1
    lat=$(awk '/Time per request/ { printf "%.3f", $4; exit }' /tmp/ab_lat)

    echo "$name,$rps,$us,$lat" >>/tmp/results
    printf '  %-18s %9s req/s  %6s us/req  %6s ms\n' "$name" "$rps" "$us" "$lat"
}

# 每个场景一行；static 不在这里，它由每轮的轮首 / 轮尾两次测量单独提供

scenarios='registry-hit a.test 9441
registry-wildcard x.c.test 9441
registry-miss unknown.test 9441
registry-big a.test 9444
registry-int0 a.test 9443
dir-hit a.test 9442
dir-wildcard x.c.test 9442
dir-miss unknown.test 9442
dir-nocache a.test 9445'

: >/tmp/results
: >/tmp/baseline

echo "== 预热"
ab -n 500 -c "$CONCURRENCY" "https://a.test:9440/" >/dev/null 2>&1
printf '%s\n' "$scenarios" | while read -r name host port; do
    ab -n 500 -c "$CONCURRENCY" "https://$host:$port/" >/dev/null 2>&1
done

# 每轮把场景顺序轮转一位：宿主机负载会随时间漂移，固定顺序会把漂移
# 算到某个场景头上，轮转之后每个场景在每轮里的位置不同，可以抵消掉

rotate() {   # $1 = 偏移量
    printf '%s\n' "$scenarios" | awk -v k="$1" '{ a[NR] = $0 } END { for (i = 1; i <= NR; i++) print a[((i - 1 + k) % NR) + 1] }'
}

# 每轮的基线取轮首和轮尾两次 static 的平均值：宿主机负载在一轮之内是
# 缓慢变化的，取首尾均值相当于线性插值，能把漂移的一阶项消掉。只测一次
# 首（或只测一次尾）时，漂移会整体算到基线或算到被测场景头上。

baseline() {   # $1 = 轮号
    r=$1
    set -- $(measure a.test 9440)
    echo "$r $1 $2" >>/tmp/baseline
    printf '  %-18s %9s req/s  %6s us/req\n' static "$2" "$1"
}

round=1
while [ "$round" -le "$ROUNDS" ]; do
    echo "== 第 $round 轮（每个场景 $REQUESTS 次握手，$CLIENTS 个 ab 进程）"

    baseline "$round"

    rotate $((round - 1)) | while read -r name host port; do
        run_one "$name" "$host" "$port"
    done

    baseline "$round"

    round=$((round + 1))
done

names=$(printf '%s\n' "$scenarios" | awk '{ print $1 }')
nscen=$(printf '%s\n' "$names" | wc -l | tr -d ' ')

# 每个场景的「相对 static」= 该场景本轮的 CPU 减去同一轮的 static 基线，
# 再取 ROUNDS 轮的中位数。宿主机负载对同一轮里所有场景的影响基本相同，
# 先在同一轮内相减就能把漂移抵消掉；直接比绝对值会被漂移盖过去。
# static 基线取轮首、轮尾两次测量的平均值（一轮之内负载是缓慢变化的，
# 首尾均值相当于线性插值）。

# 读 /tmp/baseline 建轮号 → 基线 CPU；$1 为场景名时输出每轮差值（升序），
# $2 = median 只要中位数，$2 = range 输出 "min ~ max"

delta() {   # $1 = 场景名，$2 = median | range
    awk -F, -v m="$1" -v n="$nscen" -v bf=/tmp/baseline '
        BEGIN { while ((getline line < bf) > 0) { split(line, a, " "); s[a[1]] += a[2]; c[a[1]]++ } }
        { r = int((NR - 1) / n) + 1; us[r, $1] = $3 }
        END {
            for (r in s) base[r] = s[r] / c[r]
            for (r in base) if ((r SUBSEP m) in us) print us[r SUBSEP m] - base[r]
        }
    ' /tmp/results | sort -n | awk -v how="$2" '
        { v[NR] = $1 }
        END {
            if (!NR) { print "n/a"; exit }
            if (how == "range") printf "%+d ~ %+d us", v[1], v[NR]
            else printf "%+d us", v[int((NR + 1) / 2)]
        }'
}

printf '\n%-20s %10s %9s %11s %18s %9s\n' \
    场景 吞吐req/s 服务端CPU 相对static 逐轮范围 串行延迟
printf '%-20s %10s %9s %11s %18s %9s\n' \
    ---- --------- --------- ----------- ---------------- --------

rps=$(awk '{ print $3 }' /tmp/baseline | sort -n | median)
us=$(awk '{ print $2 }' /tmp/baseline | sort -n | median)
printf '%-20s %10s %6s us %11s %18s %9s\n' static "$rps" "$us" — — —

for m in $names; do
    rps=$(awk -F, -v m="$m" '$1 == m { print $2 }' /tmp/results | sort -n | median)
    us=$(awk -F, -v m="$m" '$1 == m { print $3 }' /tmp/results | sort -n | median)
    lat=$(awk -F, -v m="$m" '$1 == m { print $4 }' /tmp/results | sort -n | median)

    printf '%-20s %10s %6s us %11s %18s %6s ms\n' \
        "$m" "$rps" "$us" "$(delta "$m" median)" "$(delta "$m" range)" "$lat"
done

echo
echo "（吞吐 / CPU / 延迟取 $ROUNDS 轮的中位数；「相对 static」按上文所述逐轮相减后取中位数，"
echo "  「逐轮范围」是该场景 $ROUNDS 轮差值的 min ~ max，用来判断差值是不是真的；"
echo "  static 是基线，不测串行延迟）"
SCRIPT
