/*
 * ngx_http_ssl_cert_dir_module
 *
 * 在 TLS 握手时，按客户端请求的域名（SNI）选择证书。整个模块只有一条指令
 * ssl_cert_registry，指向一份 JSON 清单；证书从哪来、怎么匹配、多久检查一次，
 * 全部写在清单里。查找顺序：
 *
 *   1. 清单里的证书（"certificates"）：
 *        精确域名 -> "*.上一级域名"（只向上找一级，与 TLS 通配符语义一致）
 *   2. 证书目录（清单里的 "directory"）：
 *        <dir>/<域名>.crt -> <dir>/wildcard.<上一级域名>.crt
 *   3. 清单里 "isDefault": true 的证书
 *   4. server 块里 ssl_certificate 配置的证书
 *
 * 没有 SNI 或 SNI 不合法时，直接从第 3 步开始。前两步都没匹配上时写一条
 * info 日志；清单里写了 "unmatched": "reject" 时不走第 3、4 步，直接拒绝握手。
 *
 * 清单在启动时整体读入内存，清单里的证书握手时不读磁盘。每个 worker 每隔
 * 清单里的 "interval" 秒检查一次清单文件，变化了就重新加载；新清单有任何
 * 错误时继续使用旧的证书表。
 *
 * 用法：
 *
 *   server {
 *       listen 443 ssl;
 *       ssl_certificate     certs/default.crt;     # nginx 强制要求
 *       ssl_certificate_key certs/default.key;
 *       ssl_cert_registry   /path/to/certs.json;   # 唯一的模块指令
 *   }
 *
 * 证书清单格式：
 *
 *   {
 *     "interval": 5,                           可选，检查间隔（秒或 "5s"/"1m"），
 *                                              默认 5，0 表示每次握手都检查
 *     "unmatched": "default",                  可选，default | reject，默认 default
 *     "directory": "certs",                    可选，证书目录；相对路径按清单文件
 *                                              所在目录解析
 *     "certificates": [                        可选，但和 "directory" 至少有一个
 *       {
 *         "domains": ["example.com", "www.example.com", "*.example.com"],
 *         "cert": "example.com/fullchain.pem",   相对路径按清单文件所在目录解析
 *         "key":  "example.com/privkey.pem",
 *         "enabled": true,                       可选，默认 true
 *         "isDefault": false                     可选，最多一条为 true；
 *                                                为 true 时 domains 可省略
 *       }
 *     ]
 *   }
 *
 * 因为策略和目录都写在清单里，同一份清单被多个 server 引用时，它们共用
 * 同一套策略和目录；需要区分就拆成多份清单。
 *
 * 限制：
 *   - 不要和使用变量的 ssl_certificate 同时用（两者都会设置 cert_cb）；
 *   - 动态加载的证书没有 OCSP stapling；
 *   - 运行中重新加载由 worker 进程完成，证书和私钥要对 worker 用户可读
 *     （启动时会按 worker 的身份检查一遍，读不到的写警告）。
 *
 * 加载证书时还会检查有效期，30 天内到期或已经过期的写警告。
 *
 *
 * ---------------------------------------------------------------------------
 * 代码结构（建议按这个顺序阅读）
 * ---------------------------------------------------------------------------
 *
 *   1. 数据结构          证书、证书表、清单、配置结构体
 *   2. 指令和模块定义    ngx_command_t / ngx_http_module_t / ngx_module_t
 *   3. 配置阶段          创建、合并配置；postconfiguration 里挂上 OpenSSL 回调
 *   4. 启动检查          init_module：用 worker 的身份检查文件权限、检查证书有效期
 *   5. 握手阶段          cert_cb：按 SNI 选证书
 *   6. 证书清单          首次加载、定期检查、解析 JSON、建哈希表、读 PEM
 *
 *
 * ---------------------------------------------------------------------------
 * 进程模型和生命周期
 * ---------------------------------------------------------------------------
 *
 *   nginx 启动 / reload
 *     └─ master 进程（root）解析配置
 *          ├─ create_main_conf / create_srv_conf   为每一层配置分配结构体
 *          ├─ 解析指令，写入结构体                 ngx_conf_set_*_slot
 *          ├─ merge_srv_conf                       把 http{} 的值继承到 server{}
 *          ├─ postconfiguration（本模块的 init）
 *          │    ├─ 首次加载 JSON 清单，证书读进内存（master 是 root，权限不是问题）
 *          │    └─ SSL_CTX_set_cert_cb()           给每个相关 server 的 SSL_CTX 挂回调
 *          ├─ 核心模块确定 worker 的用户（user 指令）
 *          └─ init_module（本模块的启动检查）
 *               └─ 临时切换成 worker 的用户，检查清单、证书、私钥能不能读到
 *
 *     └─ fork 出 worker 进程（非 root）
 *          worker 继承 master 的内存（写时复制），所以证书表不用重新加载。
 *          之后每个 worker 各自处理握手、各自检查清单、各自重新加载，互不影响。
 *
 *   配置相关的内存都分配在 cf->pool（也就是 cycle 的内存池）里，
 *   nginx reload 时旧 cycle 被销毁，挂在上面的清理函数会把旧证书表一起释放。
 *
 *
 * ---------------------------------------------------------------------------
 * 内存管理
 * ---------------------------------------------------------------------------
 *
 *   nginx 用内存池（ngx_pool_t）管理内存：从池里分配，最后整个池一次性释放，
 *   不需要逐个 free。每份证书表有自己的内存池：
 *
 *     table->pool      证书表本身、哈希表、证书对象（OpenSSL 对象通过 cleanup 释放）
 *     temp_pool        只在建表过程中使用（JSON 里的域名字符串、哈希构建的临时数组），
 *                      建完就销毁
 *
 *   换表时直接 ngx_destroy_pool(旧表->pool)，旧表的一切随之释放。
 *   正在使用旧证书的连接不受影响：SSL_use_cert_and_key() 会给证书和私钥增加引用计数，
 *   连接自己持有一份引用。
 */


/*
 * nginx 模块固定的三个头文件，顺序不能变：
 *   ngx_config.h  平台相关的宏和类型（必须最先包含）
 *   ngx_core.h    核心数据结构：内存池、字符串、数组、哈希、日志、文件……
 *   ngx_http.h    HTTP 模块相关；编译时带了 SSL 时也会包含 ngx_http_ssl_module.h，
 *                 以及 OpenSSL 的头文件（ssl.h、x509.h、pem.h 等）
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* jansson：解析 JSON 证书清单（链接参数 -ljansson 写在 config 文件里） */

#include <jansson.h>


/*
 * 编译期检查：
 *   NGX_HTTP_SSL 由 configure 根据 --with-http_ssl_module 定义，没有 SSL 模块
 *   就拿不到 SSL_CTX，本模块无法工作。
 *   SSL_use_cert_and_key() 是 OpenSSL 1.1.1 才有的函数。
 */

#if !(NGX_HTTP_SSL)
#error "ngx_http_ssl_cert_dir_module requires --with-http_ssl_module"
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10101000L)
#error "ngx_http_ssl_cert_dir_module requires OpenSSL 1.1.1 or newer"
#endif


/* 域名的最大长度（DNS 规定一个完整域名最多 253 个字符） */

#define NGX_HTTP_SSL_CERT_MAX_NAME  253


/* 证书剩余有效期少于这么多天时，加载时写一条警告日志 */

#define NGX_HTTP_SSL_CERT_EXPIRE_WARN_DAYS  30


/* 清单里没有写 "interval" 时的检查间隔（秒） */

#define NGX_HTTP_SSL_CERT_DEFAULT_INTERVAL  5


/* 清单里 unmatched 的取值 */

#define NGX_HTTP_SSL_CERT_UNMATCHED_DEFAULT  0   /* 使用默认证书 */
#define NGX_HTTP_SSL_CERT_UNMATCHED_REJECT   1   /* 拒绝握手 */


/* ---------------------------------------------------------------------- */
/* 数据结构                                                               */
/* ---------------------------------------------------------------------- */

/*
 * 一张已经解析好的证书（证书清单模式使用）。
 * 三个都是 OpenSSL 的对象，在加载清单时从 PEM 文件解析出来，之后握手直接使用。
 */

typedef struct {
    X509                          *cert;       /* 叶子证书（网站证书本身） */
    STACK_OF(X509)                *chain;      /* 中间证书链，可以为空 */
    EVP_PKEY                      *pkey;       /* 私钥 */
    u_char                        *cert_path;  /* 证书文件路径，'\0' 结尾，启动时检查权限用 */
    u_char                        *key_path;   /* 私钥文件路径，同上 */
} ngx_http_ssl_cert_entry_t;


/*
 * 一份证书清单对应的内存表：域名 -> ngx_http_ssl_cert_entry_t
 *
 * 一份清单解析一次就生成一张表；清单变化时生成一张新表替换旧表。
 * 同一张证书对应多个域名时，哈希表里的多个 key 指向同一个 entry。
 */

typedef struct {
    ngx_pool_t                    *pool;            /* 这张表的所有内存都在这个池里 */
    ngx_hash_t                     hash;            /* 小写域名 -> entry 指针 */
    ngx_http_ssl_cert_entry_t     *default_entry;   /* isDefault: true */
    ngx_array_t                    entries;         /* 所有证书，ngx_http_ssl_cert_entry_t *；
                                                       nelts 就是证书数，启动时检查权限也用它 */
    ngx_uint_t                     ndomains;        /* 登记了多少个域名（用于日志） */
    ngx_str_t                      dir;             /* 清单顶层 "directory"，已解析成
                                                       完整路径；len 为 0 表示不启用目录模式 */
    ngx_uint_t                     unmatched;       /* 清单顶层 "unmatched" 的值 */
    ngx_uint_t                     unmatched_set;   /* 清单里是否写了 "unmatched" */
    time_t                         interval;        /* 清单顶层 "interval" 的值（秒） */
    ngx_uint_t                     interval_set;    /* 清单里是否写了 "interval" */
} ngx_http_ssl_cert_table_t;


/*
 * 一个证书清单文件，同一个文件被多个 server 引用时共用
 *
 * 除了当前的证书表，还记录清单文件的状态（inode、修改时间、大小），
 * 用来判断文件是否变化。
 */

typedef struct {
    ngx_str_t                      path;      /* 清单文件完整路径，以 '\0' 结尾 */
    ngx_str_t                      dir;       /* 清单文件所在目录（指向 path 的前半部分） */
    ngx_log_t                     *log;       /* 创建内存池用的日志对象（cycle 的日志） */
    time_t                         interval;  /* 当前生效的检查间隔，秒 */
    time_t                         checked;   /* 上次检查的时间 */
    ngx_file_uniq_t                uniq;      /* 上次加载时文件的 inode */
    time_t                         mtime;     /* 上次加载时文件的修改时间 */
    off_t                          size;      /* 上次加载时文件的大小 */
    ngx_http_ssl_cert_table_t     *table;     /* 当前正在使用的证书表 */
} ngx_http_ssl_cert_registry_t;


/*
 * http{} 级别的配置（main conf），整个 http 块只有一份
 */

typedef struct {
    ngx_array_t                    registries;  /* ngx_http_ssl_cert_registry_t *，
                                                   按路径去重，所有清单都在这里 */
    ngx_array_t                    dirs;        /* ngx_str_t，按路径去重，清单里配置的
                                                   所有证书目录，启动时检查用 */
} ngx_http_ssl_cert_dir_main_conf_t;


/*
 * server 级别的配置（srv conf）：http{} 层和每个 server{} 各有一份，
 * 合并后 server{} 里的值就是最终生效的值
 */

typedef struct {
    ngx_str_t                      registry_path;  /* ssl_cert_registry */
    ngx_http_ssl_cert_registry_t  *registry;       /* 在 postconfiguration 里关联上 */
} ngx_http_ssl_cert_dir_srv_conf_t;


/*
 * 启动时要检查权限的一个文件（只在 init_module 里临时使用）
 */

typedef struct {
    ngx_str_t                      path;      /* 完整路径，data 以 '\0' 结尾 */
    char                          *prefix;    /* 日志前缀："ssl_cert_registry" 或 "ssl_cert_dir" */
} ngx_http_ssl_cert_file_t;


/* ---------------------------------------------------------------------- */
/* 函数声明                                                               */
/* ---------------------------------------------------------------------- */

/* 配置阶段（master 进程解析配置时调用） */

static void *ngx_http_ssl_cert_dir_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_ssl_cert_dir_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ssl_cert_dir_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_ssl_cert_dir_init(ngx_conf_t *cf);

/* 配置全部处理完之后（master 进程，fork 之前）：检查 worker 能否读到证书 */

static ngx_int_t ngx_http_ssl_cert_dir_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_ssl_cert_scan_dir(ngx_log_t *log, ngx_str_t *dir,
    ngx_array_t *files);
static ngx_int_t ngx_http_ssl_cert_add_file(ngx_array_t *files, u_char *path,
    size_t len, char *prefix);
static ngx_int_t ngx_http_ssl_cert_check_files(ngx_cycle_t *cycle,
    ngx_core_conf_t *ccf, ngx_array_t *files);
static void ngx_http_ssl_cert_check_access(ngx_log_t *log,
    ngx_http_ssl_cert_file_t *f, char *user, ngx_array_t *reported);
static void ngx_http_ssl_cert_check_expiry(ngx_log_t *log, X509 *cert,
    u_char *path, char *prefix);

/* 握手阶段（worker 进程处理 TLS 握手时由 OpenSSL 调用） */

static int ngx_http_ssl_cert_dir_cert_cb(ngx_ssl_conn_t *ssl_conn,
    void *arg);
static int ngx_http_ssl_cert_use(ngx_ssl_conn_t *ssl_conn,
    ngx_connection_t *c, ngx_http_ssl_cert_entry_t *e, u_char *what);
static ngx_int_t ngx_http_ssl_cert_normalize(const char *in, u_char *out,
    size_t size, ngx_uint_t allow_wildcard);
static ngx_int_t ngx_http_ssl_cert_dir_load(ngx_ssl_conn_t *ssl_conn,
    ngx_connection_t *c, ngx_str_t *dir, u_char *base);

/* 证书清单 */

static const char *ngx_http_ssl_cert_unmatched_name(
    ngx_http_ssl_cert_table_t *t);
static ngx_http_ssl_cert_registry_t *ngx_http_ssl_cert_registry_get(
    ngx_conf_t *cf, ngx_http_ssl_cert_dir_main_conf_t *mcf, ngx_str_t *path);
static void ngx_http_ssl_cert_registry_cleanup(void *data);
static void ngx_http_ssl_cert_registry_refresh(
    ngx_http_ssl_cert_registry_t *reg, ngx_log_t *log);
static ngx_http_ssl_cert_table_t *ngx_http_ssl_cert_registry_build(
    ngx_http_ssl_cert_registry_t *reg, ngx_log_t *log);
static ngx_int_t ngx_http_ssl_cert_registry_path(
    ngx_http_ssl_cert_registry_t *reg, json_t *value, u_char *buf,
    ngx_log_t *log, size_t index, char *field);
static ngx_int_t ngx_http_ssl_cert_registry_dir(
    ngx_http_ssl_cert_registry_t *reg, json_t *root,
    ngx_http_ssl_cert_table_t *t, ngx_pool_t *pool, ngx_log_t *log);
static ngx_http_ssl_cert_entry_t *ngx_http_ssl_cert_registry_find(
    ngx_http_ssl_cert_table_t *t, u_char *name);
static ngx_int_t ngx_http_ssl_cert_entry_load(ngx_log_t *log, u_char *crt,
    u_char *key, ngx_http_ssl_cert_entry_t *e);
static void ngx_http_ssl_cert_entry_cleanup(void *data);


/* ---------------------------------------------------------------------- */
/* 指令和模块定义                                                         */
/* ---------------------------------------------------------------------- */

/*
 * 本模块提供的配置指令。每一项（ngx_command_t）依次是：
 *
 *   name    指令名
 *   type    可以写在哪些配置块里 | 接受几个参数
 *             NGX_HTTP_MAIN_CONF  可以写在 http{} 里
 *             NGX_HTTP_SRV_CONF   可以写在 server{} 里
 *             NGX_CONF_TAKE1      必须正好 1 个参数
 *   set     解析参数的函数。nginx 提供了常用的现成函数：
 *             ngx_conf_set_str_slot   把参数原样存成 ngx_str_t
 *             ngx_conf_set_sec_slot   把 "5s"、"1m" 这样的时间解析成秒（time_t）
 *             ngx_conf_set_enum_slot  从固定的几个词里选一个，存成对应的数字
 *   conf    值存到哪一层的配置结构体里（main / srv / loc）
 *   offset  存到结构体的哪个字段（offsetof 计算字段偏移）
 *   post    额外参数：enum_slot 用它传可选值列表，其他指令不需要
 */

/*
 * 整个模块只有这一条指令：指向 JSON 清单，其余配置（证书目录、检查间隔、
 * 未匹配策略）都写在清单里。
 *
 * 因为清单里的策略和目录是清单自己的属性，同一份清单被多个 server 引用时
 * 它们共用同一套配置；需要区分就拆成多份清单。
 */

static ngx_command_t  ngx_http_ssl_cert_dir_commands[] = {

    { ngx_string("ssl_cert_registry"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_cert_dir_srv_conf_t, registry_path),
      NULL },

      ngx_null_command                     /* 数组结束标记 */
};


/*
 * HTTP 模块的上下文：nginx 解析 http{} 配置时，会在固定的时机调用这些函数。
 * 调用顺序：
 *
 *   preconfiguration    解析 http{} 之前
 *   create_*_conf       进入每一层配置块时，为本模块分配配置结构体
 *   （解析指令）
 *   （init_main_conf 本模块不需要，对应位置填 NULL）
 *   merge_srv_conf      把 http{} 层的值继承给每个 server{}
 *   postconfiguration   所有配置都处理完之后，适合做"跨模块"的初始化
 *
 * 本模块不需要 location 级别的配置，对应位置填 NULL。
 */

static ngx_http_module_t  ngx_http_ssl_cert_dir_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_ssl_cert_dir_init,             /* postconfiguration */

    ngx_http_ssl_cert_dir_create_main_conf, /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_http_ssl_cert_dir_create_srv_conf,  /* create server configuration */
    ngx_http_ssl_cert_dir_merge_srv_conf,   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


/*
 * 模块定义：变量名必须和 config 文件里的 ngx_module_name 一致，
 * nginx 通过这个符号找到本模块。
 *
 *   NGX_MODULE_V1 / NGX_MODULE_V1_PADDING  固定的头和尾，包含版本号和兼容性签名，
 *                                          动态模块加载时会检查
 *   init master ... exit master            进程生命周期的钩子。本模块只用 init module：
 *                                          配置全部生效后、fork worker 之前，
 *                                          在 master 里做启动检查
 */

ngx_module_t  ngx_http_ssl_cert_dir_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_cert_dir_module_ctx,      /* module context */
    ngx_http_ssl_cert_dir_commands,         /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    ngx_http_ssl_cert_dir_init_module,      /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


/* ---------------------------------------------------------------------- */
/* 配置                                                                   */
/* ---------------------------------------------------------------------- */

/*
 * 创建 http{} 级别的配置结构体（每个 http 块调用一次）
 *
 * 本模块没有 http 级指令，这里只需要两个去重用的数组：所有清单，
 * 以及清单里配置的所有证书目录（启动检查时要扫描）。
 */

static void *
ngx_http_ssl_cert_dir_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_ssl_cert_dir_main_conf_t  *mcf;

    /* ngx_pcalloc：从配置内存池分配并清零，随 cycle 一起释放 */

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssl_cert_dir_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    /* 动态数组，初始容量 4，不够时自动扩容 */

    if (ngx_array_init(&mcf->registries, cf->pool, 4,
                       sizeof(ngx_http_ssl_cert_registry_t *))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&mcf->dirs, cf->pool, 4, sizeof(ngx_str_t)) != NGX_OK) {
        return NULL;
    }

    return mcf;
}


/*
 * 创建 server 级别的配置结构体
 *
 * 注意：除了每个 server{}，http{} 层也会调用一次（用来存写在 http{} 里的值），
 * 之后由 merge_srv_conf 把 http{} 层的值继承下去。
 */

static void *
ngx_http_ssl_cert_dir_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_ssl_cert_dir_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssl_cert_dir_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->registry_path = { 0, NULL };
     *     conf->registry = NULL;
     */

    return conf;
}


/*
 * 合并配置：parent 是 http{} 层，child 是某个 server{}
 *
 * server{} 里没写的指令，继承 http{} 里的值；都没写就是空字符串（不启用）。
 */

static char *
ngx_http_ssl_cert_dir_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_ssl_cert_dir_srv_conf_t *prev = parent;
    ngx_http_ssl_cert_dir_srv_conf_t *conf = child;

    /*
     * 判断标准是 data == NULL（指令没出现过）：
     * 子级没配置就用父级的，父级也没配置就用默认值 ""
     */

    ngx_conf_merge_str_value(conf->registry_path, prev->registry_path, "");

    /* 相对路径按配置文件所在目录解析，和 ssl_certificate 一致 */

    /*
     * ngx_conf_full_name() 的第三个参数为 1 表示相对于配置目录（conf/），
     * 为 0 表示相对于安装目录（--prefix）。已经是绝对路径时原样保留。
     */

    if (conf->registry_path.len
        && ngx_conf_full_name(cf->cycle, &conf->registry_path, 1) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * postconfiguration：所有配置都解析、合并完之后调用（仍在 master 进程里）
 *
 * 这时 ngx_http_ssl_module 已经在它自己的 merge 阶段为每个配置了证书的 server
 * 创建好了 SSL_CTX。这里遍历所有 server：
 *   1. 关联（必要时首次加载）证书清单；
 *   2. 给这个 server 的 SSL_CTX 挂上证书选择回调 cert_cb。
 *
 * 返回 NGX_ERROR 会让 nginx -t / 启动失败。
 */

static ngx_int_t
ngx_http_ssl_cert_dir_init(ngx_conf_t *cf)
{
    ngx_str_t                          *dir;
    ngx_uint_t                          s, i;
    ngx_http_ssl_srv_conf_t            *sscf;
    ngx_http_core_srv_conf_t          **cscfp;
    ngx_http_core_main_conf_t          *cmcf;
    ngx_http_ssl_cert_dir_srv_conf_t   *cdcf;
    ngx_http_ssl_cert_dir_main_conf_t  *mcf;

    /* http 核心模块的 main conf 里保存着所有 server{} 的列表 */

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ssl_cert_dir_module);

    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {

        /*
         * 每个 server 的 ctx->srv_conf 是一个数组，按模块编号（ctx_index）
         * 存放各个模块的 srv conf。这样就能拿到本模块和 SSL 模块在这个
         * server 上的配置。
         */

        cdcf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_cert_dir_module.ctx_index];

        /* 这个 server 没用本模块的指令，跳过 */

        if (cdcf->registry_path.len == 0) {
            continue;
        }

        sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        /*
         * 没有配置 ssl_certificate 的 server，SSL 模块不会为它创建 SSL_CTX，
         * 也就无处挂回调
         */

        if (sscf->ssl.ctx == NULL) {
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                          "\"ssl_cert_registry\" is ignored in a server "
                          "without \"ssl_certificate\"");
            continue;
        }

        /* 同一个清单文件只加载一次，多个 server 共用 */

        cdcf->registry = ngx_http_ssl_cert_registry_get(cf, mcf,
                                                        &cdcf->registry_path);
        if (cdcf->registry == NULL) {
            return NGX_ERROR;
        }

        /*
         * 清单里配了证书目录就记下来（去重），启动检查时要扫描。
         *
         * 这里记的是启动那一刻的目录；运行中清单改了 directory 的话，
         * 只会影响启动检查的覆盖面，握手时用的始终是清单里的新值。
         */

        if (cdcf->registry->table->dir.len) {
            dir = mcf->dirs.elts;

            for (i = 0; i < mcf->dirs.nelts; i++) {
                if (dir[i].len == cdcf->registry->table->dir.len
                    && ngx_strncmp(dir[i].data,
                                   cdcf->registry->table->dir.data,
                                   dir[i].len)
                       == 0)
                {
                    break;
                }
            }

            if (i == mcf->dirs.nelts) {
                dir = ngx_array_push(&mcf->dirs);
                if (dir == NULL) {
                    return NGX_ERROR;
                }

                *dir = cdcf->registry->table->dir;
            }
        }

        /*
         * 挂上证书选择回调。OpenSSL 在处理 ClientHello、准备发送证书之前调用它，
         * 此时 SNI 已经可以读到。最后一个参数会原样传给回调（arg），
         * 这里传的是本 server 的配置，回调里就知道该用哪个清单 / 目录。
         *
         * nginx 自己的 SNI 回调会先根据 server_name 把连接切换到对应
         * server 的 SSL_CTX，所以每个 server 用的是自己挂的这个回调。
         */

        SSL_CTX_set_cert_cb(sscf->ssl.ctx, ngx_http_ssl_cert_dir_cert_cb,
                            cdcf);
    }

    return NGX_OK;
}


/* ---------------------------------------------------------------------- */
/* 启动检查                                                               */
/* ---------------------------------------------------------------------- */

/*
 * init module：配置全部生效之后、fork 出 worker 之前，在 master 进程里调用。
 * nginx -t、启动、每次 reload 都会调用，所以这里的警告在 nginx -t 时就能看到。
 *
 * 做两件事：
 *   1. 检查证书目录里证书的有效期（清单里的证书在加载时已经检查过）；
 *   2. 用 worker 进程的身份，检查清单文件、证书、私钥能不能读到。
 *
 * 为什么不放在 postconfiguration：worker 用哪个用户运行（user 指令）是核心
 * 模块在整个配置文件解析完之后才确定的，postconfiguration 时还拿不到。
 *
 * 发现问题只写警告，不让启动失败：权限问题影响的是之后的重新加载和目录模式的
 * 握手，不应该因此让 nginx 起不来。
 */

static ngx_int_t
ngx_http_ssl_cert_dir_init_module(ngx_cycle_t *cycle)
{
    ngx_int_t                           rc;
    ngx_str_t                          *dir;
    ngx_uint_t                          i, j;
    ngx_pool_t                         *pool;
    ngx_array_t                         files;
    ngx_core_conf_t                    *ccf;
    ngx_http_ssl_cert_entry_t         **ep;
    ngx_http_ssl_cert_registry_t      **regp;
    ngx_http_ssl_cert_dir_main_conf_t  *mcf;

    /* 配置里没有 http{} 时返回 NULL */

    mcf = ngx_http_cycle_get_module_main_conf(cycle,
                                              ngx_http_ssl_cert_dir_module);

    if (mcf == NULL
        || (mcf->registries.nelts == 0 && mcf->dirs.nelts == 0))
    {
        return NGX_OK;
    }

    /* 检查用的临时内存，函数返回前销毁 */

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cycle->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&files, pool, 64, sizeof(ngx_http_ssl_cert_file_t))
        != NGX_OK)
    {
        goto failed;
    }

    /* 1. 收集要检查的文件：清单文件本身，以及清单里每张证书的证书和私钥 */

    regp = mcf->registries.elts;

    for (i = 0; i < mcf->registries.nelts; i++) {

        if (ngx_http_ssl_cert_add_file(&files, regp[i]->path.data,
                                       regp[i]->path.len, "ssl_cert_registry")
            != NGX_OK)
        {
            goto failed;
        }

        ep = regp[i]->table->entries.elts;

        for (j = 0; j < regp[i]->table->entries.nelts; j++) {

            if (ngx_http_ssl_cert_add_file(&files, ep[j]->cert_path,
                                           ngx_strlen(ep[j]->cert_path),
                                           "ssl_cert_registry")
                != NGX_OK
                || ngx_http_ssl_cert_add_file(&files, ep[j]->key_path,
                                              ngx_strlen(ep[j]->key_path),
                                              "ssl_cert_registry")
                   != NGX_OK)
            {
                goto failed;
            }
        }
    }

    /* 证书目录：扫描出 *.crt / *.key，顺带检查证书的有效期 */

    dir = mcf->dirs.elts;

    for (i = 0; i < mcf->dirs.nelts; i++) {
        if (ngx_http_ssl_cert_scan_dir(cycle->log, &dir[i], &files)
            != NGX_OK)
        {
            goto failed;
        }
    }

    /*
     * 2. 只有 master 是 root、worker 会切换成别的用户时才需要检查权限：
     *      不是 root 启动         worker 和 master 是同一个用户，现在能读就一直能读
     *      master_process off    不会切换用户
     *      user root             worker 也是 root
     *
     *    没写 user 指令时，核心模块已经填好了编译时的默认用户（通常是 nobody）
     */

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    rc = NGX_OK;

    if (geteuid() == 0
        && ccf->master
        && ccf->user != 0
        && ccf->user != (ngx_uid_t) NGX_CONF_UNSET_UINT)
    {
        rc = ngx_http_ssl_cert_check_files(cycle, ccf, &files);
    }

    ngx_destroy_pool(pool);

    return rc;

failed:

    ngx_destroy_pool(pool);

    return NGX_ERROR;
}


/*
 * 扫描证书目录，把 *.crt 和 *.key 加进待检查列表，*.crt 顺带检查有效期。
 * 目录模式的证书在握手时才读，这里是唯一能提前发现问题的地方。
 *
 * 以 master（root）的身份扫描：worker 只需要目录的 x 权限（进入目录、打开
 * 已知文件名的文件），不需要 r 权限（列出目录内容），不能用它的身份来列。
 *
 * 目录打不开只写警告，返回 NGX_OK；只有内存分配失败才返回 NGX_ERROR。
 */

static ngx_int_t
ngx_http_ssl_cert_scan_dir(ngx_log_t *log, ngx_str_t *dir,
    ngx_array_t *files)
{
    u_char      *name, *p;
    size_t       len;
    BIO         *bio;
    X509        *cert;
    ngx_err_t    err;
    ngx_int_t    rc;
    ngx_str_t    path;
    ngx_dir_t    d;
    ngx_uint_t   is_crt;
    u_char       buf[NGX_MAX_PATH];

    /* ngx_open_dir() 要求路径以 '\0' 结尾，复制一份确保这一点 */

    if (dir->len >= NGX_MAX_PATH) {
        return NGX_OK;
    }

    p = ngx_cpymem(buf, dir->data, dir->len);
    *p = '\0';

    path.len = dir->len;
    path.data = buf;

    if (ngx_open_dir(&path, &d) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "ssl_cert_dir: " ngx_open_dir_n " \"%V\" failed", dir);
        return NGX_OK;
    }

    rc = NGX_OK;

    for ( ;; ) {

        /*
         * readdir() 读到末尾时返回 NULL 但不设置 errno，先清零才能区分
         * "读完了"和"出错了"
         */

        ngx_set_errno(0);

        if (ngx_read_dir(&d) == NGX_ERROR) {
            err = ngx_errno;

            if (err != NGX_ENOMOREFILES) {
                ngx_log_error(NGX_LOG_WARN, log, err,
                              "ssl_cert_dir: " ngx_read_dir_n " \"%V\" failed",
                              dir);
            }

            break;
        }

        /* 只关心 <名字>.crt 和 <名字>.key */

        name = ngx_de_name(&d);
        len = ngx_de_namelen(&d);

        if (len <= 4) {
            continue;
        }

        if (ngx_strcmp(name + len - 4, ".crt") == 0) {
            is_crt = 1;

        } else if (ngx_strcmp(name + len - 4, ".key") == 0) {
            is_crt = 0;

        } else {
            continue;
        }

        /* buf = "<目录>/<文件名>"；太长的文件名握手时也拼不出来，跳过 */

        if (dir->len + 1 + len >= NGX_MAX_PATH) {
            continue;
        }

        p = ngx_cpymem(buf, dir->data, dir->len);
        *p++ = '/';
        p = ngx_cpymem(p, name, len);
        *p = '\0';

        if (ngx_http_ssl_cert_add_file(files, buf, p - buf, "ssl_cert_dir")
            != NGX_OK)
        {
            rc = NGX_ERROR;
            break;
        }

        if (!is_crt) {
            continue;
        }

        /* 只读第一张（叶子证书），检查有效期 */

        bio = BIO_new_file((char *) buf, "r");
        if (bio == NULL) {
            ngx_ssl_error(NGX_LOG_WARN, log, 0,
                          "ssl_cert_dir: cannot open certificate \"%s\"", buf);
            continue;
        }

        cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
        BIO_free(bio);

        if (cert == NULL) {
            ngx_ssl_error(NGX_LOG_WARN, log, 0,
                          "ssl_cert_dir: cannot read certificate \"%s\"", buf);
            continue;
        }

        ngx_http_ssl_cert_check_expiry(log, cert, buf, "ssl_cert_dir");

        X509_free(cert);
    }

    ngx_close_dir(&d);

    return rc;
}


/*
 * 加进待检查列表。同一个文件可能同时被清单和目录引用，已经有了就跳过；
 * 文件数量不会很多，线性查找就够了。
 *
 *   path   不要求以 '\0' 结尾，会复制一份（带 '\0'）到 files 的内存池
 */

static ngx_int_t
ngx_http_ssl_cert_add_file(ngx_array_t *files, u_char *path, size_t len,
    char *prefix)
{
    ngx_uint_t                 i;
    ngx_http_ssl_cert_file_t  *f;

    f = files->elts;

    for (i = 0; i < files->nelts; i++) {
        if (f[i].path.len == len
            && ngx_strncmp(f[i].path.data, path, len) == 0)
        {
            return NGX_OK;
        }
    }

    f = ngx_array_push(files);
    if (f == NULL) {
        return NGX_ERROR;
    }

    f->path.len = len;
    f->path.data = ngx_pnalloc(files->pool, len + 1);
    if (f->path.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(f->path.data, path, len);
    f->path.data[len] = '\0';

    f->prefix = prefix;

    return NGX_OK;
}


/*
 * 临时把 master 的附加组、有效组、有效用户切换成 worker 的，逐个打开文件
 * 检查，然后再切换回来。
 *
 * 和 worker 启动时一样调用 initgroups()，并且是真的 open() 一次，所以附加组、
 * ACL、每一级目录的 x 权限都考虑到了，结果和 worker 实际运行时一致。
 *
 * 只改"有效"用户：master 的真实用户和保存的用户仍然是 root，所以 seteuid(0)
 * 一定能切回来。万一切不回来，master 已经无法正常工作，返回 NGX_ERROR，
 * nginx 会直接退出。
 */

static ngx_int_t
ngx_http_ssl_cert_check_files(ngx_cycle_t *cycle, ngx_core_conf_t *ccf,
    ngx_array_t *files)
{
    int                        n;
    gid_t                     *groups, egid;
    ngx_uint_t                 i;
    ngx_array_t                reported;
    ngx_http_ssl_cert_file_t  *f;

    /* 保存 master 当前的附加组和有效组，检查完恢复 */

    n = getgroups(0, NULL);
    if (n == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "ssl_cert_dir: getgroups() failed, "
                      "permission check skipped");
        return NGX_OK;
    }

    /* 多分配一个，避免 n 为 0 时分配 0 字节 */

    groups = ngx_palloc(files->pool, (n + 1) * sizeof(gid_t));
    if (groups == NULL) {
        return NGX_ERROR;
    }

    n = getgroups(n, groups);
    if (n == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "ssl_cert_dir: getgroups() failed, "
                      "permission check skipped");
        return NGX_OK;
    }

    egid = getegid();

    /* 已经报告过的目录，同一个目录只报一次 */

    if (ngx_array_init(&reported, files->pool, 4, sizeof(ngx_str_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * 切换成 worker 的身份，顺序和 worker 启动时一样：先改组，最后改用户
     * （改成普通用户之后就没有权限再改组了）
     */

    if (initgroups(ccf->username, ccf->group) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "ssl_cert_dir: initgroups(%s, %d) failed, "
                      "permission check skipped", ccf->username, ccf->group);
        goto restore_groups;
    }

    if (setegid(ccf->group) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "ssl_cert_dir: setegid(%d) failed, "
                      "permission check skipped", ccf->group);
        goto restore_groups;
    }

    if (seteuid(ccf->user) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "ssl_cert_dir: seteuid(%d) failed, "
                      "permission check skipped", ccf->user);
        goto restore_gid;
    }

    f = files->elts;

    for (i = 0; i < files->nelts; i++) {
        ngx_http_ssl_cert_check_access(cycle->log, &f[i], ccf->username,
                                       &reported);
    }

    /* 切换回 root：顺序和上面相反，先恢复用户，才有权限恢复组 */

    if (seteuid(0) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "ssl_cert_dir: seteuid(0) failed");
        return NGX_ERROR;
    }

restore_gid:

    if (setegid(egid) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "ssl_cert_dir: setegid(%d) failed", egid);
        return NGX_ERROR;
    }

restore_groups:

    if (setgroups(n, groups) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "ssl_cert_dir: setgroups() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * 以当前身份（已经切换成 worker 的）打开一次文件，打不开就写警告。
 *
 * 因为权限不足（EACCES）打不开时，再从上往下找第一个进不去的目录，日志里
 * 直接指出是哪个目录的问题。同一个目录只报一次（reported 记录已经报过的），
 * 避免 /root 这类目录下的几十个文件各报一遍。
 */

static void
ngx_http_ssl_cert_check_access(ngx_log_t *log, ngx_http_ssl_cert_file_t *f,
    char *user, ngx_array_t *reported)
{
    u_char           *p;
    size_t            len;
    ngx_fd_t          fd;
    ngx_err_t         err;
    ngx_str_t        *dir, name;
    ngx_uint_t        i;
    ngx_file_info_t   fi;
    u_char            buf[NGX_MAX_PATH];

    fd = ngx_open_file(f->path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd != NGX_INVALID_FILE) {
        ngx_close_file(fd);
        return;
    }

    err = ngx_errno;

    if (err == NGX_EACCES) {

        /*
         * 依次检查每一级目录，例如 "/root/.acme.sh/a.key"：
         * 先查 "/root"，再查 "/root/.acme.sh"。
         * stat("<目录>/.") 要求对这个目录（以及它的所有上级）有 x 权限，
         * 从上往下第一个失败的就是问题所在。都没问题说明是文件本身不可读。
         */

        for (p = f->path.data + 1; p < f->path.data + f->path.len; p++) {

            if (*p != '/') {
                continue;
            }

            len = p - f->path.data;

            if (len + sizeof("/.") > NGX_MAX_PATH) {
                break;
            }

            ngx_memcpy(buf, f->path.data, len);
            ngx_memcpy(buf + len, "/.", sizeof("/."));    /* 连同 '\0' */

            if (ngx_file_info(buf, &fi) != NGX_FILE_ERROR
                || ngx_errno != NGX_EACCES)
            {
                continue;
            }

            /* 找到了：f->path 的前 len 个字节就是这个目录 */

            name.len = len;
            name.data = f->path.data;

            dir = reported->elts;

            for (i = 0; i < reported->nelts; i++) {
                if (dir[i].len == len
                    && ngx_strncmp(dir[i].data, name.data, len) == 0)
                {
                    return;
                }
            }

            dir = ngx_array_push(reported);
            if (dir != NULL) {
                *dir = name;
            }

            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "%s: directory \"%V\" is not accessible to worker "
                          "processes (user \"%s\"), files under it such as "
                          "\"%V\" cannot be read",
                          f->prefix, &name, user, &f->path);
            return;
        }
    }

    ngx_log_error(NGX_LOG_WARN, log, err,
                  "%s: \"%V\" is not readable by worker processes "
                  "(user \"%s\")", f->prefix, &f->path, user);
}


/*
 * 证书快到期或者已经过期时写一条警告。只是提醒，证书照常使用。
 *
 *   path、prefix 只用于日志
 */

static void
ngx_http_ssl_cert_check_expiry(ngx_log_t *log, X509 *cert, u_char *path,
    char *prefix)
{
    int  days, secs;

    /*
     * 计算从现在（from 传 NULL）到证书到期时间还有多久，结果拆成
     * "天数 + 秒数"，两者符号相同，是负数就说明已经过期
     */

    if (ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(cert)) != 1) {
        ERR_clear_error();
        return;
    }

    if (days < 0 || secs < 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "%s: certificate \"%s\" has expired", prefix, path);

    } else if (days < NGX_HTTP_SSL_CERT_EXPIRE_WARN_DAYS) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "%s: certificate \"%s\" expires in %d days",
                      prefix, path, days);
    }
}


/* ---------------------------------------------------------------------- */
/* 握手                                                                   */
/* ---------------------------------------------------------------------- */

/*
 * OpenSSL 在握手中选择证书前调用，返回 1 继续握手，返回 0 终止握手
 *
 * 运行在 worker 进程的事件循环里：这里的任何耗时操作都会拖慢这个 worker
 * 上的所有连接，所以清单模式下握手只查内存，不读磁盘。
 *
 * 处理流程：
 *
 *   检查清单是否需要重新加载
 *   读取 SNI
 *     ├─ 没有 SNI / SNI 不合法 ──────────────────────────→ 匹配不上
 *     └─ 合法的域名
 *          ├─ 1. 清单：精确匹配 → "*.上一级域名" ─────────→ 找到就用
 *          ├─ 2. 目录：<域名>.crt → wildcard.<上一级>.crt ─→ 找到就用
 *          └─ 都没找到 ─────────────────────────────────────→ 匹配不上
 *   匹配不上：写一条 info 日志，然后看清单里的 unmatched
 *     ├─ reject   拒绝握手
 *     └─ default  使用默认证书
 *          ├─ 3. 清单里 isDefault 的证书
 *          └─ 4. 什么都不做，沿用 ssl_certificate 配置的证书
 */

static int
ngx_http_ssl_cert_dir_cert_cb(ngx_ssl_conn_t *ssl_conn, void *arg)
{
    ngx_http_ssl_cert_dir_srv_conf_t  *cdcf = arg;

    char                       *reason, *action;
    u_char                     *dot, *shown, ch;
    size_t                      i;
    ngx_int_t                   rc;
    ngx_uint_t                  unmatched;
    ngx_str_t                  *dir;
    const char                 *sni;
    ngx_connection_t           *c;
    ngx_http_ssl_cert_entry_t  *e;
    ngx_http_ssl_cert_table_t  *table;
    u_char                      name[NGX_HTTP_SSL_CERT_MAX_NAME + 1];
    u_char                      base[NGX_HTTP_SSL_CERT_MAX_NAME
                                     + sizeof("wildcard.")];

    /* 从 OpenSSL 的连接对象取回 nginx 的连接对象（主要用它的日志） */

    c = ngx_ssl_get_connection(ssl_conn);

    table = NULL;

    /*
     * 没有用定时器，而是借握手的机会检查清单：每隔 interval 秒才真正 stat
     * 一次文件，其他时候只是比较一下时间，几乎没有开销
     */

    if (cdcf->registry) {
        ngx_http_ssl_cert_registry_refresh(cdcf->registry, c->log);
        table = cdcf->registry->table;
    }

    /*
     * 未匹配时的策略和证书目录都来自清单。策略是清单的属性，所以同一份
     * 清单被多个 server 引用时，它们共用同一套策略。
     */

    unmatched = (table != NULL && table->unmatched_set)
                ? table->unmatched
                : NGX_HTTP_SSL_CERT_UNMATCHED_DEFAULT;

    dir = (table != NULL) ? &table->dir : NULL;

    /* 客户端在 ClientHello 里发来的域名，没有发就是 NULL */

    sni = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);

    if (sni == NULL) {
        reason = "no server name";
        shown = NULL;
        goto unmatched;
    }

    /* SNI 是客户端随意填写的，校验并转成小写后才能使用 */

    if (ngx_http_ssl_cert_normalize(sni, name, sizeof(name), 0) != NGX_OK) {

        /*
         * 不合法的 SNI 可能带换行等控制字符，原样写进日志会伪造出假的日志行。
         * 把不可打印的字符、引号和反斜杠替换成 '?' 后再写（复用 name 缓冲区，
         * 超长的截断）
         */

        for (i = 0; sni[i] != '\0' && i < sizeof(name) - 1; i++) {
            ch = (u_char) sni[i];
            name[i] = (ch < 0x20 || ch >= 0x7f || ch == '"' || ch == '\\')
                      ? '?' : ch;
        }

        name[i] = '\0';

        reason = "invalid server name";
        shown = name;
        goto unmatched;
    }

    /* 1. 证书清单 */

    if (table) {
        e = ngx_http_ssl_cert_registry_find(table, name);

        if (e) {
            return ngx_http_ssl_cert_use(ssl_conn, c, e, name);
        }
    }

    /* 2. 证书目录 */

    if (dir != NULL && dir->len) {

        /* 先找 <dir>/<域名>.crt */

        rc = ngx_http_ssl_cert_dir_load(ssl_conn, c, dir, name);

        /* 找到了（成功或失败）就不再往下找；只有"文件不存在"才继续 */

        if (rc != NGX_DECLINED) {
            return (rc == NGX_OK) ? 1 : 0;
        }

        /*
         * 再找通配符证书：x.example.com -> wildcard.example.com.crt
         * 要求上一级域名里至少还有一个点，避免 x.com -> wildcard.com
         */

        dot = (u_char *) ngx_strchr(name, '.');

        if (dot != NULL && ngx_strchr(dot + 1, '.') != NULL) {

            /* %Z 表示写入 '\0'；base 的长度已经按最长域名加前缀预留 */

            ngx_sprintf(base, "wildcard.%s%Z", dot + 1);

            rc = ngx_http_ssl_cert_dir_load(ssl_conn, c, dir, base);

            if (rc != NGX_DECLINED) {
                return (rc == NGX_OK) ? 1 : 0;
            }
        }
    }

    reason = "no certificate for";
    shown = name;

unmatched:

    /*
     * 匹配不上：写一条 info 日志（error_log 的级别设成 info 才看得到），
     * 方便找出哪些域名还没有配置证书。c->log 会自动带上客户端地址。
     * 日志级别不够时 ngx_log_error 在宏里就直接跳过了，没有开销。
     */

    if (unmatched == NGX_HTTP_SSL_CERT_UNMATCHED_REJECT) {
        action = "handshake rejected";

    } else if (table && table->default_entry) {
        action = "using the \"isDefault\" certificate";

    } else {
        action = "using \"ssl_certificate\"";
    }

    if (shown) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "ssl_cert_dir: %s \"%s\", %s",
                      reason, shown, action);

    } else {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "ssl_cert_dir: %s, %s",
                      reason, action);
    }

    /*
     * unmatched 为 reject：返回 0，OpenSSL 给客户端发送 internal_error
     * 告警并结束握手。nginx 把这种握手失败（"cert cb error"）记为 info 级别，
     * 不会因为扫描器大量访问而刷屏
     */

    if (unmatched == NGX_HTTP_SSL_CERT_UNMATCHED_REJECT) {
        return 0;
    }

    /* 3. 清单里 isDefault 的证书 */

    if (table && table->default_entry) {
        return ngx_http_ssl_cert_use(ssl_conn, c, table->default_entry,
                                     (u_char *) "default");
    }

    /* 4. ssl_certificate 配置的证书：不做任何替换 */

    /*
     * SSL 对象创建时已经从 SSL_CTX 继承了 ssl_certificate 配置的证书，
     * 什么都不改，握手就会使用它
     */

    return 1;
}


/*
 * 把内存里的证书设置到当前连接，返回值同 cert_cb
 *
 * what 只用于日志：域名，或者 "default"
 */

static int
ngx_http_ssl_cert_use(ngx_ssl_conn_t *ssl_conn, ngx_connection_t *c,
    ngx_http_ssl_cert_entry_t *e, u_char *what)
{
    /*
     * 先清掉从 SSL_CTX 继承来的证书，否则两者密钥类型不同时
     * （ECDSA / RSA），OpenSSL 可能仍然选中 ssl_certificate 那张
     */

    SSL_certs_clear(ssl_conn);

    /*
     * 只影响当前这一个连接，不会修改 SSL_CTX。
     *
     * OpenSSL 会给证书和私钥增加引用计数、复制一份证书链，连接持有自己的引用，
     * 所以之后证书表被替换、旧表被释放，也不影响这个连接。
     * 最后一个参数 1 表示覆盖已有的证书。
     */

    if (SSL_use_cert_and_key(ssl_conn, e->cert, e->pkey, e->chain, 1) != 1) {

        /* ngx_ssl_error 会把 OpenSSL 的错误队列一起写进日志 */

        ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                      "ssl_cert_registry: SSL_use_cert_and_key() failed "
                      "for \"%s\"", what);
        return 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "ssl_cert_registry: using certificate for \"%s\"", what);

    return 1;
}


/*
 * 域名校验并转成小写：只允许字母、数字、"-" 和 "."，不允许连续的点和
 * 首尾的点。allow_wildcard 时允许以 "*." 开头（清单里的通配符域名）。
 * SNI 来自客户端，必须校验后才能拼进文件路径或用于查表。
 *
 *   in      输入，以 '\0' 结尾
 *   out     输出缓冲区，长度为 size；成功时写入小写域名并以 '\0' 结尾
 *   返回    NGX_OK 合法；NGX_ERROR 不合法或太长
 *
 * 不允许 "/" 和 "..", 所以拼进路径后不可能跳出证书目录。
 */

static ngx_int_t
ngx_http_ssl_cert_normalize(const char *in, u_char *out, size_t size,
    ngx_uint_t allow_wildcard)
{
    u_char  ch;
    size_t  i, len, start;

    len = ngx_strlen(in);

    /* 留一个字节给 '\0' */

    if (len == 0 || len >= size) {
        return NGX_ERROR;
    }

    start = 0;

    if (allow_wildcard && len > 2 && in[0] == '*' && in[1] == '.') {

        /* "*.com" 这样只有一级的通配符不允许 */

        if (ngx_strchr(in + 2, '.') == NULL) {
            return NGX_ERROR;
        }

        out[0] = '*';
        out[1] = '.';
        start = 2;
    }

    for (i = start; i < len; i++) {
        ch = ngx_tolower((u_char) in[i]);

        /* 字母、数字、连字符 */

        if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-')
        {
            out[i] = ch;
            continue;
        }

        /* 点：不能在开头、不能在结尾、不能连续出现 */

        if (ch == '.' && i != start && i != len - 1 && out[i - 1] != '.') {
            out[i] = ch;
            continue;
        }

        return NGX_ERROR;
    }

    out[len] = '\0';

    return NGX_OK;
}


/*
 * 证书目录：加载 <dir>/<base>.crt 和 .key
 *
 *   NGX_OK        已加载
 *   NGX_DECLINED  证书文件不存在，交给下一种匹配方式
 *   NGX_ERROR     文件存在但加载失败，终止握手
 *
 * 注意：这里每次握手都会读磁盘（阻塞 I/O），性能不如清单模式。
 */

static ngx_int_t
ngx_http_ssl_cert_dir_load(ngx_ssl_conn_t *ssl_conn, ngx_connection_t *c,
    ngx_str_t *dir, u_char *base)
{
    u_char           *p;
    ngx_file_info_t   fi;
    u_char            crt[NGX_MAX_PATH], key[NGX_MAX_PATH];

    /*
     * ngx_snprintf 不会自动写 '\0'，返回写入位置的末尾。
     * 最多写 NGX_MAX_PATH - 1 个字节，留一个字节给 '\0'；
     * 写满了说明路径被截断，当作文件不存在处理。
     */

    p = ngx_snprintf(crt, NGX_MAX_PATH - 1, "%V/%s.crt", dir, base);
    if (p == crt + NGX_MAX_PATH - 1) {
        return NGX_DECLINED;
    }
    *p = '\0';

    p = ngx_snprintf(key, NGX_MAX_PATH - 1, "%V/%s.key", dir, base);
    if (p == key + NGX_MAX_PATH - 1) {
        return NGX_DECLINED;
    }
    *p = '\0';

    /* stat() 失败（通常是文件不存在）：交给下一种匹配方式 */

    if (ngx_file_info(crt, &fi) == NGX_FILE_ERROR) {
        return NGX_DECLINED;
    }

    /* 原因同 ngx_http_ssl_cert_use()：避免混用不同密钥类型的证书 */

    SSL_certs_clear(ssl_conn);

    /* 读取完整证书链（叶子证书在前，中间证书在后） */

    if (SSL_use_certificate_chain_file(ssl_conn, (char *) crt) != 1) {
        ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                      "ssl_cert_dir: cannot load certificate \"%s\"", crt);
        return NGX_ERROR;
    }

    if (SSL_use_PrivateKey_file(ssl_conn, (char *) key, SSL_FILETYPE_PEM)
        != 1)
    {
        ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                      "ssl_cert_dir: cannot load certificate key \"%s\"",
                      key);
        return NGX_ERROR;
    }

    /* 证书和私钥必须是一对，否则握手时签名验证会失败 */

    if (SSL_check_private_key(ssl_conn) != 1) {
        ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                      "ssl_cert_dir: certificate \"%s\" and key \"%s\" "
                      "do not match", crt, key);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "ssl_cert_dir: using certificate \"%s\"", crt);

    return NGX_OK;
}


/* ---------------------------------------------------------------------- */
/* 证书清单                                                               */
/* ---------------------------------------------------------------------- */

/* 日志用：清单里 "unmatched" 的值 */

static const char *
ngx_http_ssl_cert_unmatched_name(ngx_http_ssl_cert_table_t *t)
{
    if (!t->unmatched_set) {
        return "default";
    }

    return (t->unmatched == NGX_HTTP_SSL_CERT_UNMATCHED_REJECT)
           ? "reject" : "default";
}


/*
 * 配置阶段：取得（或创建并首次加载）某个清单文件对应的 registry。
 * 首次加载在 master 进程里完成，失败会让 nginx -t / 启动直接报错。
 *
 *   mcf    main conf，里面的 registries 数组按路径去重
 *   path   已经转换成完整路径的清单文件名（不一定以 '\0' 结尾）
 *   返回   registry；NULL 表示出错
 */

static ngx_http_ssl_cert_registry_t *
ngx_http_ssl_cert_registry_get(ngx_conf_t *cf,
    ngx_http_ssl_cert_dir_main_conf_t *mcf, ngx_str_t *path)
{
    u_char                         *p;
    ngx_uint_t                      i;
    ngx_file_info_t                 fi;
    ngx_pool_cleanup_t             *cln;
    ngx_http_ssl_cert_registry_t  **regp, *reg;

    /* 已经加载过同一个文件，直接复用 */

    regp = mcf->registries.elts;

    for (i = 0; i < mcf->registries.nelts; i++) {
        if (regp[i]->path.len == path->len
            && ngx_strncmp(regp[i]->path.data, path->data, path->len) == 0)
        {
            return regp[i];
        }
    }

    reg = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssl_cert_registry_t));
    if (reg == NULL) {
        return NULL;
    }

    /* 保证路径以 '\0' 结尾，方便直接传给 stat() 和 jansson */

    reg->path.len = path->len;
    reg->path.data = ngx_pnalloc(cf->pool, path->len + 1);
    if (reg->path.data == NULL) {
        return NULL;
    }
    ngx_cpystrn(reg->path.data, path->data, path->len + 1);

    /* 清单文件所在目录，用来解析清单里的相对路径 */

    /*
     * 从后往前找最后一个 '/'，dir 和 path 共用同一块内存，只是长度不同：
     *   path = "/opt/conf/certs.json"  ->  dir = "/opt/conf"
     */

    reg->dir.data = reg->path.data;
    reg->dir.len = 0;

    for (p = reg->path.data + reg->path.len; p > reg->path.data; p--) {
        if (*(p - 1) == '/') {
            reg->dir.len = p - 1 - reg->path.data;
            break;
        }
    }

    /*
     * 运行中重新加载时，证书表的内存池用 cycle 的日志对象，
     * 而不是连接的日志对象（连接关闭后就失效了）
     */

    reg->log = cf->cycle->log;
    reg->interval = NGX_HTTP_SSL_CERT_DEFAULT_INTERVAL;

    /* 先 stat 一次：既检查文件存在，也记下状态，用于以后判断是否变化 */

    if (ngx_file_info(reg->path.data, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "ssl_cert_registry: " ngx_file_info_n
                           " \"%V\" failed", &reg->path);
        return NULL;
    }

    /* 首次加载：读 JSON、读所有证书、建哈希表 */

    reg->table = ngx_http_ssl_cert_registry_build(reg, cf->log);
    if (reg->table == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ssl_cert_registry: failed to load \"%V\"",
                           &reg->path);
        return NULL;
    }

    /* 清单里写了 interval 就用它，否则用内置默认值 */

    if (reg->table->interval_set) {
        reg->interval = reg->table->interval;
    }

    reg->uniq = ngx_file_uniq(&fi);
    reg->mtime = ngx_file_mtime(&fi);
    reg->size = ngx_file_size(&fi);
    reg->checked = ngx_time();

    /*
     * 在配置内存池上注册清理函数：nginx reload 或退出、这个 cycle 被销毁时，
     * 顺带释放当前的证书表（证书表用的是独立的内存池，不会自动释放）
     */

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_ssl_cert_registry_cleanup;
    cln->data = reg;

    regp = ngx_array_push(&mcf->registries);
    if (regp == NULL) {
        return NULL;
    }

    *regp = reg;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "ssl_cert_registry: \"%V\" loaded: %ui certificates, "
                  "%ui domains, default: %s, directory: %s, interval: %i, "
                  "unmatched: %s",
                  &reg->path, reg->table->entries.nelts,
                  reg->table->ndomains,
                  reg->table->default_entry ? "yes" : "no",
                  reg->table->dir.len ? (char *) reg->table->dir.data : "no",
                  (ngx_int_t) reg->interval,
                  ngx_http_ssl_cert_unmatched_name(reg->table));

    return reg;
}


/*
 * cycle 销毁时释放当前的证书表
 */

static void
ngx_http_ssl_cert_registry_cleanup(void *data)
{
    ngx_http_ssl_cert_registry_t  *reg = data;

    if (reg->table) {

        /* 释放内存池时，会依次调用池上注册的 cleanup，释放 OpenSSL 对象 */

        ngx_destroy_pool(reg->table->pool);
        reg->table = NULL;
    }
}


/*
 * 握手时调用：距离上次检查超过 interval 秒，就看一下清单文件有没有变化，
 * 变化了就重新加载。加载失败时保留当前的证书表。
 *
 * 每个 worker 各自调用、各自维护自己的 registry 副本（fork 之后写时复制），
 * 所以不需要加锁。
 *
 * 注意：重新加载是同步完成的，要读所有证书文件，这段时间里这个 worker
 * 上的其他连接都要等。证书很多时可以考虑改成增量加载。
 */

static void
ngx_http_ssl_cert_registry_refresh(ngx_http_ssl_cert_registry_t *reg,
    ngx_log_t *log)
{
    time_t                      now;
    ngx_file_info_t             fi;
    ngx_http_ssl_cert_table_t  *t;

    /* ngx_time() 读的是 nginx 缓存的时间，不是系统调用，非常快 */

    now = ngx_time();

    if (now - reg->checked < reg->interval) {
        return;
    }

    reg->checked = now;

    /* 文件暂时不存在（比如正在替换）：保留当前证书表，下个周期再看 */

    if (ngx_file_info(reg->path.data, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "ssl_cert_registry: " ngx_file_info_n " \"%V\" failed, "
                      "keeping current certificates", &reg->path);
        return;
    }

    /*
     * 三项都没变才认为文件没变化：
     *   inode     用 mv 替换文件时会变
     *   修改时间  touch 或改写内容时会变（精度到秒）
     *   大小      同一秒内改了两次时作为补充判断
     */

    if (ngx_file_uniq(&fi) == reg->uniq
        && ngx_file_mtime(&fi) == reg->mtime
        && ngx_file_size(&fi) == reg->size)
    {
        return;
    }

    /*
     * 加载失败时不更新文件状态，下个周期会再试一次
     * （比如文件正写到一半，下次就能读到完整的了）
     */

    t = ngx_http_ssl_cert_registry_build(reg, log);

    if (t == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "ssl_cert_registry: \"%V\" not reloaded, "
                      "keeping current certificates", &reg->path);
        return;
    }

    /*
     * 新清单里的 interval 从下一次检查开始生效。清单里删掉了 interval 时，
     * 回落到内置默认值，而不是继续沿用上一份清单的值。
     */

    reg->interval = t->interval_set ? t->interval
                                    : NGX_HTTP_SSL_CERT_DEFAULT_INTERVAL;

    /* 新表建好了才释放旧表，任何时刻都有一张可用的表 */

    if (reg->table) {
        ngx_destroy_pool(reg->table->pool);
    }

    reg->table = t;
    reg->uniq = ngx_file_uniq(&fi);
    reg->mtime = ngx_file_mtime(&fi);
    reg->size = ngx_file_size(&fi);

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "ssl_cert_registry: \"%V\" reloaded: %ui certificates, "
                  "%ui domains, default: %s, directory: %s, interval: %i, "
                  "unmatched: %s",
                  &reg->path, t->entries.nelts, t->ndomains,
                  t->default_entry ? "yes" : "no",
                  t->dir.len ? (char *) t->dir.data : "no",
                  (ngx_int_t) reg->interval,
                  ngx_http_ssl_cert_unmatched_name(t));
}


/*
 * 读取 JSON 清单，加载所有启用的证书，建立 域名 -> 证书 的哈希表。
 * 任何一条记录出错，整份清单都视为加载失败（返回 NULL）。
 *
 * 步骤：
 *   1. jansson 解析 JSON 文件
 *   2. 创建两个内存池：pool 给新表用，temp_pool 只在建表时用
 *   3. 处理顶层字段 interval / unmatched / directory
 *   4. 逐条处理 certificates：校验字段 -> 读 PEM -> 把每个域名加进哈希 key 列表
 *   5. ngx_hash_init() 根据 key 列表生成最终的哈希表
 *   6. 销毁 temp_pool，返回新表
 *
 * "certificates" 和 "directory" 至少要有一个；只有 directory 时，哈希表是空的，
 * 握手时只走目录模式。
 *
 * 出错时销毁两个内存池（已经读进来的 OpenSSL 对象由 cleanup 释放）并返回 NULL。
 */

static ngx_http_ssl_cert_table_t *
ngx_http_ssl_cert_registry_build(ngx_http_ssl_cert_registry_t *reg,
    ngx_log_t *log)
{
    size_t                      i, j;
    json_t                     *root, *certs, *item, *domains, *value,
                               *enabled, *isdef, *empty;
    ngx_int_t                   rc;
    ngx_uint_t                  is_default;
    json_int_t                  n;
    ngx_int_t                   tt;
    ngx_str_t                   name, tv;
    const char                 *s;
    json_error_t                jerr;
    ngx_pool_t                 *pool, *temp_pool;
    ngx_hash_init_t             hinit;
    ngx_pool_cleanup_t         *cln;
    ngx_hash_keys_arrays_t      ha;
    ngx_http_ssl_cert_entry_t  *e, **ep;
    ngx_http_ssl_cert_table_t  *t;
    u_char                      crt[NGX_MAX_PATH], key[NGX_MAX_PATH];
    u_char                      norm[NGX_HTTP_SSL_CERT_MAX_NAME + 1];

    /* 1. 解析 JSON；格式错误时 jerr 里有行号和原因 */

    root = json_load_file((char *) reg->path.data, 0, &jerr);

    if (root == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "ssl_cert_registry: \"%V\", line %d: %s",
                      &reg->path, jerr.line, jerr.text);
        return NULL;
    }

    /* 先置空，出错跳到 failed 时才知道哪些需要释放 */

    pool = NULL;
    temp_pool = NULL;
    empty = NULL;

    /* 2. 创建内存池，16 KB 起步，不够时自动扩展 */

    pool = ngx_create_pool(16384, reg->log);
    if (pool == NULL) {
        goto failed;
    }

    temp_pool = ngx_create_pool(16384, reg->log);
    if (temp_pool == NULL) {
        goto failed;
    }

    t = ngx_pcalloc(pool, sizeof(ngx_http_ssl_cert_table_t));
    if (t == NULL) {
        goto failed;
    }

    t->pool = pool;

    if (ngx_array_init(&t->entries, pool, 16,
                       sizeof(ngx_http_ssl_cert_entry_t *))
        != NGX_OK)
    {
        goto failed;
    }

    /*
     * 构建 nginx 哈希表的辅助结构：先往里面加 key，最后一次性生成哈希表。
     * NGX_HASH_SMALL 表示预计 key 不多，初始空间小一些，不够会自动扩展。
     */

    ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

    ha.pool = pool;
    ha.temp_pool = temp_pool;

    if (ngx_hash_keys_array_init(&ha, NGX_HASH_SMALL) != NGX_OK) {
        goto failed;
    }

    /*
     * 顶层可选配置：
     *
     *   "interval"   检查间隔。整数表示秒，也可以写成 "5s"、"1m" 这样的
     *                时间字符串；没写就是默认的 5 秒。
     *   "unmatched"  未匹配时的策略，default 或 reject；没写就是 default。
     *   "directory"  证书目录，见下面的解析。
     *
     * 字段类型和取值都必须合法，否则整份清单不生效。
     */

    value = json_object_get(root, "interval");

    if (value != NULL) {

        if (json_is_integer(value)) {

            n = json_integer_value(value);

            if (n < 0 || (json_int_t) (time_t) n != n) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "ssl_cert_registry: \"%V\": \"interval\" "
                              "must be a non-negative number of seconds",
                              &reg->path);
                goto failed;
            }

            t->interval = (time_t) n;

        } else if (json_is_string(value)) {

            s = json_string_value(value);

            tv.len = ngx_strlen(s);
            tv.data = (u_char *) s;
            tt = ngx_parse_time(&tv, 1);

            if (tt == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "ssl_cert_registry: \"%V\": invalid "
                              "\"interval\" \"%s\"", &reg->path, s);
                goto failed;
            }

            t->interval = tt;

        } else {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ssl_cert_registry: \"%V\": \"interval\" must be "
                          "an integer or a time string such as \"5s\"",
                          &reg->path);
            goto failed;
        }

        t->interval_set = 1;
    }

    value = json_object_get(root, "unmatched");

    if (value != NULL) {

        s = json_string_value(value);

        if (s == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ssl_cert_registry: \"%V\": \"unmatched\" must be "
                          "\"default\" or \"reject\"", &reg->path);
            goto failed;
        }

        if (ngx_strcmp(s, "default") == 0) {
            t->unmatched = NGX_HTTP_SSL_CERT_UNMATCHED_DEFAULT;

        } else if (ngx_strcmp(s, "reject") == 0) {
            t->unmatched = NGX_HTTP_SSL_CERT_UNMATCHED_REJECT;

        } else {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ssl_cert_registry: \"%V\": \"unmatched\" must be "
                          "\"default\" or \"reject\", got \"%s\"",
                          &reg->path, s);
            goto failed;
        }

        t->unmatched_set = 1;
    }

    /* "directory"：证书目录，解析结果写进 t->dir */

    if (ngx_http_ssl_cert_registry_dir(reg, root, t, pool, log) != NGX_OK) {
        goto failed;
    }

    /*
     * "certificates"：可选，但和 "directory" 至少要有一个。
     * 只有 "directory" 时不建任何域名 key，握手时只走目录模式。
     */

    certs = json_object_get(root, "certificates");

    if (certs == NULL) {

        if (t->dir.len == 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ssl_cert_registry: \"%V\": \"certificates\" or "
                          "\"directory\" must be present", &reg->path);
            goto failed;
        }

        /* 用一个空数组顶替，下面的遍历自然什么都不做 */

        empty = json_array();
        if (empty == NULL) {
            goto failed;
        }

        certs = empty;

    } else if (!json_is_array(certs)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "ssl_cert_registry: \"%V\": \"certificates\" "
                      "must be an array", &reg->path);
        goto failed;
    }

    /* 4. 逐条处理；json_array_foreach 是 jansson 提供的遍历宏，i 是下标 */

    json_array_foreach(certs, i, item) {

        if (!json_is_object(item)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ssl_cert_registry: \"%V\": certificates[%uz] "
                          "must be an object", &reg->path, i);
            goto failed;
        }

        /* enabled：可选，必须是布尔值；false 时整条跳过 */

        enabled = json_object_get(item, "enabled");

        if (enabled != NULL && !json_is_boolean(enabled)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ssl_cert_registry: \"%V\": certificates[%uz]"
                          ".enabled must be true or false", &reg->path, i);
            goto failed;
        }

        if (enabled != NULL && json_is_false(enabled)) {
            continue;
        }

        /* isDefault：可选，必须是布尔值；最多一条为 true */

        isdef = json_object_get(item, "isDefault");

        if (isdef != NULL && !json_is_boolean(isdef)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ssl_cert_registry: \"%V\": certificates[%uz]"
                          ".isDefault must be true or false", &reg->path, i);
            goto failed;
        }

        is_default = (isdef != NULL && json_is_true(isdef));

        if (is_default && t->default_entry != NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ssl_cert_registry: \"%V\": certificates[%uz]: "
                          "more than one certificate has \"isDefault\": true",
                          &reg->path, i);
            goto failed;
        }

        /* cert / key：必填，转换成完整路径写进 crt / key 缓冲区 */

        if (ngx_http_ssl_cert_registry_path(reg, json_object_get(item, "cert"),
                                            crt, log, i, "cert")
            != NGX_OK)
        {
            goto failed;
        }

        if (ngx_http_ssl_cert_registry_path(reg, json_object_get(item, "key"),
                                            key, log, i, "key")
            != NGX_OK)
        {
            goto failed;
        }

        /* 只当默认证书用的条目可以不写 domains */

        domains = json_object_get(item, "domains");

        if (domains == NULL && is_default) {
            /* 没有域名，只作为默认证书 */

        } else if (!json_is_array(domains)
                   || (json_array_size(domains) == 0 && !is_default))
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ssl_cert_registry: \"%V\": certificates[%uz]"
                          ".domains must be a non-empty array",
                          &reg->path, i);
            goto failed;
        }

        /* 证书对象跟随 pool 一起释放 */

        /*
         * ngx_pool_cleanup_add 在 pool 上分配一块 entry 大小的内存（cln->data），
         * 并登记一个清理函数，pool 销毁时调用它释放 OpenSSL 对象。
         *
         * 先登记、再加载：即使加载到一半失败，已经读进来的对象也能被释放。
         */

        cln = ngx_pool_cleanup_add(pool, sizeof(ngx_http_ssl_cert_entry_t));
        if (cln == NULL) {
            goto failed;
        }

        e = cln->data;
        ngx_memzero(e, sizeof(ngx_http_ssl_cert_entry_t));
        cln->handler = ngx_http_ssl_cert_entry_cleanup;

        if (ngx_http_ssl_cert_entry_load(log, crt, key, e) != NGX_OK) {
            goto failed;
        }

        /* 记下路径，启动时检查 worker 能否读到要用 */

        e->cert_path = ngx_pnalloc(pool, ngx_strlen(crt) + 1);
        e->key_path = ngx_pnalloc(pool, ngx_strlen(key) + 1);

        if (e->cert_path == NULL || e->key_path == NULL) {
            goto failed;
        }

        ngx_cpystrn(e->cert_path, crt, NGX_MAX_PATH);
        ngx_cpystrn(e->key_path, key, NGX_MAX_PATH);

        ep = ngx_array_push(&t->entries);
        if (ep == NULL) {
            goto failed;
        }

        *ep = e;

        if (is_default) {
            t->default_entry = e;
        }

        /* 每个域名都作为一个 key 指向这张证书（domains 为 NULL 时不进循环） */

        json_array_foreach(domains, j, value) {

            s = json_string_value(value);

            /* 不是字符串，或者不是合法域名（允许 "*." 开头的通配符） */

            if (s == NULL
                || ngx_http_ssl_cert_normalize(s, norm, sizeof(norm), 1)
                   != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "ssl_cert_registry: \"%V\": certificates[%uz]"
                              ".domains[%uz] is not a valid domain name",
                              &reg->path, i, j);
                goto failed;
            }

            /*
             * key 的字符串放在 temp_pool 就够了：ngx_hash_init 会把 key
             * 复制进哈希表自己的内存
             */

            name.len = ngx_strlen(norm);
            name.data = ngx_pnalloc(temp_pool, name.len);
            if (name.data == NULL) {
                goto failed;
            }

            ngx_memcpy(name.data, norm, name.len);

            /*
             * 通配符 "*.example.com" 当作普通字符串 key 存进精确哈希表，
             * 查的时候自己拼 "*.上一级域名" 去查，从而只匹配一级子域名。
             * （nginx 自带的通配符哈希会匹配多级，不符合 TLS 的规则）
             *
             * NGX_HASH_READONLY_KEY：key 已经是小写，不需要 nginx 再转换
             */

            rc = ngx_hash_add_key(&ha, &name, e, NGX_HASH_READONLY_KEY);

            /* 重复的域名：保留第一次出现的，记一条警告 */

            if (rc == NGX_BUSY) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                              "ssl_cert_registry: \"%V\": duplicate domain "
                              "\"%V\", ignored", &reg->path, &name);
                continue;
            }

            if (rc != NGX_OK) {
                goto failed;
            }

            t->ndomains++;
        }
    }

    /*
     * 5. 生成哈希表
     *
     *   max_size     桶数量的上限；nginx 会从小往大尝试，直到所有 key 都放得下
     *   bucket_size  每个桶的字节数，必须放得下最长的 key（域名最长 253 字节），
     *                所以设成 512，并按 CPU 缓存行对齐
     */

    hinit.hash = &t->hash;
    hinit.key = ngx_hash_key;
    hinit.max_size = 65536;
    hinit.bucket_size = ngx_align(512, ngx_cacheline_size);
    hinit.name = "ssl_cert_registry_hash";
    hinit.pool = pool;
    hinit.temp_pool = temp_pool;

    if (ngx_hash_init(&hinit, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
        goto failed;
    }

    /* 6. 临时内存和 JSON 对象都不再需要 */

    if (empty) {
        json_decref(empty);
    }

    ngx_destroy_pool(temp_pool);
    json_decref(root);

    return t;

failed:

    if (empty) {
        json_decref(empty);
    }

    if (temp_pool) {
        ngx_destroy_pool(temp_pool);
    }

    /* 销毁 pool 时会调用各个 entry 的 cleanup，释放已经读进来的证书 */

    if (pool) {
        ngx_destroy_pool(pool);
    }

    /* jansson 用引用计数管理内存，释放根对象即释放整棵树 */

    json_decref(root);

    return NULL;
}


/* 取出清单里的 cert / key 路径，相对路径按清单文件所在目录解析 */

/*
 *   value   JSON 里的字段值
 *   buf     输出缓冲区，长度 NGX_MAX_PATH，结果以 '\0' 结尾
 *   index   第几条记录，field 是字段名，都只用于错误日志
 */

static ngx_int_t
ngx_http_ssl_cert_registry_path(ngx_http_ssl_cert_registry_t *reg,
    json_t *value, u_char *buf, ngx_log_t *log, size_t index, char *field)
{
    u_char      *p;
    size_t       len;
    const char  *s;

    /* 字段不存在或者不是字符串时，json_string_value 返回 NULL */

    s = json_string_value(value);

    if (s == NULL || *s == '\0') {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "ssl_cert_registry: \"%V\": certificates[%uz].%s "
                      "must be a non-empty string", &reg->path, index, field);
        return NGX_ERROR;
    }

    len = ngx_strlen(s);

    if (s[0] == '/') {

        /* 绝对路径：原样复制 */

        if (len >= NGX_MAX_PATH) {
            goto too_long;
        }

        p = ngx_cpymem(buf, s, len);

    } else {

        /* 相对路径：拼成 "<清单所在目录>/<相对路径>" */

        if (reg->dir.len + 1 + len >= NGX_MAX_PATH) {
            goto too_long;
        }

        p = ngx_cpymem(buf, reg->dir.data, reg->dir.len);
        *p++ = '/';
        p = ngx_cpymem(p, s, len);
    }

    *p = '\0';

    return NGX_OK;

too_long:

    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "ssl_cert_registry: \"%V\": certificates[%uz].%s "
                  "is too long", &reg->path, index, field);

    return NGX_ERROR;
}


/*
 * 顶层 "directory"：证书目录。相对路径按清单文件所在目录解析，
 * 结果存进 t->dir（表自己的内存池）。
 *
 * 字段不存在时不算错误（只说明这个 server 不启用目录模式）。
 */

static ngx_int_t
ngx_http_ssl_cert_registry_dir(ngx_http_ssl_cert_registry_t *reg, json_t *root,
    ngx_http_ssl_cert_table_t *t, ngx_pool_t *pool, ngx_log_t *log)
{
    u_char      *p;
    size_t       len;
    const char  *s;
    json_t      *value;

    value = json_object_get(root, "directory");

    if (value == NULL) {
        return NGX_OK;
    }

    s = json_string_value(value);

    if (s == NULL || *s == '\0') {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "ssl_cert_registry: \"%V\": \"directory\" must be a "
                      "non-empty string", &reg->path);
        return NGX_ERROR;
    }

    len = ngx_strlen(s);

    if (s[0] == '/') {

        /* 绝对路径 */

        if (len >= NGX_MAX_PATH) {
            goto too_long;
        }

        t->dir.data = ngx_pnalloc(pool, len + 1);
        if (t->dir.data == NULL) {
            return NGX_ERROR;
        }

        p = ngx_cpymem(t->dir.data, s, len);

    } else {

        /* 相对路径：<清单所在目录>/<相对路径> */

        if (reg->dir.len + 1 + len >= NGX_MAX_PATH) {
            goto too_long;
        }

        t->dir.data = ngx_pnalloc(pool, reg->dir.len + 1 + len + 1);
        if (t->dir.data == NULL) {
            return NGX_ERROR;
        }

        p = ngx_cpymem(t->dir.data, reg->dir.data, reg->dir.len);
        *p++ = '/';
        p = ngx_cpymem(p, s, len);
    }

    *p = '\0';
    t->dir.len = p - t->dir.data;

    return NGX_OK;

too_long:

    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "ssl_cert_registry: \"%V\": \"directory\" is too long",
                  &reg->path);

    return NGX_ERROR;
}


/* 查表：精确域名 -> "*.上一级域名" */

/*
 *   name   已经校验过的小写域名，以 '\0' 结尾
 *   返回   找到的证书；NULL 表示没有匹配
 *
 * 例：name = "www.example.com"
 *       先查 "www.example.com"，再查 "*.example.com"
 */

static ngx_http_ssl_cert_entry_t *
ngx_http_ssl_cert_registry_find(ngx_http_ssl_cert_table_t *t, u_char *name)
{
    u_char                     *dot;
    size_t                      len;
    ngx_http_ssl_cert_entry_t  *e;
    u_char                      wc[NGX_HTTP_SSL_CERT_MAX_NAME + 2];

    len = ngx_strlen(name);

    /*
     * ngx_hash_find 需要先算好 key 的哈希值，算法要和建表时一致
     * （建表时用的也是 ngx_hash_key）
     */

    e = ngx_hash_find(&t->hash, ngx_hash_key(name, len), name, len);
    if (e) {
        return e;
    }

    /*
     * 找第一个点，并要求它后面还有点：
     *   "www.example.com" -> ".example.com"  可以查 "*.example.com"
     *   "example.com"     -> ".com"          不查 "*.com"
     */

    dot = (u_char *) ngx_strchr(name, '.');

    if (dot == NULL || ngx_strchr(dot + 1, '.') == NULL) {
        return NULL;
    }

    /* 拼出 "*" + ".example.com"；ngx_cpymem 返回写入末尾，减去起点即长度 */

    wc[0] = '*';
    len = ngx_cpymem(wc + 1, dot, ngx_strlen(dot)) - wc;

    return ngx_hash_find(&t->hash, ngx_hash_key(wc, len), wc, len);
}


/* 读取 PEM 证书链和私钥，并检查两者是否匹配 */

/*
 *   crt   证书文件：第一个是叶子证书，后面可以跟任意多个中间证书
 *   key   私钥文件，不能有密码
 *   e     结果写到这里；出错时可能只填了一部分，由调用方的 cleanup 释放
 */

static ngx_int_t
ngx_http_ssl_cert_entry_load(ngx_log_t *log, u_char *crt, u_char *key,
    ngx_http_ssl_cert_entry_t *e)
{
    BIO     *bio;
    X509    *x509;
    u_long   n;

    /* BIO 是 OpenSSL 的 I/O 抽象，这里就是一个打开的文件 */

    bio = BIO_new_file((char *) crt, "r");
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ERR, log, 0,
                      "ssl_cert_registry: cannot open certificate \"%s\"",
                      crt);
        return NGX_ERROR;
    }

    /*
     * 第一个证书是叶子证书。_AUX 版本会同时读取证书附带的信任设置，
     * 和 nginx 读取 ssl_certificate 时的做法一致
     */

    e->cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (e->cert == NULL) {
        ngx_ssl_error(NGX_LOG_ERR, log, 0,
                      "ssl_cert_registry: cannot read certificate \"%s\"",
                      crt);
        BIO_free(bio);
        return NGX_ERROR;
    }

    e->chain = sk_X509_new_null();
    if (e->chain == NULL) {
        BIO_free(bio);
        return NGX_ERROR;
    }

    /* 之后的都是中间证书，一直读到文件结束 */

    for ( ;; ) {

        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);

        if (x509 == NULL) {

            /*
             * 读不到证书有两种情况：
             *   文件已经读完：错误队列里是 PEM_R_NO_START_LINE，正常结束
             *   文件内容有问题：其他错误，加载失败
             */

            n = ERR_peek_last_error();

            if (ERR_GET_LIB(n) == ERR_LIB_PEM
                && ERR_GET_REASON(n) == PEM_R_NO_START_LINE)
            {
                /* 文件读完了 */

                /* 清掉这条"错误"，免得之后被误报 */

                ERR_clear_error();
                break;
            }

            ngx_ssl_error(NGX_LOG_ERR, log, 0,
                          "ssl_cert_registry: cannot read certificate "
                          "chain \"%s\"", crt);
            BIO_free(bio);
            return NGX_ERROR;
        }

        if (sk_X509_push(e->chain, x509) == 0) {
            X509_free(x509);
            BIO_free(bio);
            return NGX_ERROR;
        }
    }

    BIO_free(bio);

    /* 读取私钥 */

    bio = BIO_new_file((char *) key, "r");
    if (bio == NULL) {
        ngx_ssl_error(NGX_LOG_ERR, log, 0,
                      "ssl_cert_registry: cannot open certificate key \"%s\"",
                      key);
        return NGX_ERROR;
    }

    /* 后两个参数是密码回调和回调参数，不支持带密码的私钥，都传 NULL */

    e->pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (e->pkey == NULL) {
        ngx_ssl_error(NGX_LOG_ERR, log, 0,
                      "ssl_cert_registry: cannot read certificate key \"%s\"",
                      key);
        return NGX_ERROR;
    }

    /* 证书里的公钥和私钥必须是一对 */

    if (X509_check_private_key(e->cert, e->pkey) != 1) {
        ngx_ssl_error(NGX_LOG_ERR, log, 0,
                      "ssl_cert_registry: certificate \"%s\" and key \"%s\" "
                      "do not match", crt, key);
        return NGX_ERROR;
    }

    /* 快到期 / 已过期只写警告，照常加载（启动时和每次重新加载时都会检查） */

    ngx_http_ssl_cert_check_expiry(log, e->cert, crt, "ssl_cert_registry");

    return NGX_OK;
}


/*
 * 内存池销毁时调用，释放一张证书的 OpenSSL 对象
 *
 * 这几个释放函数遇到 NULL 都会直接返回，所以加载到一半失败、
 * 部分字段还是 NULL 时也能安全调用。
 * 这里只是减少引用计数：仍在使用这张证书的连接持有自己的引用，不受影响。
 */

static void
ngx_http_ssl_cert_entry_cleanup(void *data)
{
    ngx_http_ssl_cert_entry_t  *e = data;

    X509_free(e->cert);
    sk_X509_pop_free(e->chain, X509_free);    /* 释放每个中间证书，再释放栈本身 */
    EVP_PKEY_free(e->pkey);
}
