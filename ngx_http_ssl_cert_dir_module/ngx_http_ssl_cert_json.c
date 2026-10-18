/*
 * ngx_http_ssl_cert_json.c
 *
 * 证书清单用的极简 JSON 解析器，不依赖任何外部库。
 *
 * 清单的结构是固定的，所以这里只实现需要的那部分 JSON。遇到不支持的写法直接报错，而不是勉强接受——写错的清单应该马上被发现，而不是产生奇怪的行为：
 *
 *   支持    对象、数组、字符串、非负整数、true / false
 *   不支持  小数、指数、负数、null、\uXXXX 转义
 *
 * 另外几条限制，同样是为了尽早发现写错的清单：
 *
 *   - 嵌套最多 8 层（清单实际只用到 4 层）；
 *   - 对象的成员名不能重复；
 *   - 顶层必须是对象；
 *   - 解析完之后文件末尾不能有多余内容。
 *
 * 内存：整棵树（包括文件内容缓冲区）都从调用方传入的内存池分配，跟着内存池一起释放，不需要单独释放。字符串已经解码并以 '\0' 结尾，可以直接当 C 字符串用。
 *
 * 出错时只写一条带行号的日志，然后返回 NULL，不做错误恢复——调用方保留旧的证书表继续用即可。
 *
 * 递归下降解析，文法：
 *
 *   value    := object | array | string | number | "true" | "false"
 *   object   := '{' [ member (',' member)* ] '}'
 *   member   := string ':' value
 *   array    := '[' [ value (',' value)* ] ']'
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_http_ssl_cert_json.h"


/* 嵌套层数上限：清单最多用到 4 层，留一些余量，同时挡住恶意的深嵌套 */

#define NGX_HTTP_SSL_CERT_JSON_MAX_DEPTH  8


/* 报错信息缓冲区的长度 */

#define NGX_HTTP_SSL_CERT_JSON_MSG_LEN  256


/*
 * 解析过程中的状态。data 指向文件内容，随 pos 往后走；line 只在跳过空白时更新（字符串里不允许出现换行）。
 */

typedef struct {
    u_char                    *data;
    size_t                     len;
    size_t                     pos;
    ngx_uint_t                 line;
    ngx_pool_t                *pool;
    ngx_log_t                 *log;
    u_char                     path[NGX_MAX_PATH];
} ngx_http_ssl_cert_json_parser_t;


/*
 * 一个节点的内部结构。
 *
 * 用联合体而不是把字段平铺，是因为清单可能有几万个节点（一张证书就是好几个），每个节点省下的几十字节是值得的。keys 只在对象里有意义。
 */

struct ngx_http_ssl_cert_json_s {
    ngx_uint_t                     type;

    union {
        ngx_str_t                  str;       /* STRING：已解码，'\0' 结尾 */
        int64_t                    num;       /* INT */
        ngx_uint_t                 boolean;   /* BOOL：1 或 0 */
        struct {
            ngx_array_t            elts;      /* ARRAY：ngx_http_ssl_cert_json_t * */
        } arr;
        struct {
            ngx_array_t            keys;      /* OBJECT：ngx_str_t */
            ngx_array_t            values;    /* OBJECT：ngx_http_ssl_cert_json_t * */
        } obj;
    } u;
};


static ngx_http_ssl_cert_json_t *ngx_http_ssl_cert_json_new(ngx_http_ssl_cert_json_parser_t *p, ngx_uint_t type);
static ngx_int_t ngx_http_ssl_cert_json_value(ngx_http_ssl_cert_json_parser_t *p, ngx_uint_t depth, ngx_http_ssl_cert_json_t **out);
static ngx_int_t ngx_http_ssl_cert_json_object(ngx_http_ssl_cert_json_parser_t *p, ngx_uint_t depth, ngx_http_ssl_cert_json_t **out);
static ngx_int_t ngx_http_ssl_cert_json_array_value(ngx_http_ssl_cert_json_parser_t *p, ngx_uint_t depth, ngx_http_ssl_cert_json_t **out);
static ngx_int_t ngx_http_ssl_cert_json_string_value(ngx_http_ssl_cert_json_parser_t *p, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_cert_json_number(ngx_http_ssl_cert_json_parser_t *p, int64_t *out);
static void ngx_http_ssl_cert_json_skip_ws(ngx_http_ssl_cert_json_parser_t *p);
static ngx_int_t ngx_http_ssl_cert_json_error(ngx_http_ssl_cert_json_parser_t *p, const char *fmt, ...);


/* ---------------------------------------------------------------------- */
/* 给外部用的几个函数                                                     */
/* ---------------------------------------------------------------------- */

/*
 * 读文件并解析。
 *
 * 文件先整个读进内存池再解析：清单本来就不大，而且这样能一次性判断"文件读到一半被改了"（读到的字节数和 stat 得到的大小对不上）。
 */

ngx_http_ssl_cert_json_t *
ngx_http_ssl_cert_json_load(ngx_pool_t *pool, u_char *path, ngx_log_t *log)
{
    u_char                           *data;
    ssize_t                           n;
    size_t                            size;
    ngx_fd_t                          fd;
    ngx_file_t                        file;
    ngx_file_info_t                   fi;
    ngx_http_ssl_cert_json_t         *root;
    ngx_http_ssl_cert_json_parser_t   p;

    fd = ngx_open_file(path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "ssl_cert_registry: cannot open \"%s\"", path);
        return NULL;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "ssl_cert_registry: " ngx_fd_info_n " \"%s\" failed", path);
        ngx_close_file(fd);
        return NULL;
    }

    size = ngx_file_size(&fi);

    if (size == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ssl_cert_registry: \"%s\" is empty", path);
        ngx_close_file(fd);
        return NULL;
    }

    /* 多分配一个字节，读完之后补 '\0'，方便报错时按 C 字符串处理 */

    data = ngx_pnalloc(pool, size + 1);

    if (data == NULL) {
        ngx_close_file(fd);
        return NULL;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.fd = fd;
    file.name.data = path;
    file.name.len = ngx_strlen(path);
    file.log = log;

    n = ngx_read_file(&file, data, size, 0);

    ngx_close_file(fd);

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "ssl_cert_registry: cannot read \"%s\"", path);
        return NULL;
    }

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ssl_cert_registry: \"%s\" changed while reading (%O of %uz bytes)", path, (off_t) n, size);
        return NULL;
    }

    data[size] = '\0';

    ngx_memzero(&p, sizeof(ngx_http_ssl_cert_json_parser_t));

    p.data = data;
    p.len = size;
    p.line = 1;
    p.pool = pool;
    p.log = log;

    ngx_cpystrn(p.path, path, sizeof(p.path));

    if (ngx_http_ssl_cert_json_value(&p, 1, &root) != NGX_OK) {
        return NULL;
    }

    /* 值后面只允许有空白 */

    ngx_http_ssl_cert_json_skip_ws(&p);

    if (p.pos < p.len) {
        ngx_http_ssl_cert_json_error(&p, "trailing data after the top-level value");
        return NULL;
    }

    if (root->type != NGX_HTTP_SSL_CERT_JSON_OBJECT) {
        ngx_http_ssl_cert_json_error(&p, "the top-level value must be an object");
        return NULL;
    }

    return root;
}


/* 建一个空数组，用来顶替清单里没写的可选数组字段 */

ngx_http_ssl_cert_json_t *
ngx_http_ssl_cert_json_array(ngx_pool_t *pool)
{
    ngx_http_ssl_cert_json_t  *node;

    node = ngx_pcalloc(pool, sizeof(ngx_http_ssl_cert_json_t));

    if (node == NULL) {
        return NULL;
    }

    node->type = NGX_HTTP_SSL_CERT_JSON_ARRAY;

    if (ngx_array_init(&node->u.arr.elts, pool, 1, sizeof(ngx_http_ssl_cert_json_t *)) != NGX_OK) {
        return NULL;
    }

    return node;
}


/*
 * 取对象的成员。对象的成员不多（最多 5 个），直接线性查找；元素少的时候，这比哈希表更快也更好懂。
 */

ngx_http_ssl_cert_json_t *
ngx_http_ssl_cert_json_get(ngx_http_ssl_cert_json_t *obj, const char *key)
{
    size_t                      i, len;
    ngx_str_t                  *keys;
    ngx_http_ssl_cert_json_t  **values;

    if (obj == NULL || obj->type != NGX_HTTP_SSL_CERT_JSON_OBJECT) {
        return NULL;
    }

    len = ngx_strlen(key);
    keys = obj->u.obj.keys.elts;
    values = obj->u.obj.values.elts;

    for (i = 0; i < obj->u.obj.keys.nelts; i++) {

        if (keys[i].len == len && ngx_strncmp(keys[i].data, key, len) == 0) {
            return values[i];
        }
    }

    return NULL;
}


ngx_uint_t
ngx_http_ssl_cert_json_is(ngx_http_ssl_cert_json_t *value, ngx_http_ssl_cert_json_type_e type)
{
    return (value != NULL && value->type == (ngx_uint_t) type);
}


ngx_str_t *
ngx_http_ssl_cert_json_string(ngx_http_ssl_cert_json_t *value)
{
    if (!ngx_http_ssl_cert_json_is(value, NGX_HTTP_SSL_CERT_JSON_STRING)) {
        return NULL;
    }

    return &value->u.str;
}


ngx_int_t
ngx_http_ssl_cert_json_int(ngx_http_ssl_cert_json_t *value, int64_t *out)
{
    if (!ngx_http_ssl_cert_json_is(value, NGX_HTTP_SSL_CERT_JSON_INT)) {
        return NGX_ERROR;
    }

    *out = value->u.num;

    return NGX_OK;
}


ngx_int_t
ngx_http_ssl_cert_json_bool(ngx_http_ssl_cert_json_t *value, ngx_uint_t *out)
{
    if (!ngx_http_ssl_cert_json_is(value, NGX_HTTP_SSL_CERT_JSON_BOOL)) {
        return NGX_ERROR;
    }

    *out = value->u.boolean;

    return NGX_OK;
}


size_t
ngx_http_ssl_cert_json_size(ngx_http_ssl_cert_json_t *value)
{
    if (!ngx_http_ssl_cert_json_is(value, NGX_HTTP_SSL_CERT_JSON_ARRAY)) {
        return 0;
    }

    return value->u.arr.elts.nelts;
}


ngx_http_ssl_cert_json_t *
ngx_http_ssl_cert_json_at(ngx_http_ssl_cert_json_t *value, size_t index)
{
    ngx_http_ssl_cert_json_t  **elts;

    if (!ngx_http_ssl_cert_json_is(value, NGX_HTTP_SSL_CERT_JSON_ARRAY) || index >= value->u.arr.elts.nelts) {
        return NULL;
    }

    elts = value->u.arr.elts.elts;

    return elts[index];
}


/* ---------------------------------------------------------------------- */
/* 解析                                                                   */
/* ---------------------------------------------------------------------- */

/*
 * 报告错误：写一条带行号的日志并返回 NGX_ERROR，调用方直接往上返回即可。只在第一个错误处停下，不做错误恢复。
 */

static ngx_int_t
ngx_http_ssl_cert_json_error(ngx_http_ssl_cert_json_parser_t *p, const char *fmt, ...)
{
    u_char   *last, *end;
    va_list   args;
    u_char    msg[NGX_HTTP_SSL_CERT_JSON_MSG_LEN];

    /* ngx_vslprintf 最多写到 last，返回实际写完的位置 */

    last = msg + sizeof(msg) - 1;

    va_start(args, fmt);
    end = ngx_vslprintf(msg, last, fmt, args);
    va_end(args);

    if (end > last) {
        end = last;
    }

    /* 必须在实际结尾补 '\0'，否则日志会带出缓冲区后面的内容 */

    *end = '\0';

    ngx_log_error(NGX_LOG_ERR, p->log, 0, "ssl_cert_registry: \"%s\", line %ui: %s", p->path, p->line, msg);

    return NGX_ERROR;
}


/* 跳过空白；换行在这里计数，所以行号总是当前解析位置的 */

static void
ngx_http_ssl_cert_json_skip_ws(ngx_http_ssl_cert_json_parser_t *p)
{
    u_char  ch;

    while (p->pos < p->len) {

        ch = p->data[p->pos];

        if (ch == '\n') {
            p->line++;
            p->pos++;
            continue;
        }

        if (ch == ' ' || ch == '\t' || ch == '\r') {
            p->pos++;
            continue;
        }

        break;
    }
}


/* 从内存池分配一个节点并填好类型 */

static ngx_http_ssl_cert_json_t *
ngx_http_ssl_cert_json_new(ngx_http_ssl_cert_json_parser_t *p, ngx_uint_t type)
{
    ngx_http_ssl_cert_json_t  *node;

    node = ngx_pcalloc(p->pool, sizeof(ngx_http_ssl_cert_json_t));

    if (node == NULL) {
        return NULL;
    }

    node->type = type;

    return node;
}


/*
 * 解析一个值。depth 是当前的嵌套层数，从 1（顶层）开始。
 *
 * 这里决定支持哪些字面量：只认 true 和 false，null 直接报错。
 */

static ngx_int_t
ngx_http_ssl_cert_json_value(ngx_http_ssl_cert_json_parser_t *p, ngx_uint_t depth, ngx_http_ssl_cert_json_t **out)
{
    u_char                     ch;
    ngx_http_ssl_cert_json_t  *node;

    ngx_http_ssl_cert_json_skip_ws(p);

    if (p->pos >= p->len) {
        return ngx_http_ssl_cert_json_error(p, "unexpected end of file");
    }

    if (depth > NGX_HTTP_SSL_CERT_JSON_MAX_DEPTH) {
        return ngx_http_ssl_cert_json_error(p, "too many nested levels (max %d)", NGX_HTTP_SSL_CERT_JSON_MAX_DEPTH);
    }

    ch = p->data[p->pos];

    switch (ch) {

    case '{':
        return ngx_http_ssl_cert_json_object(p, depth, out);

    case '[':
        return ngx_http_ssl_cert_json_array_value(p, depth, out);

    case '"':
        node = ngx_http_ssl_cert_json_new(p, NGX_HTTP_SSL_CERT_JSON_STRING);

        if (node == NULL) {
            return NGX_ERROR;
        }

        if (ngx_http_ssl_cert_json_string_value(p, &node->u.str) != NGX_OK) {
            return NGX_ERROR;
        }

        *out = node;

        return NGX_OK;

    case 't':

        if (p->len - p->pos < 4 || ngx_strncmp(p->data + p->pos, "true", 4) != 0) {
            break;
        }

        p->pos += 4;

        node = ngx_http_ssl_cert_json_new(p, NGX_HTTP_SSL_CERT_JSON_BOOL);

        if (node == NULL) {
            return NGX_ERROR;
        }

        node->u.boolean = 1;
        *out = node;

        return NGX_OK;

    case 'f':

        if (p->len - p->pos < 5 || ngx_strncmp(p->data + p->pos, "false", 5) != 0) {
            break;
        }

        p->pos += 5;

        node = ngx_http_ssl_cert_json_new(p, NGX_HTTP_SSL_CERT_JSON_BOOL);

        if (node == NULL) {
            return NGX_ERROR;
        }

        node->u.boolean = 0;
        *out = node;

        return NGX_OK;

    case 'n':
        return ngx_http_ssl_cert_json_error(p, "\"null\" is not supported");

    default:
        break;
    }

    if (ch == '-' || (ch >= '0' && ch <= '9')) {

        if (ch == '-') {
            return ngx_http_ssl_cert_json_error(p, "negative numbers are not supported");
        }

        node = ngx_http_ssl_cert_json_new(p, NGX_HTTP_SSL_CERT_JSON_INT);

        if (node == NULL) {
            return NGX_ERROR;
        }

        if (ngx_http_ssl_cert_json_number(p, &node->u.num) != NGX_OK) {
            return NGX_ERROR;
        }

        *out = node;

        return NGX_OK;
    }

    /* 不认识的字符：控制字符、非 ASCII 字节显示成 '?'，免得把不可打印的内容写进日志 */

    if (ch < 0x20 || ch >= 0x7f) {
        ch = '?';
    }

    return ngx_http_ssl_cert_json_error(p, "unexpected character '%c'", ch);
}


/* 对象：{ "名字": 值, ... } */

static ngx_int_t
ngx_http_ssl_cert_json_object(ngx_http_ssl_cert_json_parser_t *p, ngx_uint_t depth, ngx_http_ssl_cert_json_t **out)
{
    size_t                      i;
    ngx_str_t                   key, *keys;
    ngx_http_ssl_cert_json_t   *node, *value;
    ngx_http_ssl_cert_json_t  **values;

    node = ngx_http_ssl_cert_json_new(p, NGX_HTTP_SSL_CERT_JSON_OBJECT);

    if (node == NULL) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&node->u.obj.keys, p->pool, 4, sizeof(ngx_str_t)) != NGX_OK
        || ngx_array_init(&node->u.obj.values, p->pool, 4, sizeof(ngx_http_ssl_cert_json_t *)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    p->pos++;                     /* 跳过 '{' */

    ngx_http_ssl_cert_json_skip_ws(p);

    /* 空对象 */

    if (p->pos < p->len && p->data[p->pos] == '}') {
        p->pos++;
        *out = node;
        return NGX_OK;
    }

    for ( ;; ) {

        ngx_http_ssl_cert_json_skip_ws(p);

        if (p->pos >= p->len || p->data[p->pos] != '"') {
            return ngx_http_ssl_cert_json_error(p, "expecting a member name (a string)");
        }

        if (ngx_http_ssl_cert_json_string_value(p, &key) != NGX_OK) {
            return NGX_ERROR;
        }

        /* 成员名重复：多半是写清单时改了一半，报错比取其中一个安全 */

        keys = node->u.obj.keys.elts;

        for (i = 0; i < node->u.obj.keys.nelts; i++) {

            if (keys[i].len == key.len && ngx_strncmp(keys[i].data, key.data, key.len) == 0) {
                return ngx_http_ssl_cert_json_error(p, "duplicate member \"%V\"", &key);
            }
        }

        ngx_http_ssl_cert_json_skip_ws(p);

        if (p->pos >= p->len || p->data[p->pos] != ':') {
            return ngx_http_ssl_cert_json_error(p, "expecting ':' after the member name");
        }

        p->pos++;

        if (ngx_http_ssl_cert_json_value(p, depth + 1, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        keys = ngx_array_push(&node->u.obj.keys);

        if (keys == NULL) {
            return NGX_ERROR;
        }

        *keys = key;

        values = ngx_array_push(&node->u.obj.values);

        if (values == NULL) {
            return NGX_ERROR;
        }

        *values = value;

        ngx_http_ssl_cert_json_skip_ws(p);

        if (p->pos >= p->len) {
            return ngx_http_ssl_cert_json_error(p, "the object is not terminated (expecting '}')");
        }

        if (p->data[p->pos] == ',') {
            p->pos++;
            continue;
        }

        if (p->data[p->pos] == '}') {
            p->pos++;
            break;
        }

        return ngx_http_ssl_cert_json_error(p, "expecting ',' or '}'");
    }

    *out = node;

    return NGX_OK;
}


/* 数组：[ 值, ... ] */

static ngx_int_t
ngx_http_ssl_cert_json_array_value(ngx_http_ssl_cert_json_parser_t *p, ngx_uint_t depth, ngx_http_ssl_cert_json_t **out)
{
    ngx_http_ssl_cert_json_t   *node, *value;
    ngx_http_ssl_cert_json_t  **elts;

    node = ngx_http_ssl_cert_json_new(p, NGX_HTTP_SSL_CERT_JSON_ARRAY);

    if (node == NULL) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&node->u.arr.elts, p->pool, 4, sizeof(ngx_http_ssl_cert_json_t *)) != NGX_OK) {
        return NGX_ERROR;
    }

    p->pos++;                     /* 跳过 '[' */

    ngx_http_ssl_cert_json_skip_ws(p);

    /* 空数组 */

    if (p->pos < p->len && p->data[p->pos] == ']') {
        p->pos++;
        *out = node;
        return NGX_OK;
    }

    for ( ;; ) {

        if (ngx_http_ssl_cert_json_value(p, depth + 1, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        elts = ngx_array_push(&node->u.arr.elts);

        if (elts == NULL) {
            return NGX_ERROR;
        }

        *elts = value;

        ngx_http_ssl_cert_json_skip_ws(p);

        if (p->pos >= p->len) {
            return ngx_http_ssl_cert_json_error(p, "the array is not terminated (expecting ']')");
        }

        if (p->data[p->pos] == ',') {
            p->pos++;
            continue;
        }

        if (p->data[p->pos] == ']') {
            p->pos++;
            break;
        }

        return ngx_http_ssl_cert_json_error(p, "expecting ',' or ']'");
    }

    *out = node;

    return NGX_OK;
}


/*
 * 字符串：从 '"' 开始（当前位置就是引号）。
 *
 * 分两遍：先扫一遍确认合法并算出解码后的长度，再分配、解码。这样不用为了"万一要转义"而多分配内存，转义分支也只在真的出现时才走。
 *
 * 只支持 JSON 里常用的那几个转义；\uXXXX 报错，让用户直接写 UTF-8 字符——清单里的域名和路径都是 ASCII，用不到 Unicode 转义。
 */

static ngx_int_t
ngx_http_ssl_cert_json_string_value(ngx_http_ssl_cert_json_parser_t *p, ngx_str_t *out)
{
    u_char     *dst, ch, c;
    size_t      i, n;
    ngx_uint_t  escaped;

    /* 当前位置必须是开引号 */

    if (p->pos >= p->len || p->data[p->pos] != '"') {
        return ngx_http_ssl_cert_json_error(p, "expecting a string");
    }

    p->pos++;

    n = 0;
    escaped = 0;

    for (i = p->pos; i < p->len; i++) {

        ch = p->data[i];

        if (ch == '"') {
            break;
        }

        if (ch == '\\') {

            if (i + 1 >= p->len) {
                break;
            }

            c = p->data[i + 1];

            switch (c) {
            case '"':
            case '\\':
            case '/':
            case 'b':
            case 'f':
            case 'n':
            case 'r':
            case 't':
                break;

            case 'u':
                return ngx_http_ssl_cert_json_error(p, "the escape \"\\u\" is not supported, write the character in UTF-8 directly");

            default:

                if (c < 0x20 || c >= 0x7f) {
                    c = '?';
                }

                return ngx_http_ssl_cert_json_error(p, "unknown escape \"\\%c\"", c);
            }

            escaped = 1;
            i++;                  /* 跳过被转义的字符 */
            n++;

            continue;
        }

        /* 裸的控制字符必须转义，直接写进来多半是文件坏了 */

        if (ch < 0x20) {
            return ngx_http_ssl_cert_json_error(p, "control character in the string (it must be escaped)");
        }

        n++;
    }

    if (i >= p->len) {
        return ngx_http_ssl_cert_json_error(p, "the string is not terminated (expecting '\"')");
    }

    /* i 停在结尾的引号上 */

    out->len = n;
    out->data = ngx_pnalloc(p->pool, n + 1);

    if (out->data == NULL) {
        return NGX_ERROR;
    }

    if (!escaped) {

        /* 没有转义：整段复制 */

        ngx_memcpy(out->data, p->data + p->pos, n);

    } else {

        dst = out->data;

        for (i = p->pos; i < p->len; i++) {

            ch = p->data[i];

            if (ch == '"') {
                break;
            }

            if (ch != '\\') {
                *dst++ = ch;
                continue;
            }

            i++;

            switch (p->data[i]) {
            case 'b':
                *dst++ = '\b';
                break;
            case 'f':
                *dst++ = '\f';
                break;
            case 'n':
                *dst++ = '\n';
                break;
            case 'r':
                *dst++ = '\r';
                break;
            case 't':
                *dst++ = '\t';
                break;
            default:
                /* " \ / 三个就是字符本身，上面已经校验过 */
                *dst++ = p->data[i];
                break;
            }
        }
    }

    out->data[n] = '\0';

    p->pos = i + 1;               /* 跳过结尾的引号 */

    return NGX_OK;
}


/*
 * 数字：只接受非负整数。
 *
 * 不支持负数、小数和指数——清单里只有 interval 一个数字，用不到这些；真写错了，报错比静默取整好。
 */

static ngx_int_t
ngx_http_ssl_cert_json_number(ngx_http_ssl_cert_json_parser_t *p, int64_t *out)
{
    u_char    ch;
    size_t    start;
    uint64_t  v, d;

    start = p->pos;
    v = 0;

    while (p->pos < p->len && p->data[p->pos] >= '0' && p->data[p->pos] <= '9') {

        d = p->data[p->pos] - '0';

        /* 溢出检查：先判断再乘 */

        if (v > (uint64_t) INT64_MAX / 10 || (v == (uint64_t) INT64_MAX / 10 && d > (uint64_t) INT64_MAX % 10)) {
            return ngx_http_ssl_cert_json_error(p, "the number is too large");
        }

        v = v * 10 + d;
        p->pos++;
    }

    if (p->pos == start) {
        return ngx_http_ssl_cert_json_error(p, "expecting a number");
    }

    /* 前导零：JSON 不允许，多半是笔误 */

    if (p->data[start] == '0' && p->pos - start > 1) {
        return ngx_http_ssl_cert_json_error(p, "leading zeros are not allowed");
    }

    /* 后面紧跟的字符不能是数字、字母或点，否则是 "1e3"、"12.5"、"123abc" */

    if (p->pos < p->len) {

        ch = p->data[p->pos];

        if (ch == '.' || ch == 'e' || ch == 'E') {
            return ngx_http_ssl_cert_json_error(p, "fractions and exponents are not supported");
        }

        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_') {
            return ngx_http_ssl_cert_json_error(p, "unexpected character '%c' after the number", ch);
        }
    }

    *out = (int64_t) v;

    return NGX_OK;
}
