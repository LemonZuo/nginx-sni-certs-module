/*
 * ngx_http_ssl_cert_json.h
 *
 * 证书清单用的极简 JSON 解析器接口，见 ngx_http_ssl_cert_json.c。
 *
 * 解析结果是一棵只读的树，节点全部从传入的内存池分配，跟着内存池一起释放。
 */

#ifndef _NGX_HTTP_SSL_CERT_JSON_H_INCLUDED_
#define _NGX_HTTP_SSL_CERT_JSON_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <stdint.h>


/* 节点类型；null 和负数等不支持的写法在解析阶段就被拒绝了 */

typedef enum {
    NGX_HTTP_SSL_CERT_JSON_BOOL = 1,
    NGX_HTTP_SSL_CERT_JSON_INT,
    NGX_HTTP_SSL_CERT_JSON_STRING,
    NGX_HTTP_SSL_CERT_JSON_ARRAY,
    NGX_HTTP_SSL_CERT_JSON_OBJECT
} ngx_http_ssl_cert_json_type_e;


/* 节点的内部结构只在本模块的 .c 里定义，外面只用下面这些函数 */

typedef struct ngx_http_ssl_cert_json_s  ngx_http_ssl_cert_json_t;


/* 读文件并解析，path 要以 '\0' 结尾。成功返回根节点（一定是对象）；失败返回 NULL，错误已经写进 log。 */
ngx_http_ssl_cert_json_t *ngx_http_ssl_cert_json_load(ngx_pool_t *pool, u_char *path, ngx_log_t *log);

/* 建一个空数组；用来顶替清单里没写的可选数组字段 */
ngx_http_ssl_cert_json_t *ngx_http_ssl_cert_json_array(ngx_pool_t *pool);

/* 取对象的成员；不是对象、或者成员不存在时返回 NULL */
ngx_http_ssl_cert_json_t *ngx_http_ssl_cert_json_get(ngx_http_ssl_cert_json_t *obj, const char *key);

/* 类型判断；value 为 NULL 时返回 0 */
ngx_uint_t ngx_http_ssl_cert_json_is(ngx_http_ssl_cert_json_t *value, ngx_http_ssl_cert_json_type_e type);

/* 取字符串：返回值指向内存池，已经解码并以 '\0' 结尾，可以直接当 C 字符串用；不是字符串时返回 NULL */
ngx_str_t *ngx_http_ssl_cert_json_string(ngx_http_ssl_cert_json_t *value);

/* 取整数；不是整数时返回 NGX_ERROR */
ngx_int_t ngx_http_ssl_cert_json_int(ngx_http_ssl_cert_json_t *value, int64_t *out);

/* 取布尔值，1 或 0；不是布尔时返回 NGX_ERROR */
ngx_int_t ngx_http_ssl_cert_json_bool(ngx_http_ssl_cert_json_t *value, ngx_uint_t *out);

/* 数组元素个数；不是数组时返回 0 */
size_t ngx_http_ssl_cert_json_size(ngx_http_ssl_cert_json_t *value);

/* 取数组第 index 个元素；越界或不是数组时返回 NULL */
ngx_http_ssl_cert_json_t *ngx_http_ssl_cert_json_at(ngx_http_ssl_cert_json_t *value, size_t index);


#endif /* _NGX_HTTP_SSL_CERT_JSON_H_INCLUDED_ */
