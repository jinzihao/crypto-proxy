#ifndef LIB_CRYPTO_PROXY_BUCKET_H
#define LIB_CRYPTO_PROXY_BUCKET_H
#include "apr_buckets.h"

typedef struct {
    apr_size_t len;
    apr_size_t limit;
    const char *data;
    apr_bucket *b;
    apr_size_t body_end_tag_pos;
    apr_size_t html_end_tag_pos;
    apr_size_t html_start_tag_pos;
    apr_size_t head_start_tag_pos;
    apr_size_t body_start_tag_pos;
} crypto_proxy_bucket_t;

typedef struct {
    char *data;
} crypto_proxy_ctype_t;

typedef struct {
    int enabled;
    int inherit;
    int default_enabled;
    int default_inherit;
    apr_array_header_t *default_html_ctypes;
    apr_array_header_t *default_css_ctypes;
    apr_array_header_t *default_json_ctypes;
    char *html;
    char *js_path;
    char *private_key;
    char *passphrase;
    char *gnupg_root_dir;
    char *gnupg_executable_path;
    char *http_domain;
    char *https_domain;
} crypto_proxy_conf_t;

typedef struct {
    unsigned int times;
    crypto_proxy_bucket_t *crypto_proxy_bucket;
} crypto_proxy_module_ctx_t;

static crypto_proxy_bucket_t *get_crypto_proxy_bucket(ap_filter_t *f, apr_bucket *b) {
    const char *data;
    apr_size_t len = 0;
    crypto_proxy_module_ctx_t *ctx = f->ctx;
    crypto_proxy_bucket_t *rv = ctx->crypto_proxy_bucket;

    rv->len = 0;
    rv->data = NULL;
    rv->b = NULL;
    rv->body_end_tag_pos = rv->body_start_tag_pos = rv->html_start_tag_pos
            = rv->head_start_tag_pos = rv->body_start_tag_pos = -1;
    apr_bucket_read(b, &data, &len, APR_BLOCK_READ);

    rv->len = len;
    rv->data = data;
    rv->b = b;
    return rv;
}
#endif
