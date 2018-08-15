#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "apr_general.h"
#include "apr_strings.h"
#include "apr_strmatch.h"
#include "apr_lib.h"
#include "util_filter.h"
#include "http_request.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include <string.h>
#include <gpgme.h>
#include <locale.h>

#include "lib_crypto_proxy_bucket.h"
#include "lib_match.h"

#define DEFAULT_ENABLED 0
#define DEFAULT_INHERIT 1
#define HTML_CTYPE "text/html"
#define XHTML_CTYPE "application/xhtml+xml"
#define CSS_CTYPE "text/css"
#define JSON_CTYPE "application/json"
#define DEFAULT_CTYPES_LEN 3
#define CTYPES_LEN 16

module AP_MODULE_DECLARE_DATA crypto_proxy_module;
static const char crypto_proxy_rewrite_filter_name[] = "CRYPTO-PROXY-REWRITE";
static const char crypto_proxy_sign_filter_name[] = "CRYPTO-PROXY-SIGN";
static const char crypto_proxy_redirect_filter_name[] = "CRYPTO-PROXY-REDIRECT";
static const char *DEFAULT_JS_PATH = "/js/";
static const char *DEFAULT_PRIVATE_KEY = "";
static const char *DEFAULT_PASSPHRASE = "";
static const char *DEFAULT_GNUPG_ROOT_DIR = "";
static const char *DEFAULT_GNUPG_EXECUTABLE_PATH = "/usr/bin/gpg";
static const char *DEFAULT_HTTP_DOMAIN = "";
static const char *DEFAULT_HTTPS_DOMAIN = "";

int min(int a, int b) {
    return a > b ? b : a;
}

static void *create_crypto_proxy_dir_config(apr_pool_t *pool, char *dummy) {
    char *data = NULL;
    crypto_proxy_ctype_t *ctype;
    crypto_proxy_conf_t *rv = apr_pcalloc(pool, sizeof(*rv));
    if (!rv) {
	    goto last;
    }

    rv->enabled = -1;
    rv->inherit = -1;
    rv->default_html_ctypes = apr_array_make(pool, DEFAULT_CTYPES_LEN, sizeof(crypto_proxy_ctype_t));
    rv->default_css_ctypes = apr_array_make(pool, DEFAULT_CTYPES_LEN, sizeof(crypto_proxy_ctype_t));
    rv->default_json_ctypes = apr_array_make(pool, DEFAULT_CTYPES_LEN, sizeof(crypto_proxy_ctype_t));

    rv->default_enabled = DEFAULT_ENABLED;
    rv->default_inherit = DEFAULT_INHERIT;

    data = apr_pstrdup(pool, HTML_CTYPE);
    if (!data) {
	    return NULL;
    }
    else {
        ctype = apr_array_push(rv->default_html_ctypes);
        ctype->data = data;
    }

    data = apr_pstrdup(pool, XHTML_CTYPE);
    if (!data) {
	    return NULL;
    }
    else {
        ctype = apr_array_push(rv->default_html_ctypes);
        ctype->data = data;
    }

    data = apr_pstrdup(pool, CSS_CTYPE);
    if (!data) {
        return NULL;
    }
    else {
        ctype = apr_array_push(rv->default_css_ctypes);
        ctype->data = data;
    }

    data = apr_pstrdup(pool, JSON_CTYPE);
    if (!data) {
        return NULL;
    }
    else {
        ctype = apr_array_push(rv->default_json_ctypes);
        ctype->data = data;
    }

    data = apr_pstrdup(pool, DEFAULT_JS_PATH);
    if (!data) {
        return NULL;
    }
    else {
        rv->js_path = data;
    }

    data = apr_pstrdup(pool, DEFAULT_PRIVATE_KEY);
    if (!data) {
        return NULL;
    }
    else {
        rv->private_key = data;
    }

    data = apr_pstrdup(pool, DEFAULT_PASSPHRASE);
    if (!data) {
        return NULL;
    }
    else {
        rv->passphrase = data;
    }

    data = apr_pstrdup(pool, DEFAULT_GNUPG_ROOT_DIR);
    if (!data) {
        return NULL;
    }
    else {
        rv->gnupg_root_dir = data;
    }

    data = apr_pstrdup(pool, DEFAULT_GNUPG_EXECUTABLE_PATH);
    if (!data) {
        return NULL;
    }
    else {
        rv->gnupg_executable_path = data;
    }

    data = apr_pstrdup(pool, DEFAULT_HTTP_DOMAIN);
    if (!data) {
        return NULL;
    }
    else {
        rv->http_domain = data;
    }

    data = apr_pstrdup(pool, DEFAULT_HTTPS_DOMAIN);
    if (!data) {
        return NULL;
    }
    else {
        rv->https_domain = data;
    }
last:
    return (void *)rv;
}

static void *merge_crypto_proxy_dir_config(apr_pool_t *pool, void *BASE, void *ADD) {
    int i, j, skip;
    crypto_proxy_ctype_t *ctype;
    crypto_proxy_conf_t *base = (crypto_proxy_conf_t *)BASE;
    crypto_proxy_conf_t *add = (crypto_proxy_conf_t *)ADD;

    if (!base) {
	    return add;
    }

    crypto_proxy_conf_t *conf = (crypto_proxy_conf_t *)apr_palloc(pool, sizeof(crypto_proxy_conf_t));
    if (!conf) {
	    goto last;
    }

    conf->inherit = add->inherit;

    if (conf->inherit) {
        // -1 : unset
        // 0 : disabled
        // 1 : enabled
        if (add->enabled == -1 && base->enabled != -1) {
            conf->enabled = base->enabled;
        }
        else if (add->enabled != -1) {
            conf->enabled = add->enabled;
        }
        else {
            conf->enabled = add->default_enabled;
        }

        conf->default_html_ctypes = add->default_html_ctypes;
        conf->default_css_ctypes = add->default_css_ctypes;
        conf->default_json_ctypes = add->default_json_ctypes;

        if (strlen(add->js_path)) {
            conf->js_path = add->js_path;
        }
        else {
            conf->js_path = base->js_path;
        }

        if (strlen(add->private_key)) {
            conf->private_key = add->private_key;
        }
        else {
            conf->private_key = base->private_key;
        }

        if (strlen(add->passphrase)) {
            conf->passphrase = add->passphrase;
        }
        else {
            conf->passphrase = base->passphrase;
        }


        if (strlen(add->gnupg_root_dir)) {
            conf->gnupg_root_dir = add->gnupg_root_dir;
        }
        else {
            conf->gnupg_root_dir = base->gnupg_root_dir;
        }

        if (strlen(add->gnupg_executable_path)) {
            conf->gnupg_executable_path = add->gnupg_executable_path;
        }
        else {
            conf->gnupg_executable_path = base->gnupg_executable_path;
        }

        if (strlen(add->http_domain)) {
            conf->http_domain = add->http_domain;
        }
        else {
            conf->http_domain = base->http_domain;
        }

        if (strlen(add->https_domain)) {
            conf->https_domain = add->https_domain;
        }
        else {
            conf->https_domain = base->https_domain;
        }
    }
    else {
        conf->enabled = add->enabled != -1 ? add->enabled : add->default_enabled;
        conf->default_html_ctypes = add->default_html_ctypes;
        conf->default_css_ctypes = add->default_css_ctypes;
        conf->default_json_ctypes = add->default_json_ctypes;
        conf->js_path = add->js_path;
        conf->private_key = add->private_key;
        conf->passphrase = add->passphrase;
        conf->gnupg_root_dir = add->gnupg_root_dir;
        conf->gnupg_executable_path = add->gnupg_executable_path;
        conf->http_domain = add->http_domain;
        conf->https_domain = add->https_domain;
    }
last:
    return (void *)conf;
}

static int is_this_html(request_rec *r) {
    int i = 0;
    const char *ctype_line_val = apr_table_get(r->headers_out, "Content-Type");

    if (!ctype_line_val) {
        if (r->content_type) {
            ctype_line_val = apr_pstrdup(r->pool, r->content_type);
        }
        else {
            return 0;
        }
    }

    const char *ctype = ap_getword(r->pool, &ctype_line_val, ';');
    if (!ctype) {
	    return 0;
    }

    crypto_proxy_conf_t *cfg = ap_get_module_config(r->per_dir_config, &crypto_proxy_module);

    if (!cfg) {
	    return 0;
    }

    for (i = 0; i < cfg->default_html_ctypes->nelts; i++) {
        if (apr_strnatcasecmp((((crypto_proxy_ctype_t *)(cfg->default_html_ctypes->elts))[i]).data, ctype) == 0) {
            return 1;
        }
    }

    return 0;
}

static int is_this_json(request_rec *r) {
    int i = 0;
    const char *ctype_line_val = apr_table_get(r->headers_out, "Content-Type");

    if (!ctype_line_val) {
        if (r->content_type) {
            ctype_line_val = apr_pstrdup(r->pool, r->content_type);
        }
        else {
            return 0;
        }
    }

    const char *ctype = ap_getword(r->pool, &ctype_line_val, ';');
    if (!ctype) {
        return 0;
    }

    crypto_proxy_conf_t *cfg = ap_get_module_config(r->per_dir_config, &crypto_proxy_module);

    if (!cfg) {
        return 0;
    }

    for (i = 0; i < cfg->default_json_ctypes->nelts; i++) {
        if (apr_strnatcasecmp((((crypto_proxy_ctype_t *)(cfg->default_json_ctypes->elts))[i]).data, ctype) == 0) {
            return 1;
        }
    }

    return 0;
}

static int is_this_css(request_rec *r) {
    int i = 0;
    const char *ctype_line_val = apr_table_get(r->headers_out, "Content-Type");

    if (!ctype_line_val) {
        if (r->content_type) {
            ctype_line_val = apr_pstrdup(r->pool, r->content_type);
        }
        else {
            return 0;
        }
    }

    const char *ctype = ap_getword(r->pool, &ctype_line_val, ';');
    if (!ctype) {
        return 0;
    }

    crypto_proxy_conf_t *cfg = ap_get_module_config(r->per_dir_config, &crypto_proxy_module);

    if (!cfg) {
        return 0;
    }

    for (i = 0; i < cfg->default_css_ctypes->nelts; i++) {
        if (apr_strnatcasecmp((((crypto_proxy_ctype_t *)(cfg->default_css_ctypes->elts))[i]).data, ctype) == 0) {
            return 1;
        }
    }

    return 0;
}

unsigned int extract_url_params(ap_filter_t *f) {
    unsigned int result = 0;
    char *params_begin_pos = strchr(f->r->unparsed_uri, '?');
    char *end_of_uri = f->r->unparsed_uri + strlen(f->r->unparsed_uri);
    if (params_begin_pos) {
        char *last_delim_ptr = params_begin_pos;
        char *delim_ptr = NULL;
        while (last_delim_ptr) {
            delim_ptr = strchr(last_delim_ptr + 1, '&');

            char attr[(delim_ptr ? delim_ptr : end_of_uri) - last_delim_ptr];
            attr[(delim_ptr ? delim_ptr : end_of_uri) - last_delim_ptr - 1] = 0;
            memcpy(attr, last_delim_ptr + 1, (delim_ptr ? delim_ptr : end_of_uri) - last_delim_ptr - 1);

            int equal_sign_ptr = 0;
            int found = 0;
            for (equal_sign_ptr = 0; equal_sign_ptr < sizeof(attr) / sizeof(attr[0]) - 1; ++equal_sign_ptr) {
                if (attr[equal_sign_ptr] == '=') {
                    found = 1;
                    break;
                }
            }

            if (found) {
                char key[equal_sign_ptr + 1];
                key[equal_sign_ptr] = 0;
                char value[sizeof(attr) / sizeof(attr[0]) - equal_sign_ptr - 1];
                value[sizeof(attr) / sizeof(attr[0]) - equal_sign_ptr - 2] = 0;
                memcpy(key, attr, equal_sign_ptr);
                memcpy(value, attr + equal_sign_ptr + 1, sizeof(attr) / sizeof(attr[0]) - equal_sign_ptr - 2);

                int key_length = sizeof(key) / sizeof(key[0]);
                int value_length = sizeof(value) / sizeof(value[0]);
                if (key_length > 12) {
                    if (tolower(key[0]) == 'c' && tolower(key[1]) == 'r' && tolower(key[2]) == 'y' &&
                        tolower(key[3]) == 'p' && tolower(key[4]) == 't' && tolower(key[5]) == 'o' &&
                        tolower(key[6]) == 'p' && tolower(key[7]) == 'r' && tolower(key[8]) == 'o' &&
                        tolower(key[9]) == 'x' && tolower(key[10]) == 'y') {
                        int value_num = 0;
                        if (!strcasecmp(value, "1")) {
                            value_num = 1;
                        }
                        if (!strcasecmp(key + 11, "rewritedisabled")) {
                            result |= value_num << 0;
                        }
                        else if (!strcasecmp(key + 11, "encrypted")) {
                            result |= value_num << 1;
                        }
                        else if (!strcasecmp(key + 11, "redirected")) {
                            result |= value_num << 2;
                        }
                    }
                }
            }
            last_delim_ptr = delim_ptr;
        }
    }
    return result;
}

static apr_status_t crypto_proxy_rewrite_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
    apr_status_t rv = APR_SUCCESS;
    crypto_proxy_conf_t *cfg;
    crypto_proxy_module_ctx_t *ctx = f->ctx;
    if (APR_BRIGADE_EMPTY(bb)) {
	    return APR_SUCCESS;
    }

    unsigned int flags = extract_url_params(f);
    if (flags & 1) {
        goto last;
    }

    cfg = ap_get_module_config(f->r->per_dir_config, &crypto_proxy_module);
    if (!cfg) {
	    goto last;
    }
    if (!cfg->enabled) {
	    goto last;
    }
    if (!ctx) {
	    f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        if (!ctx) {
            goto last;
        }
        ctx->times = 1;
        ctx->crypto_proxy_bucket = apr_pcalloc(f->r->pool, sizeof(crypto_proxy_bucket_t));
        if (!ctx->crypto_proxy_bucket) {
            goto last;
        }
        apr_table_unset(f->r->headers_out, "Content-Length");
    }
    else {
	    ctx->times++;
        goto last;
    }
    if (is_this_html(f->r)) {
        rewrite_html_brigade(f, bb, cfg);
    }
    else if (is_this_css(f->r)) {
        rewrite_css_brigade(f, bb, cfg);
    }
last:
    rv = ap_pass_brigade(f->next, bb);
    return rv;
}

static apr_status_t crypto_proxy_redirect_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
    apr_status_t rv = APR_SUCCESS;
    crypto_proxy_conf_t *cfg;
    crypto_proxy_module_ctx_t *ctx = f->ctx;
    if (APR_BRIGADE_EMPTY(bb)) {
	    return APR_SUCCESS;
    }

    unsigned int flags = extract_url_params(f);
    if (!(flags & 4)) {
        goto last;
    }

    cfg = ap_get_module_config(f->r->per_dir_config, &crypto_proxy_module);
    if (!cfg) {
	    goto last;
    }
    if (!cfg->enabled) {
	    goto last;
    }
    if (!ctx) {
	    f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        if (!ctx) {
            goto last;
        }
        ctx->times = 1;
        ctx->crypto_proxy_bucket = apr_pcalloc(f->r->pool, sizeof(crypto_proxy_bucket_t));
        if (!ctx->crypto_proxy_bucket) {
            goto last;
        }
        apr_table_unset(f->r->headers_out, "Content-Length");
    }
    else {
	    ctx->times++;
        goto last;
    }

    if (!is_this_html(f->r) && !is_this_json(f->r)) {
        int http_domain_length = strlen(cfg->http_domain);
        int uri_length = strlen(f->r->unparsed_uri);
        char buffer[8 + http_domain_length + uri_length + 1];
        memcpy(buffer, "https://", 8);
        memcpy(buffer + 8, cfg->http_domain, http_domain_length);
        memcpy(buffer + 8 + http_domain_length, f->r->unparsed_uri, uri_length);
        buffer[8 + http_domain_length + uri_length] = 0;

        apr_bucket *b = APR_BRIGADE_FIRST(bb);
        while (b != APR_BRIGADE_SENTINEL(bb)) {
            get_crypto_proxy_bucket(f, b);
            apr_bucket *next_b = APR_BUCKET_NEXT(b);
            if (!APR_BUCKET_IS_METADATA(b)) {
                APR_BUCKET_REMOVE(b);
            }
            b = next_b;
        }

        apr_table_set(f->r->headers_out, "Location", buffer);
        f->r->status = 302;

    }
last:
    rv = ap_pass_brigade(f->next, bb);
    return rv;
}

typedef struct {
    ap_filter_t *f;
    apr_bucket_brigade *bb;
    int position;
} brigade_handle;

brigade_handle create_brigade_handle(ap_filter_t *f, apr_bucket_brigade *bb) {
    brigade_handle handle;
    handle.f = f;
    handle.bb = bb;
    handle.position = 0;
    return handle;
}

ssize_t read_bucket_brigade(void *handle, void *buffer, size_t size) {
    ap_filter_t *f = ((brigade_handle *)handle)->f;
    apr_bucket_brigade *bb = ((brigade_handle *)handle)->bb;
    int position = ((brigade_handle *)handle)->position;
    crypto_proxy_module_ctx_t *ctx = f->ctx;
    apr_bucket *b = APR_BRIGADE_FIRST(bb);
    int current_position = 0;
    unsigned char *buffer_ptr = buffer;
    ssize_t total_read_length = 0;

    while (b != APR_BRIGADE_SENTINEL(bb)) {
        get_crypto_proxy_bucket(f, b);
        if (!APR_BUCKET_IS_METADATA(b)) {
            if (current_position + ctx->crypto_proxy_bucket->len <= position) {
                current_position += ctx->crypto_proxy_bucket->len;
            }
            else {
                int begin_offset = (current_position < position) ? position - current_position : 0;
                int length = min(size - (buffer_ptr - (unsigned char *)buffer), ctx->crypto_proxy_bucket->len - begin_offset);
                memcpy(buffer_ptr, ctx->crypto_proxy_bucket->data + begin_offset, length);
                buffer_ptr += length;
                current_position += begin_offset + length;
                total_read_length += length;
                if (total_read_length >= size) {
                    break;
                }
            }
        }
        b = APR_BUCKET_NEXT(b);
    }

    ((brigade_handle *)handle)->position += total_read_length;
    return total_read_length;
}

ssize_t write_bucket_brigade(void *handle, const void *buffer, size_t size) {
    ap_filter_t *f = ((brigade_handle *)handle)->f;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "[ERROR] write_bucket_brigade() not implemented.");
    return -1;
}

off_t seek_bucket_brigade(void *handle, off_t offset, int whence) {
    if (whence == SEEK_SET) {
        return ((brigade_handle *)handle)->position = offset;
    }
    else if (whence == SEEK_CUR) {
        return ((brigade_handle *)handle)->position += offset;
    }
    else if (whence == SEEK_END) {
        ap_filter_t *f = ((brigade_handle *)handle)->f;
        apr_bucket_brigade *bb = ((brigade_handle *)handle)->bb;
        crypto_proxy_module_ctx_t *ctx = f->ctx;
        unsigned long total_size = 0;
        apr_bucket *b = APR_BRIGADE_FIRST(bb);
        while (b != APR_BRIGADE_SENTINEL(bb)) {
            get_crypto_proxy_bucket(f, b);
            if (!APR_BUCKET_IS_METADATA(b)) {
                total_size += ctx->crypto_proxy_bucket->len;
            }
        }
        return ((brigade_handle *)handle)->position = total_size + offset;
    }
}

void release_bucket_brigade(void *handle) {
    apr_bucket_brigade *bb = ((brigade_handle *)handle)->bb;
    apr_brigade_destroy(bb);
}

gpgme_error_t gpgme_passphrase_callback(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd) {
    ap_filter_t *f = ((brigade_handle *)hook)->f;
    crypto_proxy_conf_t *cfg = ap_get_module_config(f->r->per_dir_config, &crypto_proxy_module);
    if (!cfg) {
        return GPG_ERR_NO_ERROR;
    }
    unsigned int str_length = strlen(cfg->passphrase);
    char temp_str[str_length + 1];
    memcpy(temp_str, cfg->passphrase, str_length);
    temp_str[str_length] = '\n';
    gpgme_io_writen(fd, temp_str, str_length + 1);
    return GPG_ERR_NO_ERROR;
}

static apr_status_t crypto_proxy_sign_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
    apr_status_t rv = APR_SUCCESS;
    crypto_proxy_conf_t *cfg;
    crypto_proxy_module_ctx_t *ctx = f->ctx;
    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }

    unsigned int flags = extract_url_params(f);

    cfg = ap_get_module_config(f->r->per_dir_config, &crypto_proxy_module);
    if (!cfg) {
        rv = ap_pass_brigade(f->next, bb);
        return rv;
    }
    if (!cfg->enabled) {
        rv = ap_pass_brigade(f->next, bb);
        return rv;
    }
    if (!ctx) {
        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        if (!ctx) {
            rv = ap_pass_brigade(f->next, bb);
            return rv;
        }
        ctx->times = 1;
        ctx->crypto_proxy_bucket = apr_pcalloc(f->r->pool, sizeof(crypto_proxy_bucket_t));
        if (!ctx->crypto_proxy_bucket) {
            rv = ap_pass_brigade(f->next, bb);
            return rv;
        }
        apr_table_unset(f->r->headers_out, "Content-Length");
    }
    else {
        ctx->times++;
    }
    if (is_this_html(f->r)) {
        rv = ap_pass_brigade(f->next, bb);
        return rv;
    }

    apr_bucket *b = APR_BRIGADE_FIRST(bb);
    int count = 0;
    while (b != APR_BRIGADE_SENTINEL(bb)) {
        get_crypto_proxy_bucket(f, b);
        if (!APR_BUCKET_IS_METADATA(b)) {
            ++count;
        }
        b = APR_BUCKET_NEXT(b);
    }
    if (count == 0) {
        rv = ap_pass_brigade(f->next, bb);
        return rv;
    }

    brigade_handle handle = create_brigade_handle(f, bb);
    gpgme_ctx_t gpgme_ctx;
    gpgme_err_code_t gpgme_e = gpgme_err_code(gpgme_new(&gpgme_ctx));
    if (gpgme_e != GPG_ERR_NO_ERROR) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "[ERROR] Failed to initialize GnuPG");
        rv = ap_pass_brigade(f->next, bb);
        return rv;
    }

    gpgme_e = gpgme_err_code(gpgme_ctx_set_engine_info(gpgme_ctx, GPGME_PROTOCOL_OpenPGP, cfg->gnupg_executable_path, cfg->gnupg_root_dir));
    if (gpgme_e != GPG_ERR_NO_ERROR) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "[ERROR] Failed set GnuPG root directory.");
        rv = ap_pass_brigade(f->next, bb);
        return rv;
    }

    gpgme_e = gpgme_err_code(gpgme_set_pinentry_mode(gpgme_ctx, GPGME_PINENTRY_MODE_LOOPBACK));
    if (gpgme_e != GPG_ERR_NO_ERROR) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "[ERROR] Failed set GnuPG pinentry mode.");
        rv = ap_pass_brigade(f->next, bb);
        return rv;
    }
    gpgme_set_passphrase_cb(gpgme_ctx, gpgme_passphrase_callback, &handle);

    gpgme_key_t gpgme_key;
    gpgme_e = gpgme_err_code(gpgme_get_key(gpgme_ctx, cfg->private_key, &gpgme_key, 1));
    if (gpgme_e != GPG_ERR_NO_ERROR) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "[ERROR] Failed to get GnuPG private key");
        rv = ap_pass_brigade(f->next, bb);
        return rv;
    }

    if (!gpgme_key->can_sign) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "[ERROR] GnuPG private key cannot sign.");
    }

    gpgme_signers_add(gpgme_ctx, gpgme_key);

    gpgme_data_t gpgme_data;
    struct gpgme_data_cbs callbacks;
    callbacks.read = read_bucket_brigade;
    callbacks.write = write_bucket_brigade;
    callbacks.seek = seek_bucket_brigade;
    callbacks.release = release_bucket_brigade;
    gpgme_data_t content;
    gpgme_e = gpgme_err_code(gpgme_data_new_from_cbs(&content, &callbacks, &handle));
    if (gpgme_e != GPG_ERR_NO_ERROR) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "[ERROR] Failed to set up gpgme_data_t from APR bucket brigade.");
        rv = ap_pass_brigade(f->next, bb);
        return rv;
    }

    gpgme_data_t signature;
    gpgme_e = gpgme_err_code(gpgme_data_new(&signature));
    if (gpgme_e != GPG_ERR_NO_ERROR) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "[ERROR] Failed to create a gpgme_data_t to hold signature.");
        rv = ap_pass_brigade(f->next, bb);
        return rv;
    }

    gpgme_e = gpgme_err_code(gpgme_op_sign(gpgme_ctx, content, signature, GPGME_SIG_MODE_DETACH));
    if (gpgme_e != GPG_ERR_NO_ERROR) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "[ERROR] Failed to sign on content.");
        rv = ap_pass_brigade(f->next, bb);
        return rv;
    }


    off_t signature_size = gpgme_data_seek(signature, 0, SEEK_END);
    gpgme_data_seek(signature, 0, SEEK_SET);
    unsigned char signature_buffer[12 + signature_size];
    signature_buffer[0] = 251;
    signature_buffer[1] = 241;
    signature_buffer[2] = 239;
    signature_buffer[3] = 233;
    signature_buffer[4] = 229;
    signature_buffer[5] = 227;
    signature_buffer[6] = 223;
    signature_buffer[7] = 211;
    *(int *)(signature_buffer + 8) = signature_size;
    gpgme_data_read(signature, signature_buffer + 12, signature_size);

    apr_bucket *sig_bucket = apr_bucket_transient_create(signature_buffer, signature_size + 12, f->r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_HEAD(bb, sig_bucket);

    b = APR_BRIGADE_FIRST(bb);
    count = 0;
    while (b != APR_BRIGADE_SENTINEL(bb)) {
        get_crypto_proxy_bucket(f, b);
        if (!APR_BUCKET_IS_METADATA(b)) {
        }
        b = APR_BUCKET_NEXT(b);
    }

    rv = ap_pass_brigade(f->next, bb);
    return rv;
}

static const char *set_enabled(cmd_parms *cmd, void *mconfig, int on) {
    crypto_proxy_conf_t *cfg = mconfig;
    cfg->enabled = on;
    return NULL;
}

static const char *set_inherit(cmd_parms * cmd, void *mconfig, int on) {
    crypto_proxy_conf_t *cfg = mconfig;
    cfg->inherit = on;
    return NULL;
}

static const char *set_js_path(cmd_parms * cmd, void *mconfig, const char *js_path) {
    crypto_proxy_conf_t *cfg = mconfig;
    if (js_path) {
        cfg->js_path = apr_pstrdup(cmd->pool, js_path);
    }
    return NULL;
}

static const char *set_private_key(cmd_parms * cmd, void *mconfig, const char *private_key) {
    crypto_proxy_conf_t *cfg = mconfig;
    if (private_key) {
        cfg->private_key = apr_pstrdup(cmd->pool, private_key);
    }
    return NULL;
}

static const char *set_passphrase(cmd_parms * cmd, void *mconfig, const char *passphrase) {
    crypto_proxy_conf_t *cfg = mconfig;
    if (passphrase) {
        cfg->passphrase = apr_pstrdup(cmd->pool, passphrase);
    }
    return NULL;
}

static const char *set_gnupg_root_dir(cmd_parms * cmd, void *mconfig, const char *root_dir) {
    crypto_proxy_conf_t *cfg = mconfig;
    if (root_dir) {
        cfg->gnupg_root_dir = apr_pstrdup(cmd->pool, root_dir);
    }
    return NULL;
}

static const char *set_gnupg_executable_path(cmd_parms * cmd, void *mconfig, const char *executable_path) {
    crypto_proxy_conf_t *cfg = mconfig;
    if (executable_path) {
        cfg->gnupg_executable_path = apr_pstrdup(cmd->pool, executable_path);
    }
    return NULL;
}

static const char *set_http_domain(cmd_parms * cmd, void *mconfig, const char *http_domain) {
    crypto_proxy_conf_t *cfg = mconfig;
    if (http_domain) {
        cfg->http_domain = apr_pstrdup(cmd->pool, http_domain);
    }
    return NULL;
}

static const char *set_https_domain(cmd_parms * cmd, void *mconfig, const char *https_domain) {
    crypto_proxy_conf_t *cfg = mconfig;
    if (https_domain) {
        cfg->https_domain = apr_pstrdup(cmd->pool, https_domain);
    }
    return NULL;
}

static void crypto_proxy_initialize_gpgme(apr_pool_t *p, server_rec *s) {
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "crypto_proxy_initialize_gpgme: %s", s->path);
    setlocale(LC_ALL, "");
    gpgme_check_version(NULL);
    gpgme_set_locale(NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
}

static void register_hooks(apr_pool_t * pool) {
    ap_register_output_filter(crypto_proxy_rewrite_filter_name, crypto_proxy_rewrite_filter, NULL, AP_FTYPE_RESOURCE);
    ap_register_output_filter(crypto_proxy_sign_filter_name, crypto_proxy_sign_filter, NULL, AP_FTYPE_CONTENT_SET);
    ap_register_output_filter(crypto_proxy_redirect_filter_name, crypto_proxy_redirect_filter, NULL, AP_FTYPE_RESOURCE);
    ap_hook_child_init(crypto_proxy_initialize_gpgme, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec crypto_proxy_cmds[] = {
    AP_INIT_FLAG("CryptoProxyEnable",
                 set_enabled,
                 NULL,
                 RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
                 "Enable/Disable the output filter"),
    AP_INIT_FLAG("CryptoProxyInherit",
                 set_inherit,
                 NULL,
                 RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
                 "Inherit from server configuration"),
    AP_INIT_ITERATE("CryptoProxyJavaScriptPath",
                    set_js_path,
                    NULL,
                    RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
                    "Set the path of loader.js and its dependencies"),
    AP_INIT_ITERATE("CryptoProxyPrivateKey",
                    set_private_key,
                    NULL,
                    RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
                    "Set the private key to sign content."),
    AP_INIT_ITERATE("CryptoProxyPassphrase",
                    set_passphrase,
                    NULL,
                    RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
                    "Set the passphrase of the private key."),
    AP_INIT_ITERATE("CryptoProxyGnuPGRootDir",
                    set_gnupg_root_dir,
                    NULL,
                    RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
                    "Set the root directory of GnuPG."),
    AP_INIT_ITERATE("CryptoProxyGnuPGExecutablePath",
                    set_gnupg_executable_path,
                    NULL,
                    RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
                    "Set the path of GnuPG executable."),
    AP_INIT_ITERATE("CryptoProxyHttpDomain",
                    set_http_domain,
                    NULL,
                    RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
                    "Set the domain that communicates with backend via http."),
    AP_INIT_ITERATE("CryptoProxyHttpsDomain",
                    set_https_domain,
                    NULL,
                    RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
                    "Set the domain that communicates with backend via https."),
    {NULL}
};

module AP_MODULE_DECLARE_DATA crypto_proxy_module = {
    STANDARD20_MODULE_STUFF,
    create_crypto_proxy_dir_config,
    merge_crypto_proxy_dir_config,
    NULL,
    NULL,
    crypto_proxy_cmds, register_hooks
};
