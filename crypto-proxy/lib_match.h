#ifndef LIB_MATCH_H
#define LIB_MATCH_H
#include <string.h>
#include "lib_crypto_proxy_bucket.h"
#include "uthash.h"

int is_letter(char c) {
    return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z';
}

int is_space(char c) {
    return c == ' ' || c == 13 || c == 10 || c == 9;
}

int ltrim(char *str) {
    unsigned int length = strlen(str);
    char *ptr = str;
    while (ptr - str < length && is_space(*ptr)) {
        ++ptr;
    }
    if (*ptr) {
        memmove(str, ptr, length - (ptr - str));
    }
}

typedef enum DOCUMENT_MODE {
    EXPECTING_HTML,
    EXPECTING_HEAD,
    EXPECTING_BODY,
    EXPECTING_NOTHING
} DOCUMENT_MODE;

typedef enum TAG_MODE {
    EXPECTING_LEFT_BRACKET,
    EXPECTING_TAG_TYPE,
    EXPECTING_ATTRIBUTE_TYPE,
    EXPECTING_ATTRIBUTE_TYPE_EQUAL,
    EXPECTING_ATTRIBUTE_VALUE_QUOTE,
    EXPECTING_ATTRIBUTE_VALUE,
    EXPECTING_CLOSE,
    EXPECTING_CLOSE_COMMENT
} TAG_MODE;

typedef enum QUOTATION_MODE {
    OUTSIDE,
    INSIDE_SINGLE,
    INSIDE_DOUBLE
} QUOTATION_MODE;

static const size_t TAG_TYPE_BUFFER_SIZE = 64;
#define ATTRIBUTE_TYPE_BUFFER_SIZE 64
#define ATTRIBUTE_VALUE_BUFFER_SIZE 1024

static const char* INSERTED_HTML_TEMPLATE_1 = "<script src=\"";
static const char* INSERTED_HTML_TEMPLATE_2 = "openpgp.min.js\"></script><script src=\"";
static const char* INSERTED_HTML_TEMPLATE_3 = "jquery.min.js\"></script><script src=\"";
static const char* INSERTED_HTML_TEMPLATE_4 = "loader.js\"></script><script>crypto_proxy_scripts = [];</script>";

static int script_count = 0;
static int img_count = 1;
static int inside_inline_script = 0;

char *generate_html_to_insert(ap_filter_t *f, crypto_proxy_conf_t *cfg) {
    char *html_to_insert = apr_palloc(f->r->pool, strlen(INSERTED_HTML_TEMPLATE_1) + strlen(INSERTED_HTML_TEMPLATE_2) +
            strlen(INSERTED_HTML_TEMPLATE_3) + strlen(INSERTED_HTML_TEMPLATE_4) + strlen(cfg->js_path) * 3 + 1);
    char *buffer = html_to_insert;

    strcpy(buffer, INSERTED_HTML_TEMPLATE_1);
    buffer += strlen(INSERTED_HTML_TEMPLATE_1);
    strcpy(buffer, cfg->js_path);
    buffer += strlen(cfg->js_path);
    strcpy(buffer, INSERTED_HTML_TEMPLATE_2);
    buffer += strlen(INSERTED_HTML_TEMPLATE_2);
    strcpy(buffer, cfg->js_path);
    buffer += strlen(cfg->js_path);
    strcpy(buffer, INSERTED_HTML_TEMPLATE_3);
    buffer += strlen(INSERTED_HTML_TEMPLATE_3);
    strcpy(buffer, cfg->js_path);
    buffer += strlen(cfg->js_path);
    strcpy(buffer, INSERTED_HTML_TEMPLATE_4);
    buffer += strlen(INSERTED_HTML_TEMPLATE_4);

    return html_to_insert;
}

void insert_after_head(ap_filter_t *f, apr_bucket_brigade *bb, apr_bucket **b, int *position,
                       crypto_proxy_conf_t *cfg) {
    crypto_proxy_module_ctx_t *ctx = f->ctx;
    apr_bucket_split(*b, *position + 1);

    char *html_to_insert = generate_html_to_insert(f, cfg);
    apr_bucket *str_bucket = apr_bucket_transient_create(html_to_insert, strlen(html_to_insert), f->r->connection->bucket_alloc);

    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_AFTER(*b, str_bucket);
    *b = APR_BUCKET_NEXT(str_bucket);
    get_crypto_proxy_bucket(f, *b);
    *position = 0;
}

void insert_before_anything(ap_filter_t *f, apr_bucket_brigade *bb, crypto_proxy_conf_t *cfg) {
    char *html_to_insert = generate_html_to_insert(f, cfg);
    apr_bucket *str_bucket = apr_bucket_transient_create(html_to_insert, strlen(html_to_insert), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(APR_BRIGADE_FIRST(bb), str_bucket);
}

typedef struct dict_t {
    char key[ATTRIBUTE_TYPE_BUFFER_SIZE + 1];
    char value[ATTRIBUTE_VALUE_BUFFER_SIZE + 1];
    UT_hash_handle hh;
} dict_t;

void replace_domain(char *str, char *domain, int type, ap_filter_t *f) {
    // 0: non-local resource
    // 1: local resource with an absolute path
    // 2: local resource with a relative path
    // 3: local resource with an explicit domain via http
    // 4: local resource with an explicit domain via https
    // 5: local resource with a protocol relative url and an explicit domain.
    // 6: javascript variable
    if (type == 0) {
        // Shouldn't use replace_domain when type == 0, just return.
        return;
    }
    else if (type == 1) {
        int str_length = strlen(str);
        char path[str_length];
        memcpy(path, str, str_length);
        memcpy(str, "https://", 8);
        int domain_length = strlen(domain);
        memcpy(str + 8, domain, domain_length);
        memcpy(str + 8 + domain_length, path, str_length);
    }
    else if (type == 2) {
        int uri_length = strlen(f->r->uri);
        char *uri_ptr;
        char *last_slash = f->r->uri;
        for (uri_ptr = f->r->uri; uri_ptr < f->r->uri + uri_length; ++uri_ptr) {
            if (*uri_ptr == '/') {
                last_slash = uri_ptr;
            }
        }
        int actual_path_length = last_slash - f->r->uri + 1;

        int str_length = strlen(str);
        char path[str_length];
        memcpy(path, str, str_length);
        memcpy(str, "https://", 8);
        int domain_length = strlen(domain);
        memcpy(str + 8, domain, domain_length);
        memcpy(str + 8 + domain_length, f->r->uri, actual_path_length);
        memcpy(str + 8 + domain_length + actual_path_length, path, str_length);
    }
    else if (type < 6){
        char *domain_begin_ptr;
        if (type == 3) {
            domain_begin_ptr = str + 7;
        }
        else if (type == 4) {
            domain_begin_ptr = str + 8;
        }
        else if (type == 5) {
            domain_begin_ptr = str + 2;
        }
        char *str_end_ptr = str + strlen(str);
        char *domain_end_ptr;
        for (domain_end_ptr = domain_begin_ptr; domain_end_ptr != str_end_ptr; ++domain_end_ptr) {
            if (*domain_end_ptr == '/') {
                break;
            }
        }
        int path_length = str_end_ptr - domain_end_ptr;
        char path[path_length];
        memcpy(path, domain_end_ptr, path_length);
        memcpy(str, "https://", 8);
        int domain_length = strlen(domain);
        memcpy(str + 8, domain, domain_length);
        memcpy(str + 8 + domain_length, path, path_length);
    }
    else {
        // type == 6
        return;
    }
}

void replace_script_tag(ap_filter_t *f, apr_bucket **b, char *s, dict_t **attr_dict, int sequence) {
    char *temp_str = "<script>loadScript(verify, ";
    apr_bucket *str_bucket = apr_bucket_transient_create(temp_str, strlen(temp_str), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);
    char *buf = apr_pstrdup(f->r->pool, s);
    str_bucket = apr_bucket_transient_create(buf, strlen(buf), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);
    temp_str = ", PUBLIC_KEY, ";
    str_bucket = apr_bucket_transient_create(temp_str, strlen(temp_str), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);

    char seq_buf[16];
    int length = sprintf(seq_buf, "%d", sequence);
    str_bucket = apr_bucket_transient_create(apr_pstrdup(f->r->pool, seq_buf), length, f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);

    temp_str = ");";
    str_bucket = apr_bucket_transient_create(temp_str, strlen(temp_str), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);
}

void replace_inline_script_tag(ap_filter_t *f, apr_bucket **b, dict_t **attr_dict, int sequence) {
    char *temp_str = "<script";
    apr_bucket *str_bucket = apr_bucket_transient_create(temp_str, strlen(temp_str), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);

    dict_t *current_attr, *tmp;
    HASH_ITER(hh, *attr_dict, current_attr, tmp) {
        int key_length = strlen(current_attr->key);
        int value_length = strlen(current_attr->value);

        char buf[key_length + 1 + value_length + 2];
        buf[0] = ' ';
        buf[key_length + 1] = '=';
        buf[key_length + 1 + value_length + 1] = 0;
        memcpy(buf + 1, current_attr->key, key_length);
        memcpy(buf + key_length + 2, current_attr->value, value_length);
        char *buf_ptr = apr_pstrdup(f->r->pool, buf);
        str_bucket = apr_bucket_transient_create(buf_ptr, strlen(buf_ptr), f->r->connection->bucket_alloc);
        if (!str_bucket) {
            return;
        }
        APR_BUCKET_INSERT_BEFORE(*b, str_bucket);
    }

    temp_str = ">process_script(function () {";
    str_bucket = apr_bucket_transient_create(temp_str, strlen(temp_str), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);
}

void replace_img_tag(ap_filter_t *f, apr_bucket **b, dict_t **attr_dict) {
    char *temp_str = "<script>loadImage(verify, ";
    apr_bucket *str_bucket = apr_bucket_transient_create(temp_str, strlen(temp_str), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);
    dict_t *s = NULL;
    HASH_FIND_STR(*attr_dict, "src", s);
    if (!s) {
        return;
    }
    char *buf = apr_pstrdup(f->r->pool, s->value);
    str_bucket = apr_bucket_transient_create(buf, strlen(buf), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);
    temp_str = ", PUBLIC_KEY, ";
    str_bucket = apr_bucket_transient_create(temp_str, strlen(temp_str), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);

    HASH_FIND_STR(*attr_dict, "id", s);
    if (s) {
        char *buf = apr_pstrdup(f->r->pool, s->value);
        str_bucket = apr_bucket_transient_create(buf, strlen(buf), f->r->connection->bucket_alloc);
        if (!str_bucket) {
            return;
        }
        APR_BUCKET_INSERT_BEFORE(*b, str_bucket);
    }
    else {
        int digits = 0;
        int temp_int = img_count;
        while (temp_int > 0) {
            ++digits;
            temp_int /= 10;
        }
        char buf[7 + digits + 2];
        buf[0] = '"';
        buf[1] = 'C';
        buf[2] = 'P';
        buf[3] = 'I';
        buf[4] = 'M';
        buf[5] = 'G';
        buf[6] = '-';
        sprintf(buf + 7, "%d", img_count);
        buf[7 + digits] = '"';
        buf[7 + digits + 1] = 0;
        char *buf_ptr = apr_pstrdup(f->r->pool, buf);
        str_bucket = apr_bucket_transient_create(buf_ptr, strlen(buf_ptr), f->r->connection->bucket_alloc);
        if (!str_bucket) {
            return;
        }
        APR_BUCKET_INSERT_BEFORE(*b, str_bucket);
        dict_t *s;
        s = malloc(sizeof(dict_t));
        memset(s->key, 0, ATTRIBUTE_TYPE_BUFFER_SIZE + 1);
        memset(s->value, 0, ATTRIBUTE_VALUE_BUFFER_SIZE + 1);
        memcpy(s->key, "id", 3);
        memcpy(s->value, buf_ptr, strlen(buf_ptr));
        HASH_ADD_STR(*attr_dict, key, s);
        ++img_count;
    }

    temp_str = ");</script><img src=\"\"";
    str_bucket = apr_bucket_transient_create(temp_str, strlen(temp_str), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);

    dict_t *current_attr, *tmp;
    HASH_ITER(hh, *attr_dict, current_attr, tmp) {
        if (strcasecmp(current_attr->key, "src")) {
            int key_length = strlen(current_attr->key);
            int value_length = strlen(current_attr->value);

            char buf[key_length + 1 + value_length + 2];
            buf[0] = ' ';
            buf[key_length + 1] = '=';
            buf[key_length + 1 + value_length + 1] = 0;
            memcpy(buf + 1, current_attr->key, key_length);
            memcpy(buf + key_length + 2, current_attr->value, value_length);
            char *buf_ptr = apr_pstrdup(f->r->pool, buf);
            str_bucket = apr_bucket_transient_create(buf_ptr, strlen(buf_ptr), f->r->connection->bucket_alloc);
            if (!str_bucket) {
                return;
            }
            APR_BUCKET_INSERT_BEFORE(*b, str_bucket);
        }
    }

    temp_str = "/>";
    str_bucket = apr_bucket_transient_create(temp_str, strlen(temp_str), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);
}

void replace_link_tag(ap_filter_t *f, apr_bucket **b, char *s, dict_t **attr_dict) {
    char *temp_str = "<script>loadCSS(verify, ";
    apr_bucket *str_bucket = apr_bucket_transient_create(temp_str, strlen(temp_str), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);

    char *buf = apr_pstrdup(f->r->pool, s);
    str_bucket = apr_bucket_transient_create(buf, strlen(buf), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);

    temp_str = ", PUBLIC_KEY";
    str_bucket = apr_bucket_transient_create(temp_str, strlen(temp_str), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);

    dict_t *current_attr, *tmp;
    HASH_ITER(hh, *attr_dict, current_attr, tmp) {
        int key_length = strlen(current_attr->key);
        int value_length = strlen(current_attr->value);

        char buf[4 + key_length + 2 + value_length + 3];
        buf[0] = ',';
        buf[1] = ' ';
        buf[2] = '"';
        buf[key_length + 3] = '"';
        buf[key_length + 4] = ',';
        buf[key_length + 5] = ' ';
        buf[key_length + 5 + value_length + 1] = 0;
        memcpy(buf + 3, current_attr->key, key_length);
        memcpy(buf + key_length + 6, current_attr->value, value_length);
        char *buf_ptr = apr_pstrdup(f->r->pool, buf);
        str_bucket = apr_bucket_transient_create(buf_ptr, strlen(buf_ptr), f->r->connection->bucket_alloc);
        if (!str_bucket) {
            return;
        }
        APR_BUCKET_INSERT_BEFORE(*b, str_bucket);
    }

    temp_str = ");</script>";
    str_bucket = apr_bucket_transient_create(temp_str, strlen(temp_str), f->r->connection->bucket_alloc);
    if (!str_bucket) {
        return;
    }
    APR_BUCKET_INSERT_BEFORE(*b, str_bucket);
}

int is_local_resource(char *s, char *domain) {
    // 0: non-local resource
    // 1: local resource with an absolute path
    // 2: local resource with a relative path
    // 3: local resource with an explicit domain via http
    // 4: local resource with an explicit domain via https
    // 5: local resource with a protocol relative url and an explicit domain.
    // 6: javascript variable
    // 7: data URI scheme
    int src_length = strlen(s);
    int domain_length = strlen(domain);
    if (src_length > 1) {
        // Check for case 5/6
        if (s[0] == '/' && s[1] == '/') {
            char *domain_begin_ptr = s + 2;
            char *domain_end_ptr = s + 2;
            while (domain_end_ptr < s + src_length) {
                if (*domain_end_ptr == '/') {
                    break;
                }
                ++domain_end_ptr;
            }
            if (domain_end_ptr - domain_begin_ptr != domain_length) {
                return 0;
            }
            else {
                char *ptr;
                for (ptr = domain_begin_ptr; ptr != domain_end_ptr; ++ptr) {
                    if (tolower(*ptr) != tolower(domain[ptr - domain_begin_ptr])) {
                        return 0;
                    }
                }
                return 5;
            }
        }
        else if (s[0] == '{' && s[1] == '{') {
            return 6;
        }
    }
    if (src_length > 4) {
        // Check for case 7
        if (tolower(s[0]) == 'd' && tolower(s[1]) == 'a' && tolower(s[2]) == 't' && tolower(s[3]) == 'a' && s[4] == ':') {
            return 7;
        }
    }

    if (src_length == 0) {
        return 0;
    }
    else if (src_length < 7) {
        if (s[0] == '/') {
            return 1;
        }
        else {
            return 2;
        }
    }
    else if (src_length == 7) {
        if (tolower(s[0]) == 'h' &&
            tolower(s[1]) == 't' &&
            tolower(s[2]) == 't' &&
            tolower(s[3]) == 'p' &&
            tolower(s[4]) == ':' &&
            tolower(s[5]) == '/' &&
            tolower(s[6]) == '/') {
            return 0;
        }
        else {
            if (s[0] == '/') {
                return 1;
            }
            else {
                return 2;
            }
        }
    }
    else if (src_length == 8) {
        if (tolower(s[0]) == 'h' &&
            tolower(s[1]) == 't' &&
            tolower(s[2]) == 't' &&
            tolower(s[3]) == 'p') {
            if (tolower(s[4]) == 's' && tolower(s[5]) == ':' && tolower(s[6]) == '/' && tolower(s[7]) == '/') {
                return 0;
            }
            else if (tolower(s[4]) == ':' && tolower(s[5]) == '/' && tolower(s[6]) == '/') {
                if (tolower(s[7]) == domain[0] && domain_length == 1) {
                    return 3;
                }
                else {
                    return 0;
                }
            }
            else {
                if (s[0] == '/') {
                    return 1;
                }
                else {
                    return 2;
                }
            }
        }
        else {
            if (s[0] == '/') {
                return 1;
            }
            else {
                return 2;
            }
        }
    }
    else {
        if (tolower(s[0]) == 'h' &&
            tolower(s[1]) == 't' &&
            tolower(s[2]) == 't' &&
            tolower(s[3]) == 'p') {
            char *domain_begin_ptr;
            if (tolower(s[4]) == 's' && tolower(s[5]) == ':' && tolower(s[6]) == '/' && tolower(s[7]) == '/') {
                domain_begin_ptr = s + 8;
            }
            else if (tolower(s[4]) == ':' && tolower(s[5]) == '/' && tolower(s[6]) == '/') {
                domain_begin_ptr = s + 7;
            }
            else {
                if (s[0] == '/') {
                    return 1;
                }
                else {
                    return 2;
                }
            }
            char *domain_end_ptr = domain_begin_ptr;
            while (domain_end_ptr < s + src_length) {
                if (*domain_end_ptr == '/') {
                    break;
                }
                ++domain_end_ptr;
            }
            if (domain_end_ptr - domain_begin_ptr != domain_length) {
                return 0;
            }
            else {
                char *ptr;
                for (ptr = domain_begin_ptr; ptr != domain_end_ptr; ++ptr) {
                    if (tolower(*ptr) != tolower(domain[ptr - domain_begin_ptr])) {
                        return 0;
                    }
                }
                return (domain_begin_ptr - s == 8) ? 4 : 3;
            }
        }
        else {
            if (s[0] == '/') {
                return 1;
            }
            else {
                return 2;
            }
        }
    }

    return src_length > 0 &&
            !((src_length > 6 &&
              tolower(s[0]) == 'h' &&
              tolower(s[1]) == 't' &&
              tolower(s[2]) == 't' &&
              tolower(s[3]) == 'p') &&
             (src_length > 7 &&
              tolower(s[4]) == 's' &&
              s[5] == ':' &&
              s[6] == '/' &&
              s[7] == '/') ||
             (s[4] == ':' &&
              s[5] == '/' &&
              s[6] == '/'));
}

int should_rewrite_url(int resource_type) {
    return (resource_type != 0 && resource_type != 6 && resource_type != 7);
}

void update_doc_mode(const char *tag_type, DOCUMENT_MODE* doc_mode, ap_filter_t *f, apr_bucket_brigade *bb,
                     apr_bucket **b, int *position, int *inserted_code, crypto_proxy_conf_t *cfg, dict_t **attr_dict,
                     apr_bucket *tag_begin_bucket, int tag_begin_offset) {
    if (!strcasecmp(tag_type, "html")) {
        if (*doc_mode == EXPECTING_HTML) {
            *doc_mode = EXPECTING_HEAD;
        }
    }
    else if (!strcasecmp(tag_type, "head")) {
        if (!*inserted_code && (*doc_mode == EXPECTING_HTML || *doc_mode == EXPECTING_HEAD)) {
            insert_after_head(f, bb, b, position, cfg);
            *inserted_code = 1;
        }
        *doc_mode = EXPECTING_BODY;
    }
    else if (!strcasecmp(tag_type, "body")) {
        if (!*inserted_code && (*doc_mode == EXPECTING_HTML || *doc_mode == EXPECTING_HEAD)) {
            insert_after_head(f, bb, b, position, cfg);
            *inserted_code = 1;
        }
        *doc_mode = EXPECTING_NOTHING;
    }
    else if (strlen(tag_type)){
        if (!*inserted_code && (*doc_mode == EXPECTING_HTML || *doc_mode == EXPECTING_HEAD)) {
            insert_before_anything(f, bb, cfg);
            *inserted_code = 1;
        }
        if (!strcasecmp(tag_type, "script")) {
            dict_t *s = NULL;
            HASH_FIND_STR(*attr_dict, "src", s);
            if (s && !inside_inline_script) {
                ltrim(s->value + 1);
                int resource_type = is_local_resource(s->value + 1, cfg->https_domain);
                if (should_rewrite_url(resource_type)) {
                    apr_bucket *ptr = tag_begin_bucket;
                    replace_domain(s->value + 1, cfg->http_domain, resource_type, f);
                    HASH_DEL(*attr_dict, s);
                    if (ptr != *b) {
                        apr_bucket_split(ptr, tag_begin_offset);
                        APR_BUCKET_REMOVE(APR_BUCKET_NEXT(ptr));
                        ptr = APR_BUCKET_NEXT(ptr);
                        while (ptr != *b) {
                            apr_bucket *temp_ptr = ptr;
                            ptr = APR_BUCKET_NEXT(ptr);
                            APR_BUCKET_REMOVE(temp_ptr);
                        }
                        apr_bucket_split(*b, *position + 1);
                        apr_bucket *temp_ptr = *b;
                        *b = APR_BUCKET_NEXT(*b);
                        replace_script_tag(f, b, s->value, attr_dict, script_count++);
                        get_crypto_proxy_bucket(f, *b);
                        *position = 0;
                    }
                    else {
                        apr_bucket_split(*b, tag_begin_offset);
                        *b = APR_BUCKET_NEXT(*b);
                        apr_bucket_split(*b, *position - tag_begin_offset + 1);
                        *b = APR_BUCKET_NEXT(*b);
                        APR_BUCKET_REMOVE(APR_BUCKET_PREV(*b));
                        replace_script_tag(f, b, s->value, attr_dict, script_count++);
                        get_crypto_proxy_bucket(f, *b);
                        *position = 0;
                    }
                }
            }
            // Inline script
            else {
                s = NULL;
                HASH_FIND_STR(*attr_dict, "type", s);
                if (s) {
                    int s_length = strlen(s->value);
                    memmove(s->value, s->value + 1, s_length - 2);
                    s->value[s_length - 2] = 0;
                }
                if (!s || !strcasecmp("text/javascript", s->value)) {
                    inside_inline_script = 1;
                    apr_bucket *ptr = tag_begin_bucket;
                    if (ptr != *b) {
                        apr_bucket_split(ptr, tag_begin_offset);
                        APR_BUCKET_REMOVE(APR_BUCKET_NEXT(ptr));
                        ptr = APR_BUCKET_NEXT(ptr);
                        while (ptr != *b) {
                            apr_bucket *temp_ptr = ptr;
                            ptr = APR_BUCKET_NEXT(ptr);
                            APR_BUCKET_REMOVE(temp_ptr);
                        }
                        apr_bucket_split(*b, *position + 1);
                        apr_bucket *temp_ptr = *b;
                        *b = APR_BUCKET_NEXT(*b);
                        replace_inline_script_tag(f, b, attr_dict, script_count++);
                        get_crypto_proxy_bucket(f, *b);
                        *position = 0;
                    }
                    else {
                        apr_bucket_split(*b, tag_begin_offset);
                        *b = APR_BUCKET_NEXT(*b);
                        apr_bucket_split(*b, *position - tag_begin_offset + 1);
                        *b = APR_BUCKET_NEXT(*b);
                        APR_BUCKET_REMOVE(APR_BUCKET_PREV(*b));
                        replace_inline_script_tag(f, b, attr_dict, script_count++);
                        get_crypto_proxy_bucket(f, *b);
                        *position = 0;
                    }
                }
                if (s) {
                    HASH_DEL(*attr_dict, s);
                }
            }
        }
        else if (!strcasecmp(tag_type, "link")) {
            dict_t *s_rel = NULL;
            HASH_FIND_STR(*attr_dict, "rel", s_rel);
            if (s_rel) {
                int s_rel_length = strlen(s_rel->value);
                memmove(s_rel->value, s_rel->value + 1, s_rel_length - 2);
                s_rel->value[s_rel_length - 2] = 0;
            }
            if (s_rel && !strcasecmp(s_rel->value, "stylesheet") && !inside_inline_script) {
                dict_t *s = NULL;
                HASH_FIND_STR(*attr_dict, "href", s);
                if (s) {
                    ltrim(s->value + 1);
                    int resource_type = is_local_resource(s->value + 1, cfg->https_domain);
                    if (should_rewrite_url(resource_type)) {
                        apr_bucket *ptr = tag_begin_bucket;
                        replace_domain(s->value + 1, cfg->http_domain, resource_type, f);
                        HASH_DEL(*attr_dict, s_rel);
                        HASH_DEL(*attr_dict, s);
                        if (ptr != *b) {
                            apr_bucket_split(ptr, tag_begin_offset);
                            APR_BUCKET_REMOVE(APR_BUCKET_NEXT(ptr));
                            ptr = APR_BUCKET_NEXT(ptr);
                            while (ptr != *b) {
                                apr_bucket *temp_ptr = ptr;
                                ptr = APR_BUCKET_NEXT(ptr);
                                APR_BUCKET_REMOVE(temp_ptr);
                            }
                            apr_bucket_split(*b, *position + 1);
                            apr_bucket *temp_ptr = *b;
                            *b = APR_BUCKET_NEXT(*b);
                            replace_link_tag(f, b, s->value, attr_dict);
                            get_crypto_proxy_bucket(f, *b);
                            *position = 0;
                        }
                        else {
                            apr_bucket_split(*b, tag_begin_offset);
                            *b = APR_BUCKET_NEXT(*b);
                            apr_bucket_split(*b, *position - tag_begin_offset + 1);
                            *b = APR_BUCKET_NEXT(*b);
                            APR_BUCKET_REMOVE(APR_BUCKET_PREV(*b));
                            replace_link_tag(f, b, s->value, attr_dict);
                            get_crypto_proxy_bucket(f, *b);
                            *position = 0;
                        }
                    }
                }
            }
        }
        else if (!strcasecmp(tag_type, "img")) {
            dict_t *s = NULL;
            HASH_FIND_STR(*attr_dict, "src", s);
            if (s && !inside_inline_script) {
                size_t src_length = strlen(s->value);
                ltrim(s->value + 1);
                int resource_type = is_local_resource(s->value + 1, cfg->https_domain);
                if (should_rewrite_url(resource_type)) {
                    apr_bucket *ptr = tag_begin_bucket;
                    replace_domain(s->value + 1, cfg->http_domain, resource_type, f);
                    if (ptr != *b) {
                        apr_bucket_split(ptr, tag_begin_offset);
                        APR_BUCKET_REMOVE(APR_BUCKET_NEXT(ptr));
                        ptr = APR_BUCKET_NEXT(ptr);
                        while (ptr != *b) {
                            apr_bucket *temp_ptr = ptr;
                            ptr = APR_BUCKET_NEXT(ptr);
                            APR_BUCKET_REMOVE(temp_ptr);
                        }
                        apr_bucket_split(*b, *position + 1);
                        apr_bucket *temp_ptr = *b;
                        *b = APR_BUCKET_NEXT(*b);
                        replace_img_tag(f, b, attr_dict);
                        get_crypto_proxy_bucket(f, *b);
                        *position = 0;
                    }
                    else {
                        apr_bucket_split(*b, tag_begin_offset);
                        *b = APR_BUCKET_NEXT(*b);
                        apr_bucket_split(*b, *position - tag_begin_offset + 1);
                        *b = APR_BUCKET_NEXT(*b);
                        APR_BUCKET_REMOVE(APR_BUCKET_PREV(*b));
                        replace_img_tag(f, b, attr_dict);
                        get_crypto_proxy_bucket(f, *b);
                        *position = 0;
                    }
                }
            }
        }
        else if (!strcasecmp(tag_type, "/script")) {
            if (inside_inline_script) {
                apr_bucket *ptr = tag_begin_bucket;
                int update_b = 0;
                if (ptr == *b) {
                    update_b = 1;
                }
                apr_bucket_split(tag_begin_bucket, tag_begin_offset);

                char seq_buf[64];
                seq_buf[0] = '}';
                seq_buf[1] = ',';
                seq_buf[2] = ' ';
                seq_buf[3] = '1';
                seq_buf[4] = ',';
                seq_buf[5] = ' ';
                int length = sprintf(seq_buf + 6, "%d", script_count - 1);
                seq_buf[length + 6] = ')';
                seq_buf[length + 7] = ';';
                apr_bucket *str_bucket = apr_bucket_transient_create(apr_pstrdup(f->r->pool, seq_buf), length + 8, f->r->connection->bucket_alloc);
                if (!str_bucket) {
                    return;
                }
                APR_BUCKET_INSERT_AFTER(tag_begin_bucket, str_bucket);

                if (update_b) {
                    *b = APR_BUCKET_NEXT(APR_BUCKET_NEXT(tag_begin_bucket));
                    *position -= tag_begin_offset;
                    get_crypto_proxy_bucket(f, *b);
                }
                inside_inline_script = 0;
            }
        }
    }
}

void rewrite_css_brigade(ap_filter_t *f, apr_bucket_brigade *bb, crypto_proxy_conf_t *cfg) {
    crypto_proxy_module_ctx_t *ctx = f->ctx;
    apr_bucket *b = APR_BRIGADE_FIRST(bb);
    QUOTATION_MODE quotation_mode = OUTSIDE;

    int i = 0;
    apr_bucket *tag_begin_bucket;
    int tag_begin_offset;

    int stage = 0;
    apr_bucket *url_begin_bucket;
    unsigned int url_begin_offset;
    const int URL_BUFFER_SIZE = 2048;
    char url_buffer[URL_BUFFER_SIZE];
    int url_buffer_pos = 0;
    const char *data;

    while (b != APR_BRIGADE_SENTINEL(bb)) {
        get_crypto_proxy_bucket(f, b);
        if (!APR_BUCKET_IS_METADATA(b)) {
            data = ctx->crypto_proxy_bucket->data;
            while (i < ctx->crypto_proxy_bucket->len) {
                char lower_data_i = tolower(data[i]);
                if (stage == 0) {
                    if (lower_data_i == 'u') {
                        stage = 1;
                    }
                }
                else if (stage == 1) {
                    if (lower_data_i == 'r') {
                        stage = 2;
                    }
                    else if (lower_data_i == 'u') {
                        stage = 1;
                    }
                    else {
                        stage = 0;
                    }
                }
                else if (stage == 2) {
                    if (lower_data_i == 'l') {
                        stage = 3;
                    }
                    else if (lower_data_i == 'u') {
                        stage = 1;
                    }
                    else {
                        stage = 0;
                    }
                }
                else if (stage == 3) {
                    if (lower_data_i == '(') {
                        stage = 4;
                    }
                    else if (lower_data_i == 'u') {
                        stage = 1;
                    }
                    else {
                        stage = 0;
                    }
                }
                else if (stage == 4) {
                    if (lower_data_i == '"') {
                        quotation_mode = INSIDE_DOUBLE;
                        stage = 5;
                    }
                    else if (lower_data_i == '\'') {
                        quotation_mode = INSIDE_SINGLE;
                        stage = 6;
                    }
                    else if (lower_data_i == ')') {
                        stage = 0;
                    }
                    else if (!is_space(lower_data_i)) {
                        stage = 7;
                        url_begin_bucket = b;
                        url_begin_offset = i;
                        url_buffer_pos = 0;
                        --i;
                    }
                }
                else if (stage == 5) {
                    if (lower_data_i == '"') {
                        quotation_mode = OUTSIDE;
                        stage = 0;
                    }
                    else if (!is_space(lower_data_i)) {
                        stage = 7;
                        url_begin_bucket = b;
                        url_begin_offset = i;
                        url_buffer_pos = 0;
                        --i;
                    }
                }
                else if (stage == 6) {
                    if (lower_data_i == '\'') {
                        quotation_mode = OUTSIDE;
                        stage = 0;
                    }
                    else if (!is_space(lower_data_i)) {
                        stage = 7;
                        url_begin_bucket = b;
                        url_begin_offset = i;
                        url_buffer_pos = 0;
                        --i;
                    }
                }
                else if (stage == 7) {
                    if (quotation_mode == INSIDE_SINGLE && lower_data_i == '\''
                            || quotation_mode == INSIDE_DOUBLE && lower_data_i == '"'
                            || quotation_mode == OUTSIDE && lower_data_i == ')') {
                        url_buffer[url_buffer_pos] = 0;
                        if (should_rewrite_url(is_local_resource(url_buffer, cfg->https_domain))) {
                            unsigned int https_domain_length = strlen(cfg->https_domain);
                            unsigned int uri_length = strlen(f->r->uri);
                            while (uri_length > 0) {
                                if (f->r->uri[uri_length - 1] != '/') {
                                    --uri_length;
                                }
                                else {
                                    break;
                                }
                            }
                            char css_url_prefix[https_domain_length + uri_length + 9];
                            memcpy(css_url_prefix, "https://", 8);
                            css_url_prefix[https_domain_length + uri_length + 8] = 0;
                            memcpy(css_url_prefix + 8, cfg->https_domain, https_domain_length);
                            memcpy(css_url_prefix + 8 + https_domain_length, f->r->uri, uri_length);
                            char *buf_ptr = apr_pstrdup(f->r->pool, css_url_prefix);
                            apr_bucket *str_bucket = apr_bucket_transient_create(buf_ptr, https_domain_length + uri_length + 8, f->r->connection->bucket_alloc);
                            if (!str_bucket) {
                                return;
                            }

                            if (url_begin_bucket == b) {
                                apr_bucket_split(b, url_begin_offset);
                                b = APR_BUCKET_NEXT(b);
                                APR_BUCKET_INSERT_BEFORE(b, str_bucket);
                                get_crypto_proxy_bucket(f, b);
                                data = ctx->crypto_proxy_bucket->data;
                                i -= url_begin_offset;
                            }
                            else {
                                apr_bucket_split(url_begin_bucket, url_begin_offset);
                                APR_BUCKET_INSERT_BEFORE(APR_BUCKET_NEXT(url_begin_bucket), str_bucket);
                            }
                        }
                        stage = 0;
                    }
                    else {
                        if (url_buffer_pos < URL_BUFFER_SIZE) {
                            url_buffer[url_buffer_pos++] = data[i];
                        }
                    }
                }
                ++i;
            }
        }
        b = APR_BUCKET_NEXT(b);
        i = 0;
    }
}

void rewrite_html_brigade(ap_filter_t *f, apr_bucket_brigade *bb, crypto_proxy_conf_t *cfg) {
    crypto_proxy_module_ctx_t *ctx = f->ctx;
    apr_bucket *b = APR_BRIGADE_FIRST(bb);
    DOCUMENT_MODE doc_mode = EXPECTING_HTML;
    TAG_MODE tag_mode = EXPECTING_LEFT_BRACKET;
    QUOTATION_MODE quote_mode = OUTSIDE;

    apr_bucket *script_begin_bucket;
    int script_begin_offset;

    img_count = 1;
    script_count = 0;
    inside_inline_script = 0;

    int i = 0;
    char tag_type[TAG_TYPE_BUFFER_SIZE + 1];
    memset(tag_type, 0, TAG_TYPE_BUFFER_SIZE + 1);
    int tag_type_ptr = 0;
    char attribute_type[ATTRIBUTE_TYPE_BUFFER_SIZE + 1];
    memset(attribute_type, 0, ATTRIBUTE_TYPE_BUFFER_SIZE + 1);
    int attribute_type_ptr = 0;
    char attribute_value[ATTRIBUTE_VALUE_BUFFER_SIZE + 1];
    memset(attribute_value, 0, ATTRIBUTE_VALUE_BUFFER_SIZE + 1);
    int attribute_value_ptr = 0;
    int inserted_code = 0;

    dict_t *attr_dict = NULL;

    apr_bucket *tag_begin_bucket;
    int tag_begin_offset;

    while (b != APR_BRIGADE_SENTINEL(bb)) {
        get_crypto_proxy_bucket(f, b);
        if (!APR_BUCKET_IS_METADATA(b)) {
            while (i < ctx->crypto_proxy_bucket->len) {
                const char *data = ctx->crypto_proxy_bucket->data;
                if (tag_mode == EXPECTING_LEFT_BRACKET) {
                    if (data[i] == '<') {
                        tag_type_ptr = 0;
                        tag_begin_bucket = b;
                        tag_begin_offset = i;
                        HASH_CLEAR(hh, attr_dict);
                        tag_mode = EXPECTING_TAG_TYPE;
                    }
                }
                else if (tag_mode == EXPECTING_TAG_TYPE) {
                    if (is_space(data[i])) {
                        tag_type[tag_type_ptr] = 0;
                        attribute_type_ptr = 0;
                        tag_mode = EXPECTING_ATTRIBUTE_TYPE;
                    }
                    else if (data[i] == '>') {
                        tag_type[tag_type_ptr] = 0;
                        update_doc_mode(tag_type, &doc_mode, f, bb, &b, &i, &inserted_code, cfg, &attr_dict, tag_begin_bucket, tag_begin_offset);
                        tag_type_ptr = 0;
                        tag_mode = EXPECTING_LEFT_BRACKET;
                    }
                    else if (data[i] == '<' && inside_inline_script) {
                        tag_type_ptr = 0;
                        tag_begin_bucket = b;
                        tag_begin_offset = i;
                        HASH_CLEAR(hh, attr_dict);
                    }
                    else {
                        if (tag_type_ptr < TAG_TYPE_BUFFER_SIZE) {
                            tag_type[tag_type_ptr++] = data[i];
                        }
                        // Handle HTML comments (<!-- -->)
                        if (tag_type_ptr == 3 && tag_type[0] == '!' && tag_type[1] == '-' && tag_type[2] == '-') {
                            tag_type_ptr = 0;
                            tag_mode = EXPECTING_CLOSE_COMMENT;
                        }
                        // Handle <!DOCTYPE>
                        if (tag_type_ptr == 8 && tag_type[0] == '!'
                            && tolower(tag_type[1]) == 'd' && tolower(tag_type[2]) == 'o'
                            && tolower(tag_type[3]) == 'c' && tolower(tag_type[4]) == 't'
                            && tolower(tag_type[5]) == 'y' && tolower(tag_type[6]) == 'p'
                            && tolower(tag_type[7]) == 'e') {
                            tag_type_ptr = 0;
                            tag_mode = EXPECTING_CLOSE;
                        }
                    }
                }
                else if (tag_mode == EXPECTING_ATTRIBUTE_TYPE) {
                    if (is_space(data[i])) {
                        if (attribute_type_ptr > 0) {
                            tag_mode == EXPECTING_ATTRIBUTE_TYPE_EQUAL;
                        }
                    }
                    else if (data[i] == '=') {
                        if (attribute_type_ptr > 0) {
                            attribute_type[attribute_type_ptr] = 0;
                            attribute_type_ptr = 0;
                            tag_mode = EXPECTING_ATTRIBUTE_VALUE_QUOTE;
                        }
                    }
                    else if (data[i] == '>') {
                        if (attribute_type_ptr > 0) {
                            attribute_type[attribute_type_ptr] = 0;

                            dict_t *s;
                            s = malloc(sizeof(dict_t));
                            memset(s->key, 0, ATTRIBUTE_TYPE_BUFFER_SIZE + 1);
                            memset(s->value, 0, ATTRIBUTE_VALUE_BUFFER_SIZE + 1);
                            memcpy(s->key, attribute_type, attribute_type_ptr);
                            int j;
                            for (j = 0; j < attribute_type_ptr; ++j) {
                                s->key[j] = tolower(s->key[j]);
                            }
                            HASH_ADD_STR(attr_dict, key, s);

                            attribute_type_ptr = 0;
                        }

                        tag_type[tag_type_ptr] = 0;
                        update_doc_mode(tag_type, &doc_mode, f, bb, &b, &i, &inserted_code, cfg, &attr_dict, tag_begin_bucket, tag_begin_offset);
                        tag_type_ptr = 0;
                        tag_mode = EXPECTING_LEFT_BRACKET;
                    }
                    else if (data[i] == '/') {
                        if (attribute_type_ptr > 0) {
                            attribute_type[attribute_type_ptr] = 0;

                            dict_t *s;
                            s = malloc(sizeof(dict_t));
                            memset(s->key, 0, ATTRIBUTE_TYPE_BUFFER_SIZE + 1);
                            memset(s->value, 0, ATTRIBUTE_VALUE_BUFFER_SIZE + 1);
                            memcpy(s->key, attribute_type, attribute_type_ptr);
                            int j;
                            for (j = 0; j < attribute_type_ptr; ++j) {
                                s->key[j] = tolower(s->key[j]);
                            }
                            HASH_ADD_STR(attr_dict, key, s);

                            attribute_type_ptr = 0;
                        }
                        tag_mode = EXPECTING_CLOSE;
                    }
                    else if (data[i] == '<' && inside_inline_script) {
                        tag_type_ptr = 0;
                        tag_begin_bucket = b;
                        tag_begin_offset = i;
                        HASH_CLEAR(hh, attr_dict);
                        tag_mode = EXPECTING_TAG_TYPE;
                    }
                    else {
                        if (attribute_type_ptr < ATTRIBUTE_TYPE_BUFFER_SIZE) {
                            attribute_type[attribute_type_ptr++] = data[i];
                        }
                    }
                }
                else if (tag_mode == EXPECTING_ATTRIBUTE_TYPE_EQUAL) {
                    if (data[i] == '=') {
                        if (attribute_type_ptr > 0) {
                            attribute_type[attribute_type_ptr] = 0;
                            attribute_type_ptr = 0;
                            tag_mode = EXPECTING_ATTRIBUTE_VALUE_QUOTE;
                        }
                    }
                    else if (data[i] == '>') {
                        if (attribute_type_ptr > 0) {
                            attribute_type[attribute_type_ptr] = 0;

                            dict_t *s;
                            s = malloc(sizeof(dict_t));
                            memset(s->key, 0, ATTRIBUTE_TYPE_BUFFER_SIZE + 1);
                            memset(s->value, 0, ATTRIBUTE_VALUE_BUFFER_SIZE + 1);
                            memcpy(s->key, attribute_type, attribute_type_ptr);
                            int j;
                            for (j = 0; j < attribute_type_ptr; ++j) {
                                s->key[j] = tolower(s->key[j]);
                            }
                            HASH_ADD_STR(attr_dict, key, s);

                            attribute_type_ptr = 0;
                        }

                        tag_type[tag_type_ptr] = 0;
                        update_doc_mode(tag_type, &doc_mode, f, bb, &b, &i, &inserted_code, cfg, &attr_dict, tag_begin_bucket, tag_begin_offset);
                        tag_type_ptr = 0;
                        tag_mode = EXPECTING_LEFT_BRACKET;
                    }
                    else if (data[i] != ' ') {
                        if (attribute_type_ptr > 0) {
                            attribute_type[attribute_type_ptr] = 0;

                            dict_t *s;
                            s = malloc(sizeof(dict_t));
                            memset(s->key, 0, ATTRIBUTE_TYPE_BUFFER_SIZE + 1);
                            memset(s->value, 0, ATTRIBUTE_VALUE_BUFFER_SIZE + 1);
                            memcpy(s->key, attribute_type, attribute_type_ptr);
                            int j;
                            for (j = 0; j < attribute_type_ptr; ++j) {
                                s->key[j] = tolower(s->key[j]);
                            }
                            HASH_ADD_STR(attr_dict, key, s);

                            attribute_type_ptr = 0;
                            tag_mode = EXPECTING_ATTRIBUTE_TYPE;
                        }
                    }
                    else if (data[i] == '<' && inside_inline_script) {
                        tag_type_ptr = 0;
                        tag_begin_bucket = b;
                        tag_begin_offset = i;
                        HASH_CLEAR(hh, attr_dict);
                        tag_mode = EXPECTING_TAG_TYPE;
                    }
                }
                else if (tag_mode == EXPECTING_ATTRIBUTE_VALUE_QUOTE) {
                    if (data[i] == '"') {
                        quote_mode = INSIDE_DOUBLE;
                        tag_mode = EXPECTING_ATTRIBUTE_VALUE;
                    }
                    else if (data[i] == '\'') {
                        quote_mode = INSIDE_SINGLE;
                        tag_mode = EXPECTING_ATTRIBUTE_VALUE;
                    }
                    else if (data[i] == '<' && inside_inline_script) {
                        tag_type_ptr = 0;
                        tag_begin_bucket = b;
                        tag_begin_offset = i;
                        HASH_CLEAR(hh, attr_dict);
                        tag_mode = EXPECTING_TAG_TYPE;
                    }
                    else {
                        quote_mode = OUTSIDE;
                        tag_mode = EXPECTING_ATTRIBUTE_VALUE;
                        --i;
                    }
                }
                else if (tag_mode == EXPECTING_ATTRIBUTE_VALUE) {
                    if (data[i] == '<' && inside_inline_script) {
                        tag_type_ptr = 0;
                        tag_begin_bucket = b;
                        tag_begin_offset = i;
                        HASH_CLEAR(hh, attr_dict);
                        tag_mode = EXPECTING_TAG_TYPE;
                    }
                    if (quote_mode == OUTSIDE && is_space(data[i])
                        || quote_mode == INSIDE_SINGLE && data[i] == '\''
                        || quote_mode == INSIDE_DOUBLE && data[i] == '"') {
                        attribute_value[attribute_value_ptr] = 0;

                        dict_t *s;
                        s = malloc(sizeof(dict_t));
                        memset(s->key, 0, ATTRIBUTE_TYPE_BUFFER_SIZE + 1);
                        memset(s->value, 0, ATTRIBUTE_VALUE_BUFFER_SIZE + 1);
                        strcpy(s->key, attribute_type);
                        s->value[0] = (quote_mode == INSIDE_SINGLE) ? '\'' : '"';
                        memcpy(s->value + 1, attribute_value, attribute_value_ptr);
                        s->value[1 + strlen(attribute_value)] = (quote_mode == INSIDE_SINGLE) ? '\'' : '"';
                        int j;
                        for (j = 0; j < attribute_type_ptr; ++j) {
                            s->key[j] = tolower(s->key[j]);
                        }
                        HASH_ADD_STR(attr_dict, key, s);

                        attribute_value_ptr = 0;
                        tag_mode = EXPECTING_ATTRIBUTE_TYPE;
                    }
                    else if (quote_mode == OUTSIDE && data[i] == '>') {
                        attribute_value[attribute_value_ptr] = 0;

                        dict_t *s;
                        s = malloc(sizeof(dict_t));
                        memset(s->key, 0, ATTRIBUTE_TYPE_BUFFER_SIZE + 1);
                        memset(s->value, 0, ATTRIBUTE_VALUE_BUFFER_SIZE + 1);
                        strcpy(s->key, attribute_type);
                        s->value[0] = (quote_mode == INSIDE_SINGLE) ? '\'' : '"';
                        memcpy(s->value + 1, attribute_value, attribute_value_ptr);
                        s->value[1 + strlen(attribute_value)] = (quote_mode == INSIDE_SINGLE) ? '\'' : '"';
                        int j;
                        for (j = 0; j < attribute_type_ptr; ++j) {
                            s->key[j] = tolower(s->key[j]);
                        }
                        HASH_ADD_STR(attr_dict, key, s);

                        attribute_value_ptr = 0;
                        tag_type[tag_type_ptr] = 0;
                        update_doc_mode(tag_type, &doc_mode, f, bb, &b, &i, &inserted_code, cfg, &attr_dict, tag_begin_bucket, tag_begin_offset);
                        tag_type_ptr = 0;
                        tag_mode = EXPECTING_LEFT_BRACKET;
                    }
                    else {
                        if (attribute_value_ptr < ATTRIBUTE_VALUE_BUFFER_SIZE) {
                            attribute_value[attribute_value_ptr++] = data[i];
                        }
                    }
                }
                else if (tag_mode == EXPECTING_CLOSE) {
                    if (data[i] == '>') {
                        tag_type[tag_type_ptr] = 0;
                        update_doc_mode(tag_type, &doc_mode, f, bb, &b, &i, &inserted_code, cfg, &attr_dict, tag_begin_bucket, tag_begin_offset);
                        tag_type_ptr = 0;
                        tag_mode = EXPECTING_LEFT_BRACKET;
                    }
                    else if (data[i] == '<' && inside_inline_script) {
                        tag_type_ptr = 0;
                        tag_begin_bucket = b;
                        tag_begin_offset = i;
                        HASH_CLEAR(hh, attr_dict);
                        tag_mode = EXPECTING_TAG_TYPE;
                    }
                }
                else if (tag_mode == EXPECTING_CLOSE_COMMENT) {
                    if (data[i] == '<' && inside_inline_script) {
                        tag_type_ptr = 0;
                        tag_begin_bucket = b;
                        tag_begin_offset = i;
                        HASH_CLEAR(hh, attr_dict);
                        tag_mode = EXPECTING_TAG_TYPE;
                    }
                    if (tag_type_ptr < 3) {
                        tag_type[tag_type_ptr++] = data[i];
                    }
                    else {
                        if (tag_type[0] == '-' && tag_type[1] == '-' && tag_type[2] == '>') {
                            tag_type_ptr = 0;
                            tag_mode = EXPECTING_LEFT_BRACKET;
                        }
                        tag_type[0] = tag_type[1];
                        tag_type[1] = tag_type[2];
                        tag_type[2] = data[i];
                    }
                }
                ++i;
            }
        }
        b = APR_BUCKET_NEXT(b);
        i = 0;
    }

    dict_t *current_attr, *tmp;
    HASH_ITER(hh, attr_dict, current_attr, tmp) {
        HASH_DEL(attr_dict, current_attr);
        free(current_attr);
    }
}
#endif