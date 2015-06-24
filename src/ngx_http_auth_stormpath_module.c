/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Stormpath, Inc.
 */


#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "json.h"

#define NGX_HTTP_AUTH_STORMPATH_BUF_SIZE 8192
#define NGX_HTTP_AUTH_STORMPATH_API_PREFIX "https://api.stormpath.com"

typedef struct {
    ngx_str_t                 app_href;
    ngx_str_t                 app_uri;
    ngx_str_t                 apikey;
    ngx_str_t                 group_href;
    ngx_str_t                 group_uri;
    ngx_http_upstream_conf_t  upstream;
} ngx_http_auth_stormpath_conf_t;


typedef struct {
    ngx_uint_t                in_flight;
    ngx_uint_t                authenticated;
    ngx_uint_t                status;
    ngx_http_request_t       *subrequest;
    ngx_str_t                 response;
    ngx_http_chunked_t        chunked;
    ngx_str_t                 account_href;
} ngx_http_auth_stormpath_ctx_t;


static struct {
    ngx_str_t http_method_post;
    ngx_str_t api_stormpath_com;
    ngx_str_t realm_stormpath;
} strings = {
    { 4, (u_char *) "POST " }, /* nginx deliberately offs-by-one here */
    ngx_string("api.stormpath.com"),
    ngx_string("Protected by Stormpath"),
};


static ngx_int_t ngx_http_auth_stormpath_set_realm(ngx_http_request_t *r,
    ngx_str_t *realm);
static ngx_str_t ngx_http_auth_stormpath_encode_user_pass(
    ngx_http_request_t *r, ngx_str_t user, ngx_str_t pass);
ngx_http_request_t *ngx_http_auth_stormpath_make_request(ngx_str_t *href,
    ngx_uint_t method, ngx_str_t uri, ngx_str_t encoded_userpwd,
    ngx_http_request_t *parent, ngx_http_auth_stormpath_ctx_t *ctx);
ngx_str_t ngx_http_auth_stormpath_build_login_attempt_uri(
    ngx_http_request_t *r, ngx_str_t app_uri);
ngx_str_t ngx_http_auth_stormpath_build_group_accounts_uri(
    ngx_http_request_t *r, ngx_str_t group_uri, ngx_str_t username);

static ngx_int_t ngx_http_auth_stormpath_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_auth_stormpath_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_stormpath_process_status_line(
    ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_stormpath_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_stormpath_reinit_request(ngx_http_request_t *r);
void ngx_http_auth_stormpath_abort_request(ngx_http_request_t *r);
void ngx_http_auth_stormpath_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);
static ngx_int_t ngx_http_auth_stormpath_filter_init(void *data);
static ngx_int_t ngx_http_auth_stormpath_input_filter(void *data,
    ssize_t bytes);

static ngx_int_t ngx_http_auth_stormpath_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc);
static void *ngx_http_auth_stormpath_create_conf(ngx_conf_t *cf);
static char *ngx_http_auth_stormpath_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_auth_stormpath_init(ngx_conf_t *cf);
static char *ngx_http_auth_stormpath(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char * ngx_http_auth_stormpath_require_group(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_stormpath_apikey(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

/* JSON response parsing */
static void *ngx_json_mem_alloc(size_t size, int zero, void *user_data);
static void ngx_json_mem_free(void *ptr, void *user_data);
static void ngx_sp_json_init_parser_settings(json_settings *js,
    ngx_pool_t *pool);
static json_value *ngx_sp_json_get_property(json_value *v, char *name);
static ngx_str_t ngx_sp_parse_login_attempt_response(ngx_http_request_t *r,
    ngx_str_t resp);
static ngx_int_t ngx_sp_parse_group_accounts_response(ngx_http_request_t *r,
    ngx_str_t resp, ngx_str_t account_href);


static ngx_command_t  ngx_http_auth_stormpath_commands[] = {

    { ngx_string("auth_stormpath"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_stormpath,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_stormpath_conf_t, app_href),
      NULL },

    { ngx_string("auth_stormpath_require_group"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_stormpath_require_group,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_stormpath_conf_t, group_href),
      NULL },

    { ngx_string("auth_stormpath_apikey"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_stormpath_apikey,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_stormpath_conf_t, apikey),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_stormpath_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_auth_stormpath_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_stormpath_create_conf,   /* create location configuration */
    ngx_http_auth_stormpath_merge_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_auth_stormpath_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_stormpath_module_ctx,   /* module context */
    ngx_http_auth_stormpath_commands,      /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/* Set WWW-Authenticate header in the response so the client knows they need
 * to authenticate. This verbatim copy of ngx_http_auth_stormpath_set_realm,
 * which is unfortunately not an externally-visible symbol. */
static ngx_int_t
ngx_http_auth_stormpath_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
    size_t   len;
    u_char  *basic, *p;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("Basic realm=\"\"") - 1 + realm->len;

    basic = ngx_pnalloc(r->pool, len);
    if (basic == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';

    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = basic;
    r->headers_out.www_authenticate->value.len = len;

    return NGX_HTTP_UNAUTHORIZED;
}


/* Base64-encode account username and password for loginAttempt, as per
 * http://docs.stormpath.com/rest/product-guide/#application-account-authc
 */
static ngx_str_t
ngx_http_auth_stormpath_encode_user_pass(ngx_http_request_t *r,
    ngx_str_t user, ngx_str_t pass)
{
    ngx_str_t txt, enc, body, err = ngx_null_string;
    u_char *p;

    txt.len = user.len + 1 + pass.len;
    txt.data = ngx_pnalloc(r->pool, txt.len);
    if (txt.data == NULL) {
        return err;
    }
    ngx_snprintf(txt.data, txt.len, "%V:%V", &user, &pass);

    enc.len = txt.len * 2;
    enc.data = ngx_pnalloc(r->pool, enc.len);
    if (enc.data == NULL) {
        return err;
    }

    ngx_encode_base64(&enc, &txt);

    body.data = ngx_pnalloc(r->pool, NGX_HTTP_AUTH_STORMPATH_BUF_SIZE);
    p = ngx_snprintf(body.data, NGX_HTTP_AUTH_STORMPATH_BUF_SIZE,
        "{\"type\": \"basic\", \"value\": \"%V\"}", &enc);

    body.len = p - body.data;

    return body;
}


/* create_request handler for the Stormpath API upstream. Since we'll be
 * using the upstream ourselves, we know exactly how the request should be
 * made and are basically constructing it from scratch here (as opposed to
 * doing so in the handler, manipulating the subrequest object). */
static ngx_int_t
ngx_http_auth_stormpath_create_request(ngx_http_request_t *r)
{
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_http_auth_stormpath_conf_t *cf;
    u_char                         *method_name = NULL;

    cf = ngx_http_get_module_loc_conf(r->parent,
        ngx_http_auth_stormpath_module);

    b = ngx_create_temp_buf(r->pool, NGX_HTTP_AUTH_STORMPATH_BUF_SIZE);
    if (b == NULL)
        return NGX_ERROR;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL)
        return NGX_ERROR;

    cl->buf = b;
    r->upstream->request_bufs = cl;

    switch (r->method) {
        case NGX_HTTP_GET:
            method_name = (u_char *) "GET";
            break;
        case NGX_HTTP_POST:
            method_name = (u_char *) "POST";
            break;
        default:
            return NGX_ERROR;
    }

    b->last = ngx_snprintf(b->pos, NGX_HTTP_AUTH_STORMPATH_BUF_SIZE - 1,
        "%s %V HTTP/1.1\r\n"
        "Host: api.stormpath.com\r\n"
        "Content-Type: application/json\r\n"
        "Accept: application/json\r\n"
        "Content-Length: %d\r\n"
        "Authorization: Basic %V\r\n"
        "Connection: close\r\n"
        "User-Agent: stormpath-nginx/alpha (" NGINX_VER ")\r\n\r\n",
            method_name, &r->uri,
            r->headers_in.content_length_n,
            &cf->apikey);

    if (r->method == NGX_HTTP_POST) {
        cl->next = r->request_body->bufs;
    }

    return NGX_OK;
}


/* First-phase process_header handler for Stormpath API upstream. It attempts
 * to parse the status line, fetching the status code, and then pass control
 * on to ngx_http_auth_stormpath_process_header so it can parse the rest of
 * the headers. We're only ever interested in the status code, tho. */
static ngx_int_t
ngx_http_auth_stormpath_process_status_line(ngx_http_request_t *r)
{
    ngx_int_t         rc;
    ngx_http_status_t status;

    ngx_memzero(&status, sizeof(ngx_http_status_t));

    rc = ngx_http_parse_status_line(r, &r->upstream->buffer, &status);
    if (rc == NGX_AGAIN) {
        return rc;
    }

    if (rc == NGX_OK) {
        r->upstream->headers_in.status_n = status.code;
        r->upstream->process_header = ngx_http_auth_stormpath_process_header;
        return ngx_http_auth_stormpath_process_header(r);
    }

    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
}


/* Second-phase process_header handler for Stormpath API upstream. We're
 * interested in some headers (chunked encoding, etc.) so we only parse
 * them, instead of setting up and invoking the built-in nginx parser engine.
 */
static ngx_int_t
ngx_http_auth_stormpath_process_header(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ssize_t keylen;
    u_char *te = (u_char *) "transfer-encoding";
    ssize_t te_len = ngx_strlen(te);

    for ( ;; ) {
        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

        if (rc == NGX_OK) {
            keylen = r->header_name_end - r->header_name_start;

            if ((keylen == te_len) && !ngx_strncasecmp(r->header_name_start,
                    te, te_len)) {
                if (!ngx_strncasecmp(r->header_start,
                        (u_char *) "chunked", 7)) {
                    r->upstream->headers_in.chunked = 1;
                }
            }

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header");

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    return NGX_OK;
}


/* If the upstream request is to be repeated (ie. connection to the Stormpath
 * API breaks and we want to retry), we need to reset the process_header
 * handler back to the first-phase, the status line parser, and the chunked
 * encoding body parser. */
static ngx_int_t
ngx_http_auth_stormpath_reinit_request(ngx_http_request_t *r)
{
    ngx_http_auth_stormpath_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_stormpath_module);

    r->upstream->process_header = ngx_http_auth_stormpath_process_status_line;
    ctx->chunked.state = 0;

    return NGX_OK;
}


void
ngx_http_auth_stormpath_abort_request(ngx_http_request_t *r)
{
    /* nothing to do here, but we still need to provide it */
}


void
ngx_http_auth_stormpath_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc)
{
    /* nothing to do here, but we still need to provide it */
}


static ngx_int_t
ngx_http_auth_stormpath_filter_init(void *data)
{
    /* nothing to do here, but we still need to provide it */
    return NGX_OK;
}


/* Invoked multiple times, as server response content is available. We just
 * append the data to our internal buffer, reallocating it each time. While
 * this is less performant than nginx chain-of-buffers, it's easier to do
 * and we don't expect large responses from our Stormpath API calls.
 *
 * If the response transfer-encoding is chunked, we need to decode the body
 * before appending it to the response buffer.
 */
static ngx_int_t
ngx_http_auth_stormpath_input_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t            *r = data;
    ngx_http_auth_stormpath_ctx_t *ctx;
    ngx_buf_t                     *b;
    ngx_int_t                      rc;
    u_char                        *tmp;

    ctx = ngx_http_get_module_ctx(r->parent, ngx_http_auth_stormpath_module);
    b = &r->upstream->buffer;

    b->last = b->pos + bytes;

    if (r->upstream->headers_in.chunked) {
        rc = ngx_http_parse_chunked(r, b, &ctx->chunked);

        if (rc == NGX_AGAIN) {
            return NGX_OK;
        }
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        bytes = ctx->chunked.size;
        b->last = b->pos + bytes;
    }

    /* Pretty suboptimal, but we're relying on the fact that at most
     * a few chunks will arrive from the server, so it's going to be fine.
     */
    if (bytes) {
        tmp = ngx_pnalloc(r->parent->pool, ctx->response.len + bytes);
        if (ctx->response.len) {
            (void) ngx_copy(tmp, ctx->response.data, ctx->response.len);
        }
        (void) ngx_copy(tmp + ctx->response.len, b->pos, bytes);
        ctx->response.data = tmp;
        ctx->response.len += bytes;
    }

    return NGX_OK;
}


/* Glue between nginx memory allocators and JSON parser library. */
static void *
ngx_json_mem_alloc(size_t size, int zero, void *user_data)
{
    ngx_pool_t *pool = (ngx_pool_t *) user_data;
    return zero ? ngx_pcalloc(pool, size) : ngx_pnalloc(pool, size);
}


/* Glue between nginx memory allocators and JSON parser library. */
static void
ngx_json_mem_free(void *ptr, void *user_data)
{
    ngx_pool_t *pool = (ngx_pool_t *) user_data;
    ngx_pfree(pool, ptr);
}


/* Initialize the JSON parser library settings so it know how to do
 * memory allocation/freeing. */
static void
ngx_sp_json_init_parser_settings(json_settings *js, ngx_pool_t *pool) {
    js->mem_alloc = ngx_json_mem_alloc;
    js->mem_free = ngx_json_mem_free;
    js->user_data = pool;
    js->max_memory = 1048576; // 1MB should be enough for everyone
    js->value_extra = 0;
}


/* Helper for getting property out of a JSON object, with guards so it can be
 * easily used recursively without checking for errors in each step. */
static json_value *
ngx_sp_json_get_property(json_value *v, char *name)
{
    ssize_t name_len = ngx_strlen(name);
    unsigned int i;

    if (!v || v->type != json_object)
        return NULL;

    for (i = 0; i < v->u.object.length; i++) {
        if (name_len != v->u.object.values[i].name_length) continue;
        if (ngx_strncmp(name, v->u.object.values[i].name, name_len)) continue;
        return v->u.object.values[i].value;
    }
    return NULL;
}


/* Parse loginAttempt response and try to pluck the account href from the
 * result. Returns the account href as a nginx string or null string if
 * parse failed. */
static ngx_str_t
ngx_sp_parse_login_attempt_response(ngx_http_request_t *r, ngx_str_t resp)
{
    ngx_str_t href, err = ngx_null_string;
    json_settings js;
    json_value *jv, *v;
    char json_err[NGX_HTTP_AUTH_STORMPATH_BUF_SIZE];

    if (!resp.len) return err;

    ngx_sp_json_init_parser_settings(&js, r->pool);
    jv = json_parse_ex(&js, (char *) resp.data, resp.len, json_err);
    if (jv == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "error parsing upstream JSON response: %s", json_err);
        return err;
    }

    v = ngx_sp_json_get_property(jv, "account");
    v = ngx_sp_json_get_property(v, "href");

    if (!v || v->type != json_string || !v->u.string.length) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "upstream sent invalid response: %V", &resp);
        return err;
    }

    href.len = v->u.string.length;
    href.data = ngx_pnalloc(r->pool, href.len);
    (void) ngx_copy(href.data, v->u.string.ptr, href.len);

    json_value_free_ex(&js, jv);
    return href;
}

/* Parse group accounts response and check if provided account href is in
 * the group. Returns NGX_OK if account is found, NGX_ERROR if not or if
 * there was an error parsing the response.
 */
static ngx_int_t
ngx_sp_parse_group_accounts_response(ngx_http_request_t *r, ngx_str_t resp,
    ngx_str_t account_href)
{
    json_settings js;
    json_value *jv, *v, *el, *prop;
    unsigned int i;
    char json_err[NGX_HTTP_AUTH_STORMPATH_BUF_SIZE];

    if (!resp.len) return NGX_ERROR;

    ngx_sp_json_init_parser_settings(&js, r->pool);
    jv = json_parse_ex(&js, (char *) resp.data, resp.len, json_err);
    if (jv == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "error parsing upstream JSON response: %s", json_err);
        return NGX_ERROR;
    }

    v = ngx_sp_json_get_property(jv, "items");
    if (!v || v->type != json_array) {
        goto invalid_response;
    }

    for (i = 0; i < v->u.array.length; i++) {
        el = v->u.array.values[i];
        if (!el || el->type != json_object) {
            goto invalid_response;
        }
        prop = ngx_sp_json_get_property(el, "href");
        if (!prop || prop->type != json_string) continue;
        if (prop->u.string.length != account_href.len) continue;
        if (ngx_strncmp(prop->u.string.ptr, account_href.data, account_href.len))
            continue;

        json_value_free_ex(&js, jv);
        return NGX_OK;
    }

    /* specified account not found in group response */
    json_value_free_ex(&js, jv);
    return NGX_ERROR;

invalid_response:
    json_value_free_ex(&js, jv);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "upstream sent invalid response: %V", &resp);
    return NGX_ERROR;
}


/* Handler to be executed when request wants a location with stormpath_auth.
 */
static ngx_int_t
ngx_http_auth_stormpath_handler(ngx_http_request_t *r)
{
    ngx_http_request_t             *sr;
    ngx_http_auth_stormpath_ctx_t  *ctx;
    ngx_http_auth_stormpath_conf_t *cf;
    ngx_str_t                       uri, body, str_null = ngx_null_string;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_auth_stormpath_module);

    /* Reject all requests by default is server is not properly configured. */
    if ((cf->app_href.len == 0) || (cf->apikey.len == 0)) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_stormpath_module);

    if (ctx == NULL) {
        /* It's a new request we haven't started handling yet. */

        /* We know we require basic auth from the client. If it's not provided,
         * we can immediately request it and end the handling. */
        if (ngx_http_auth_basic_user(r) == NGX_DECLINED) {
            return ngx_http_auth_stormpath_set_realm(r,
                &strings.realm_stormpath);
        }

        /* The fun starts here. We allocate our per-request context and set up
         * a subrequest that will use our internal Stormpath API upstream to
         * do a login attempt and verify the credentials. */
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_stormpath_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        body = ngx_http_auth_stormpath_encode_user_pass(r,
            r->headers_in.user, r->headers_in.passwd);
        if (body.len == 0) {
            return NGX_ERROR;
        }

        uri = ngx_http_auth_stormpath_build_login_attempt_uri(r, cf->app_uri);
        if (uri.len == 0) {
            return NGX_ERROR;
        }

        sr = ngx_http_auth_stormpath_make_request(&cf->app_href,
            NGX_HTTP_POST, uri, body, r, ctx);
        if (sr == NULL) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    /* If the sub request is still in-flight, ask nginx to invoke us later. */
    if (ctx->in_flight) {
        return NGX_AGAIN;
    }

    if (!ctx->authenticated) {
        /* Subrequest returned 401, meaning our Stormpath API credentials are
         * incorrect, which is a server error (not the client's fault). */
        if (ctx->status == NGX_HTTP_UNAUTHORIZED) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "invalid Stormpath API credentials");

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Subrequest returned 400, meaning the login attempt failed. We set
         * HTTP basic authentication challenge header and we're done here. */
        if (ctx->status == NGX_HTTP_BAD_REQUEST) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "Stormpath login attempt failed");

            return ngx_http_auth_stormpath_set_realm(r,
                &strings.realm_stormpath);
        }

        /* Something unexpected happened, the safest choice is to treat it as
         * server error. */
        if (ctx->status != NGX_HTTP_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth stormpath unexpected status: %d", ctx->status);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Subrequest returned 200 OK, which means the client has successfully
         * authenticated. Now we just need to get the account href from the
         * response. */

        ctx->authenticated = 1;

        ctx->account_href = ngx_sp_parse_login_attempt_response(r,
            ctx->response);
        if (!ctx->account_href.len) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* If there's no need to check for group membership, we're done. */
        if (cf->group_href.len == 0) {
            return NGX_OK;
        }

        /* We need to make another Stormpath API Request to check for group
         * membership. */

        uri = ngx_http_auth_stormpath_build_group_accounts_uri(r,
            cf->group_uri, r->headers_in.user);
        if (uri.len == 0) {
            return NGX_ERROR;
        }

        sr = ngx_http_auth_stormpath_make_request(&cf->group_href,
            NGX_HTTP_GET, uri, str_null, r, ctx);
        if (sr == NULL) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    /* Client has been authenticated and group membership check request has
     * also finished. */

    if (ctx->status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth stormpath group check unexpected status: %d",
                      ctx->status);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Check that our authenticated account's href is in the group. */
    if (ngx_sp_parse_group_accounts_response(r, ctx->response,
            ctx->account_href) == NGX_OK) {
        return NGX_OK;
    }

    /* Group check was made and account wasn't in it, deny auth. */
    return ngx_http_auth_stormpath_set_realm(r, &strings.realm_stormpath);
}


/* Build a URI for login attempt against a Stormpath application. */
ngx_str_t
ngx_http_auth_stormpath_build_login_attempt_uri(ngx_http_request_t *r,
    ngx_str_t app_uri)
{
    ngx_str_t uri, err = ngx_null_string;

    uri.len = app_uri.len + sizeof("/loginAttempts") - 1;
    uri.data = ngx_pnalloc(r->pool, uri.len);
    if (uri.data == NULL) {
        return err;
    }

    ngx_snprintf(uri.data, uri.len, "%V/loginAttempts", &app_uri);
    return uri;
}


/* Build a URI for checking whether account is in the group. The check is
 * made by doing a filter on the group accounts collection resource, filtering
 * by username. We cheat here and append the query string directly in the
 * URI instead of putting it in the request args, but we know we can do that
 * because we're outputting the request manually later via
 * http_auth_stormpath_create_request anyways. */
ngx_str_t
ngx_http_auth_stormpath_build_group_accounts_uri(ngx_http_request_t *r,
    ngx_str_t group_uri, ngx_str_t username)
{
    ngx_str_t uri, eusr, err = ngx_null_string;
    u_char *p;

    eusr.data = ngx_pnalloc(r->pool, username.len * 3);
    if (eusr.data == NULL) {
        return err;
    }

    p = (u_char *) ngx_escape_uri(eusr.data, username.data, username.len, 0);
    eusr.len = p - eusr.data;

    uri.len = group_uri.len + sizeof("/accounts?username=") - 1 + eusr.len;
    uri.data = ngx_pnalloc(r->pool, uri.len);
    if (uri.data == NULL) {
        return err;
    }

    ngx_snprintf(uri.data, uri.len, "%V/accounts?username=%V",
        &group_uri, &eusr);

    return uri;
}


/* Build and issue the request to the Stormpath API. In contrast to
 * http_auth_stormpath_create_request, which takes care of speaking with the
 * upstream, this function takes care of actually setting up the
 * ngx_http_request_t structure and filling it up with the URI,
 * request body and other per-request variables.
 */
ngx_http_request_t *
ngx_http_auth_stormpath_make_request(ngx_str_t *href, ngx_uint_t method,
    ngx_str_t uri, ngx_str_t body, ngx_http_request_t *parent,
    ngx_http_auth_stormpath_ctx_t *ctx)
{
    ngx_http_post_subrequest_t     *ps;
    ngx_http_request_t             *sr;
    ngx_buf_t                      *b;
    ngx_http_upstream_t            *u;
    ngx_http_auth_stormpath_conf_t *cf;

    cf = ngx_http_get_module_loc_conf(parent, ngx_http_auth_stormpath_module);

    ps = ngx_palloc(parent->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NULL;
    }

    ps->handler = ngx_http_auth_stormpath_done;
    ps->data = ctx;

    if (ngx_http_subrequest(parent, href, NULL, &sr, ps, 0)
        != NGX_OK)
    {
        return NULL;
    }

    sr->method = method;
    sr->header_only = 0;

    sr->request_body = ngx_pcalloc(parent->pool,
        sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        return NULL;
    }

    b = ngx_calloc_buf(parent->pool);
    if (b == NULL) {
        return NULL;
    }

    b->start = b->pos = body.data;
    b->end = b->last = body.data + body.len;

    sr->headers_in.content_length_n = body.len;

    b->temporary = 1;

    sr->request_body->bufs = ngx_alloc_chain_link(parent->pool);
    if (sr->request_body->bufs == NULL) {
        return NULL;
    }

    sr->request_body->bufs->buf = b;
    sr->request_body->bufs->next = NULL;
    sr->request_body->buf = b;

    sr->header_in = parent->header_in;
    sr->internal = 1;
    sr->uri = uri;

    ctx->subrequest = sr;

    ngx_http_set_ctx(parent, ctx, ngx_http_auth_stormpath_module);

    /* We create the Stormpath API upstream internally instead of asking the
     * user to set it up in the config file. */
    if (ngx_http_upstream_create(sr) != NGX_OK) {
        return NULL;
    }

    u = sr->upstream;
    u->output.tag = (ngx_buf_tag_t) &ngx_http_auth_stormpath_module;
    u->conf = &cf->upstream;
    u->ssl = 1;

    u->create_request = ngx_http_auth_stormpath_create_request;
    u->reinit_request = ngx_http_auth_stormpath_reinit_request;
    u->process_header = ngx_http_auth_stormpath_process_status_line;
    u->abort_request = ngx_http_auth_stormpath_abort_request;
    u->finalize_request = ngx_http_auth_stormpath_finalize_request;
    u->input_filter_init = ngx_http_auth_stormpath_filter_init;
    u->input_filter = ngx_http_auth_stormpath_input_filter;
    u->input_filter_ctx = sr;

    sr->upstream = u;

    ngx_http_upstream_init(sr);

    if (ctx->response.data) {
        ctx->response.data = NULL;
        ctx->response.len = 0;
    }

    ctx->chunked.state = 0;
    ctx->chunked.size = 0;
    ctx->in_flight = 1;
    return sr;
}


/* When the subrequest is done, we mark it as such and pluck out the response
 * status from the response. For now that's all we need to figure out the
 * status of the login attempt. */
static ngx_int_t
ngx_http_auth_stormpath_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_auth_stormpath_ctx_t *ctx = data;

    ctx->in_flight = 0;
    ctx->status = r->headers_out.status;

    return rc;
}


static void *
ngx_http_auth_stormpath_create_conf(ngx_conf_t *cf)
{
    ngx_http_auth_stormpath_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_stormpath_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_auth_stormpath_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_stormpath_conf_t *prev = parent;
    ngx_http_auth_stormpath_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->app_href, prev->app_href, "");
    ngx_conf_merge_str_value(conf->apikey, prev->apikey, "");

    return NGX_CONF_OK;
}


/* Initialize the stormpath module and add our handler to the list of nginx
 * access handlers (so that it'll be invoked to figure out whether access to
 * a location is permitted). */
static ngx_int_t
ngx_http_auth_stormpath_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_stormpath_handler;

    return NGX_OK;
}


/* Parse 'auth_stormpath' directive in the config file. The directive takes
 * only one parameter, a full href of the application to authenticate against.
 * The parser verifies the prefix is correct Stormpath API URL, and then
 * creates an upstream configuration pointing to the Stormpath API, which
 * the subrequests will later use to authenticate against this app.
 */
static char *
ngx_http_auth_stormpath(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char  *prefix = (u_char *) NGX_HTTP_AUTH_STORMPATH_API_PREFIX;
    size_t   prefix_len = sizeof(NGX_HTTP_AUTH_STORMPATH_API_PREFIX) - 1;

    ngx_http_auth_stormpath_conf_t *ascf = conf;
    ngx_str_t                      *value;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;
    ngx_http_upstream_server_t     *s;
    ngx_url_t                       u;
    ngx_pool_cleanup_t  *cln;

    if (ascf->app_href.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        ascf->app_href.len = 0;
        ascf->app_href.data = (u_char *) "";

        return NGX_CONF_OK;
    }

    if (value[1].len < prefix_len) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid application href \"%V\"", &(value[1]));
        return NGX_CONF_ERROR;
    }
    if (ngx_strncmp(prefix, value[1].data, prefix_len)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid application href \"%V\"", &(value[1]));
        return NGX_CONF_ERROR;
    }

    ascf->app_href = value[1];
    ascf->app_uri.len = ascf->app_href.len - prefix_len;
    ascf->app_uri.data = ngx_pcalloc(cf->pool, ascf->app_uri.len);
    (void) ngx_copy(ascf->app_uri.data, ascf->app_href.data + prefix_len,
        ascf->app_uri.len);

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    uscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_srv_conf_t));
    if (uscf == NULL) {
        return NGX_CONF_ERROR;
    }

    uscf->flags = 0;
    uscf->host = ascf->app_href;
    uscf->file_name = cf->conf_file->file.name.data;
    uscf->line = cf->conf_file->line;
    uscf->port = 443;
    uscf->default_port = 443;
    uscf->no_port = 0;

    uscfp = ngx_array_push(&umcf->upstreams);
    if (uscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *uscfp = uscf;

    uscf->servers = ngx_array_create(cf->pool, 1,
        sizeof(ngx_http_upstream_server_t));
    if (uscf->servers == NULL) {
        return NGX_CONF_ERROR;
    }

    s = ngx_array_push(uscf->servers);
    if (s == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = strings.api_stormpath_com;
    u.default_port = 443;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "%s in stormpath \"%V\"", u.err, &u.url);
        return NGX_CONF_ERROR;
    }

    s->name = ascf->app_href;
    s->addrs = u.addrs;
    s->naddrs = u.naddrs;
    s->weight = 1;
    s->max_fails = 1;
    s->fail_timeout = 10;
    s->down = 0;
    s->backup = 0;

    ascf->upstream.upstream = uscf;
    ascf->upstream.timeout = 10000;
    ascf->upstream.connect_timeout = 10000;
    ascf->upstream.send_timeout = 10000;
    ascf->upstream.read_timeout = 10000;
    ascf->upstream.pass_request_headers = 1;
    ascf->upstream.pass_request_body = 1;
    ascf->upstream.buffer_size = ngx_pagesize;

    ascf->upstream.ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (ascf->upstream.ssl == NULL) {
        return NGX_CONF_ERROR;
    }

    ascf->upstream.ssl->log = cf->log;

    if (ngx_ssl_create(ascf->upstream.ssl, NGX_SSL_TLSv1, NULL)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = ascf->upstream.ssl;

    return NGX_CONF_OK;

}


/* Parse 'auth_stormpath_require_group' directive in the config file.
 * The directive takes one parameter, a full href of the group to check
 * for membership.
 */
static char *
ngx_http_auth_stormpath_require_group(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    u_char  *prefix = (u_char *) NGX_HTTP_AUTH_STORMPATH_API_PREFIX;
    size_t   prefix_len = sizeof(NGX_HTTP_AUTH_STORMPATH_API_PREFIX) - 1;

    ngx_http_auth_stormpath_conf_t *ascf = conf;
    ngx_str_t                      *value;

    if (ascf->group_href.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        ascf->group_href.len = 0;
        ascf->group_href.data = (u_char *) "";

        return NGX_CONF_OK;
    }

    if (value[1].len < prefix_len) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid group href \"%V\"", &(value[1]));
        return NGX_CONF_ERROR;
    }
    if (ngx_strncmp(prefix, value[1].data, prefix_len)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid group href \"%V\"", &(value[1]));
        return NGX_CONF_ERROR;
    }

    ascf->group_href = value[1];
    ascf->group_uri.len = ascf->group_href.len - prefix_len;
    ascf->group_uri.data = ngx_pcalloc(cf->pool, ascf->group_uri.len);
    (void) ngx_copy(ascf->group_uri.data, ascf->group_href.data + prefix_len,
        ascf->group_uri.len);

    return NGX_CONF_OK;
}


/* Encode the Stormpath API credentials so they can be easily used in the
 * subrequests to the API. This is virtually identical to
 * ngx_http_auth_stormpath_encode_user_pass but uses different memory
 * allocation mechanism (config pool vs request pool) so can't be the same. */
static ngx_str_t
ngx_http_auth_stormpath_encode_conf_id_secret(ngx_conf_t *cf,
    ngx_str_t id, ngx_str_t secret)
{
    ngx_str_t txt, enc, err = ngx_null_string;

    txt.len = id.len + 1 + secret.len;
    txt.data = ngx_pnalloc(cf->pool, txt.len);
    if (txt.data == NULL) {
        return err;
    }
    ngx_snprintf(txt.data, txt.len, "%V:%V", &id, &secret);

    enc.len = txt.len * 2;
    enc.data = ngx_pnalloc(cf->pool, enc.len);
    if (enc.data == NULL) {
        return err;
    }

    ngx_encode_base64(&enc, &txt);

    return enc;
}


/* Parser for Java properties file format, simplified as in use by Stormpath
 * for API key and secret.
 * http://docs.oracle.com/cd/E23095_01/Platform.93/ATGProgGuide/html/s0204propertiesfileformat01.html
 * Notably, it doesn't support quoting (backslashes) and line continuation.
 */
static char *
parse_apikey_file(ngx_conf_t *cf, u_char *p, ngx_str_t *id, ngx_str_t *secret)
{
    u_char    *key;
    u_char    *value;
    ngx_str_t *str;

    id->len = 0;
    secret->len = 0;

    while (*p) {
        key = NULL;
        value = NULL;

        /* skip leading spaces */
        while ((*p == '\n') || (*p == '\r') || (*p == ' ') || (*p == '\t')) p++;
        /* if it's a comment, skip to the end of the line */
        if ((*p == '#') || (*p == '!')) {
            while ((*p != '\n') && (*p != '\r') && (*p != '\0')) p++;
        }
        /* if the line is empty or comment, skip the line */
        if ((*p == '\n') || (*p == '\r')) {
            p++;
            continue;
        }

        /* scan the key portion */
        key = p;
        while ((*p != ' ') && (*p != '=') && (*p != ':') && (*p != '\0')) p++;
        if (*p == '\0') break;

        /* terminate the key portion and scan over the syntax */
        *p++ = '\0';
        while ((*p == ' ') || (*p == '=') || (*p == ':')) p++;

        /* scan the value portion */
        value = p;
        while ((*p != ' ') && (*p != '\r') && (*p != '\n') && (*p != '\0')) p++;
        /* got the key/value pair, handle it and either finish or iterate */
        if (*p != '\0') {
            *p++ = '\0';
        }

        if (!ngx_strcasecmp(key, (u_char *) "apiKey.id")) {
            str = id;
        } else if (!ngx_strcasecmp(key, (u_char *) "apiKey.secret")) {
            str = secret;
        } else {
            continue;
        }

        str->len = ngx_strlen(value);
        str->data = ngx_pnalloc(cf->pool, str->len);
        if (str->data == NULL) {
            return NGX_CONF_ERROR;
        }
        (void)ngx_copy(str->data, value, str->len);
    }

    if ((id->len > 0) && (secret->len) > 0) {
        return NGX_CONF_OK;
    } else {
        return "apiKey id or secret not found in properties file";
    }
}


/* Parse 'auth_stormpath_apikey' directive in the config file. The directive
 * takes one parameter, a path to .properties file containing Stormpath API
 * credentials (ID and secret).
 */
static char *
ngx_http_auth_stormpath_apikey(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_auth_stormpath_conf_t *ascf = conf;
    ngx_str_t                      *value;
    ngx_fd_t                        fd;
    ngx_file_t                      file;
    u_char                          buf[NGX_HTTP_AUTH_STORMPATH_BUF_SIZE];
    ssize_t                         n;
    ngx_str_t                       id, secret;

    if (ascf->apikey.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    fd = ngx_open_file(value[1].data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        return "Stormpath API properties file open failed";
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd = fd;
    file.name = value[1];

    n = ngx_read_file(&file, buf, NGX_HTTP_AUTH_STORMPATH_BUF_SIZE, 0);
    if (n == NGX_ERROR) {
        ngx_close_file(fd);
    }

    parse_apikey_file(cf, buf, &id, &secret);

    ascf->apikey = ngx_http_auth_stormpath_encode_conf_id_secret(cf,
        id, secret);

    return NGX_CONF_OK;
}
