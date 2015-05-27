
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Stormpath, Inc.
 */


#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t                 app_href;
    ngx_str_t                 apikey;
} ngx_http_auth_stormpath_conf_t;


typedef struct {
    ngx_uint_t                done;
    ngx_uint_t                status;
    ngx_http_request_t       *subrequest;
} ngx_http_auth_stormpath_ctx_t;

static struct {
    ngx_str_t http_method_post;
    ngx_str_t content_type;
    ngx_str_t application_json;
    ngx_str_t accept;
    ngx_str_t user_agent;
    ngx_str_t user_agent_value;
    ngx_str_t content_length;
    ngx_str_t host;
    ngx_str_t api_stormpath_com;
    ngx_str_t realm_stormpath;
    ngx_str_t authorization;
} strings = {
    { 4, (u_char *) "POST " }, // nginx deliberately offs-by-one here
    ngx_string("Content-Type"),
    ngx_string("application/json"),
    ngx_string("Accept"),
    ngx_string("User-Agent"),
    ngx_string("stormpath-nginx/alpha (" NGINX_VER ")"),
    ngx_string("Content-Length"),
    ngx_string("Host"),
    ngx_string("api.stormpath.com"),
    ngx_string("Protected by Stormpath"),
    ngx_string("Authorization")
};


static ngx_int_t ngx_http_auth_stormpath_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_stormpath_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc);
static void *ngx_http_auth_stormpath_create_conf(ngx_conf_t *cf);
static char *ngx_http_auth_stormpath_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_auth_stormpath_init(ngx_conf_t *cf);
static char *ngx_http_auth_stormpath(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_auth_stormpath_apikey(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_auth_stormpath_commands[] = {

    { ngx_string("auth_stormpath"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_stormpath,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_stormpath_conf_t, app_href),
      NULL },

    { ngx_string("auth_stormpath_apikey"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
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


static ngx_table_elt_t *
ngx_http_auth_stormpath_add_header(ngx_http_request_t *r,
    ngx_str_t key, ngx_str_t value)
{
    ngx_table_elt_t *h;
    u_char *p;

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NULL;
    }

    h->key = key;
    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NULL;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    p = ngx_pnalloc(r->pool, value.len);
    if (p == NULL) {
        return NULL;
    }

    ngx_memcpy(p, value.data, value.len);

    h->value.data = p;
    h->value.len = value.len;

    return h;
}

static ngx_table_elt_t *
ngx_http_auth_stormpath_add_content_length_header(ngx_http_request_t *r,
    u_char *data)
{
    u_char *p;
    ngx_str_t val;

    p = ngx_palloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        return NULL;
    }

    ngx_sprintf(p, "%z", ngx_strlen(data));

    val.data = p;
    val.len = ngx_strlen(p);

    return ngx_http_auth_stormpath_add_header(r, strings.content_length, val);
}

/* this is directly copied from ngx_http_auth_stormpath_set_realm, too
 * bad it isn't originally exposed */
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


static ngx_str_t
ngx_http_auth_stormpath_encode_user_pass(ngx_http_request_t *r,
    ngx_str_t user, ngx_str_t pass)
{
    ngx_str_t txt, enc, err = ngx_null_string;

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

    return enc;
}


static ngx_int_t
ngx_http_auth_stormpath_handler(ngx_http_request_t *r)
{
    ngx_table_elt_t                *h;
    ngx_http_request_t             *sr;
    ngx_http_post_subrequest_t     *ps;
    ngx_http_auth_stormpath_ctx_t  *ctx;
    ngx_http_auth_stormpath_conf_t *cf;
    ngx_buf_t                      *b;
    u_char                         *auth_data;
    ngx_str_t encoded_userpwd;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_auth_stormpath_module);

    if ((cf->app_href.len == 0) || (cf->apikey.len == 0)) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_stormpath_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return NGX_AGAIN;
        }

        if (ctx->status == NGX_HTTP_OK)
        {
            return NGX_OK;
        }

        if (ctx->status == NGX_HTTP_UNAUTHORIZED) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "invalid Stormpath API credentials");

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ctx->status == NGX_HTTP_BAD_REQUEST) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "Stormpath login attempt failed");

            return ngx_http_auth_stormpath_set_realm(r, &strings.realm_stormpath);
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth stormpath unexpected status: %d", ctx->status);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_auth_basic_user(r) == NGX_DECLINED) {
        return ngx_http_auth_stormpath_set_realm(r, &strings.realm_stormpath);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_stormpath_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_http_auth_stormpath_done;
    ps->data = ctx;

    if (ngx_http_subrequest(r, &cf->app_href, NULL, &sr, ps, 0)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    sr->method = NGX_HTTP_POST;
    sr->method_name = strings.http_method_post;
    sr->header_only = 1;

    /* init subrequest headers */
    if (ngx_list_init(&sr->headers_in.headers, sr->pool, 20,
            sizeof(ngx_table_elt_t)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    h = ngx_http_auth_stormpath_add_header(sr, strings.content_type,
        strings.application_json);
    if (h == NULL) {
        return NGX_ERROR;
    }
    sr->headers_in.content_type = h;

    h = ngx_http_auth_stormpath_add_header(sr, strings.accept,
        strings.application_json);
    if (h == NULL) {
        return NGX_ERROR;
    }
#if (NGX_HTTP_HEADERS)
    sr->headers_in.accept = h;
#endif

    h = ngx_http_auth_stormpath_add_header(sr, strings.user_agent,
        strings.user_agent_value);
    if (h == NULL) {
        return NGX_ERROR;
    }
    sr->headers_in.user_agent = h;

    h = ngx_http_auth_stormpath_add_header(sr, strings.host,
        strings.api_stormpath_com);
    if (h == NULL) {
        return NGX_ERROR;
    }
    sr->headers_in.host = h;

    h = ngx_http_auth_stormpath_add_header(sr, strings.authorization,
        cf->apikey);
    if (h == NULL) {
        return NGX_ERROR;
    }
    sr->headers_in.authorization = h;

    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        return NGX_ERROR;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    encoded_userpwd = ngx_http_auth_stormpath_encode_user_pass(sr,
        r->headers_in.user, r->headers_in.passwd);
    if (encoded_userpwd.len == 0) {
        return NGX_ERROR;
    }

    auth_data = ngx_pcalloc(r->pool, 8192);
    ngx_sprintf(auth_data, "{\"type\": \"basic\", \"value\": \"%V\"}",
        &encoded_userpwd);

    h = ngx_http_auth_stormpath_add_content_length_header(sr,
        auth_data);
    if (h == NULL) {
        return NGX_ERROR;
    }
    sr->headers_in.content_length = h;
    sr->headers_in.content_length_n = ngx_strlen(auth_data);

    b->temporary = 1;
    b->start = b->pos = auth_data;
    b->end = b->last = auth_data + ngx_strlen(auth_data);

    sr->request_body->bufs = ngx_alloc_chain_link(r->pool);
    if (sr->request_body->bufs == NULL) {
        return NGX_ERROR;
    }

    sr->request_body->bufs->buf = b;
    sr->request_body->bufs->next = NULL;
    sr->request_body->buf = b;

    sr->header_in = r->header_in;
    sr->internal = 1;

    /* XXX work-around a bug in ngx_http_subrequest */

    if (r->headers_in.headers.last == &r->headers_in.headers.part) {
        sr->headers_in.headers.last = &sr->headers_in.headers.part;
    }
    ctx->subrequest = sr;

    ngx_http_set_ctx(r, ctx, ngx_http_auth_stormpath_module);

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_auth_stormpath_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_auth_stormpath_ctx_t   *ctx = data;

    ngx_log_debug1(NGX_LOG_ERR, r->connection->log, 0,
                   "Stormpath API request done s:%d", r->headers_out.status);

    ctx->done = 1;
    ctx->status = r->headers_out.status;

    return rc;
}


static void *
ngx_http_auth_stormpath_create_conf(ngx_conf_t *cf)
{
    ngx_http_auth_stormpath_conf_t  *conf;

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

static char *
ngx_http_auth_stormpath(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_stormpath_conf_t *ascf = conf;
    ngx_str_t                      *value;

    if (ascf->app_href.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        ascf->app_href.len = 0;
        ascf->app_href.data = (u_char *) "";

        return NGX_CONF_OK;
    }

    ascf->app_href = value[1];

    return NGX_CONF_OK;
}

static ngx_str_t
ngx_http_auth_stormpath_encode_conf_id_secret(ngx_conf_t *cf,
    ngx_str_t id, ngx_str_t secret)
{
    ngx_str_t txt, enc, err = ngx_null_string;
    u_char *p;

    txt.len = id.len + 1 + secret.len;
    txt.data = ngx_pnalloc(cf->pool, txt.len);
    if (txt.data == NULL) {
        return err;
    }
    ngx_snprintf(txt.data, txt.len, "%V:%V", &id, &secret);

    enc.len = 6 + txt.len * 2;
    enc.data = ngx_pnalloc(cf->pool, enc.len);
    if (enc.data == NULL) {
        return err;
    }

    ngx_memcpy(enc.data, "Basic ", 6);
    p = enc.data;
    enc.data += 6;
    enc.len -= 6;

    ngx_encode_base64(&enc, &txt);

    enc.data = p;
    enc.len += 6;

    return enc;
}

static char *
ngx_http_auth_stormpath_apikey(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_auth_stormpath_conf_t *ascf = conf;
    ngx_str_t                      *value;

    if (ascf->apikey.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ascf->apikey = ngx_http_auth_stormpath_encode_conf_id_secret(cf,
        value[1], value[2]);

    return NGX_CONF_OK;
}
