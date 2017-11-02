#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    in_addr_t         mask;
    in_addr_t         addr;
} ngx_http_allow_region_rule_t;

#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr   addr;
    struct in6_addr   mask;
} ngx_http_allow_region_rule6_t;

#endif

typedef struct {
    ngx_array_t	                *rules;          /* array of ngx_http_allow_region_rule_t */
    ngx_array_t                 *rules_cust;     /* array of ngx_http_allow_region_rule_t */
    ngx_flag_t  enable;
#if (NGX_HAVE_INET6)
    ngx_array_t                 *rules6;         /* array of ngx_http_allow_region_rule6_t */
    ngx_array_t                 *rules6_cust;    /* array of ngx_http_allow_region_rule6_t */
#endif
} ngx_http_allow_region_loc_conf_t;

static ngx_int_t ngx_http_allow_region_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_allow_region_inet(ngx_http_request_t *r,
    ngx_http_allow_region_loc_conf_t *alcf, in_addr_t addr);
static char *ngx_http_allow_region_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_allow_region_inet6(ngx_http_request_t *r,
    ngx_http_allow_region_loc_conf_t *alcf, u_char *p);
static void *ngx_http_allow_region_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_allow_region_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_allow_region_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_allow_region_handler(ngx_http_request_t *r);


static ngx_command_t  ngx_http_allow_region_commands[] = {

    { ngx_string("allow_jp"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_allow_region_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("custom_allow_jp"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_allow_region_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("region_check"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_allow_region_loc_conf_t, enable),
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_allow_region_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_allow_region_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_allow_region_create_loc_conf, /* create location configuration */
    ngx_http_allow_region_merge_loc_conf   /* merge location configuration */
};

ngx_module_t  ngx_http_allow_region_module = {
    NGX_MODULE_V1,
    &ngx_http_allow_region_module_ctx,     /* module context */
    ngx_http_allow_region_commands,        /* module directives */
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

static ngx_int_t
ngx_http_allow_region_handler(ngx_http_request_t *r)
{
    struct sockaddr_in          *sin;
    ngx_http_allow_region_loc_conf_t  *alcf;
#if (NGX_HAVE_INET6)
    u_char                      *p;
    in_addr_t                    addr;
    struct sockaddr_in6         *sin6;
#endif

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_allow_region_module);

    if (alcf->enable != 1) {
        return NGX_DECLINED;
    }

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        if (alcf->rules || alcf->rules_cust) {
            sin = (struct sockaddr_in *) r->connection->sockaddr;
            return ngx_http_allow_region_inet(r, alcf, sin->sin_addr.s_addr);
        }
        break;

#if (NGX_HAVE_INET6)

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        p = sin6->sin6_addr.s6_addr;

        if (alcf->rules && IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            addr = p[12] << 24;
            addr += p[13] << 16;
            addr += p[14] << 8;
            addr += p[15];
            return ngx_http_allow_region_inet(r, alcf, htonl(addr));
        }

        if (alcf->rules6 || alcf->rules6_cust) {
            return ngx_http_allow_region_inet6(r, alcf, p);
        }

#endif
    }

    return NGX_HTTP_FORBIDDEN;
}


static ngx_int_t
ngx_http_allow_region_inet(ngx_http_request_t *r, ngx_http_allow_region_loc_conf_t *alcf,
    in_addr_t addr)
{
    ngx_uint_t                    i;
    ngx_http_allow_region_rule_t  *rule;
    ngx_http_allow_region_rule_t  *rule_cust;

    if (alcf->rules){
        rule = alcf->rules->elts;
        for (i = 0; i < alcf->rules->nelts; i++) {
            if ((addr & rule[i].mask) == rule[i].addr) {
                return NGX_DECLINED;
            }
        }
    }

    if (alcf->rules_cust) {
        rule_cust = alcf->rules_cust->elts;
        for (i = 0; i < alcf->rules_cust->nelts; i++) {
            if (( addr & rule_cust[i].mask) == rule_cust[i].addr) {
                return NGX_DECLINED;
            }
        }
    }

    return NGX_HTTP_FORBIDDEN;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_http_allow_region_inet6(ngx_http_request_t *r, ngx_http_allow_region_loc_conf_t *alcf,
    u_char *p)
{
    ngx_uint_t                n;
    ngx_uint_t                i;
    ngx_http_allow_region_rule6_t  *rule6;
    ngx_http_allow_region_rule6_t  *rule6_cust;

    if (alcf->rules6) {
        rule6 = alcf->rules6->elts;
        for (i = 0; i < alcf->rules6->nelts; i++) {
            for (n = 0; n < 16; n++) {
                if ((p[n] & rule6[i].mask.s6_addr[n]) != rule6[i].addr.s6_addr[n]) {
                    goto next;
                }
            }
    
            return NGX_DECLINED;
    
        next:
            continue;
        }
    }
    if (alcf->rules6_cust) {
        rule6_cust = alcf->rules6_cust->elts;
        for (i = 0; i < alcf->rules6_cust->nelts; i++) {
            for (n = 0; n < 16; n++) {
                if ((p[n] & rule6_cust[i].mask.s6_addr[n]) != rule6_cust[i].addr.s6_addr[n]) {
                    goto next2;
                }
            }

            return NGX_DECLINED;

        next2:
            continue;
        }
    }
    return NGX_HTTP_FORBIDDEN;
}

#endif

static char *
ngx_http_allow_region_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_allow_region_loc_conf_t *alcf = conf;

    ngx_int_t                         rc;
    ngx_uint_t                        all;
    ngx_str_t                         *value;
    ngx_cidr_t                        cidr;
    ngx_http_allow_region_rule_t      *rule;
    ngx_http_allow_region_rule_t      *rule_cust;
#if (NGX_HAVE_INET6)
    ngx_http_allow_region_rule6_t     *rule6;
    ngx_http_allow_region_rule6_t     *rule6_cust;
#endif

    all = 0;
    ngx_memzero(&cidr, sizeof(ngx_cidr_t));

    value = cf->args->elts;

    if (value[1].len == 3 && ngx_strcmp(value[1].data, "all") == 0) {
        all = 1;

    } else {
        rc = ngx_ptocidr(&value[1], &cidr);

        if (rc == NGX_ERROR) {
             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "invalid parameter \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                         "low address bits of %V are meaningless", &value[1]);
        }
    }

    if (cidr.family == AF_INET || all) {
        if (value[0].len == 15 && ngx_strcmp(value[0].data, "custom_allow_jp") == 0) {
            if (alcf->rules_cust == NULL) {
                alcf->rules_cust = ngx_array_create(cf->pool, 4,
                                               sizeof(ngx_http_allow_region_rule_t));
                if (alcf->rules_cust == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            rule_cust = ngx_array_push(alcf->rules_cust);
            if (rule_cust == NULL) {
                return NGX_CONF_ERROR;
            }

            rule_cust->mask = cidr.u.in.mask;
            rule_cust->addr = cidr.u.in.addr;
        } else {
            if (alcf->rules == NULL) {
                alcf->rules = ngx_array_create(cf->pool, 4,
                                               sizeof(ngx_http_allow_region_rule_t));
                if (alcf->rules == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            rule = ngx_array_push(alcf->rules);
            if (rule == NULL) {
                return NGX_CONF_ERROR;
            }

            rule->mask = cidr.u.in.mask;
            rule->addr = cidr.u.in.addr;
        }
    }

#if (NGX_HAVE_INET6)
    if (cidr.family == AF_INET6 || all) {
        if (value[0].len == 15 && ngx_strcmp(value[0].data, "custom_allow_jp") == 0) {
            if (alcf->rules6_cust == NULL) {
                alcf->rules6_cust = ngx_array_create(cf->pool, 4,
                                                sizeof(ngx_http_allow_region_rule6_t));
                if (alcf->rules6_cust == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            rule6_cust = ngx_array_push(alcf->rules6_cust);
            if (rule6_cust == NULL) {
                return NGX_CONF_ERROR;
            }

            rule6_cust->mask = cidr.u.in6.mask;
            rule6_cust->addr = cidr.u.in6.addr;
        }else{
            if (alcf->rules6 == NULL) {
                alcf->rules6 = ngx_array_create(cf->pool, 4,
                                                sizeof(ngx_http_allow_region_rule6_t));
                if (alcf->rules6 == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            rule6 = ngx_array_push(alcf->rules6);
            if (rule6 == NULL) {
                return NGX_CONF_ERROR;
            }

            rule6->mask = cidr.u.in6.mask;
            rule6->addr = cidr.u.in6.addr;
        }
    }
#endif

    return NGX_CONF_OK;
}

static void *
ngx_http_allow_region_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_allow_region_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_allow_region_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->enable = NGX_CONF_UNSET;
    return conf;
}


static char *
ngx_http_allow_region_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_allow_region_loc_conf_t  *prev = parent;
    ngx_http_allow_region_loc_conf_t  *conf = child;

#if (NGX_HAVE_INET6)
    if (conf->rules6 == NULL) {
        conf->rules6 = prev->rules6;
    }
    if (conf->rules6_cust == NULL) {
        conf->rules6_cust = prev->rules6_cust;
    }
#endif
    if (conf->rules == NULL) {
        conf->rules = prev->rules;
    }
    if (conf->rules_cust == NULL) {
        conf->rules_cust = prev->rules_cust;
    }

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_allow_region_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_allow_region_handler;

    return NGX_OK;
}
