#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jwt.h>

#define NGX_HTTP_AUTH_JWT_DISABLED  -1
#define NGX_HTTP_AUTH_JWT_ENABLED    1
#define NGX_HTTP_AUTH_JWT_TOKEN      2

static ngx_int_t
ngx_http_auth_jwt_init(ngx_conf_t *cf);
static void *
ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf);
static char *
ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *
ngx_http_auth_jwt_auth_jwt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_http_auth_jwt_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_auth_jwt_set_realm(ngx_http_request_t *r, ngx_str_t *realm);
static char *
ngx_http_auth_jwt_key_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// Declare a struct to hold configurations
typedef struct {
  ssize_t    active;
  ngx_str_t  realm;
  ngx_str_t  key;
  ngx_uint_t jwt_algorithm;
  ngx_int_t  variable_index;
} ngx_http_auth_jwt_loc_conf_t;

// enum of all algorithms
static ngx_conf_enum_t ngx_http_jwt_algorithms[] = {
  { ngx_string("none"),  JWT_ALG_NONE  },
  { ngx_string("HS256"), JWT_ALG_HS256 },
  { ngx_string("HS384"), JWT_ALG_HS384 },
  { ngx_string("HS512"), JWT_ALG_HS512 },
  { ngx_string("RS256"), JWT_ALG_RS256 },
  { ngx_string("RS384"), JWT_ALG_RS384 },
  { ngx_string("RS512"), JWT_ALG_RS512 },
  { ngx_string("ES256"), JWT_ALG_ES256 },
  { ngx_string("ES384"), JWT_ALG_ES384 },
  { ngx_string("ES512"), JWT_ALG_ES512 },
  { ngx_null_string, 0 }
};


// Definition for the directive
static ngx_command_t ngx_http_auth_jwt_commands[] = {

  { ngx_string("auth_jwt"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
    ngx_http_auth_jwt_auth_jwt,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },

  { ngx_string("auth_jwt_key_file"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_auth_jwt_key_file,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },

  { ngx_string("auth_jwt_alg"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_enum_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_jwt_loc_conf_t, jwt_algorithm),
    &ngx_http_jwt_algorithms },

  ngx_null_command
};

// Context for the module
static ngx_http_module_t ngx_http_auth_jwt_module_ctx = {
  NULL,                                   /* preconfiguration */
  ngx_http_auth_jwt_init,                 /* postconfiguration */

  NULL,                                   /* create main configuration */
  NULL,                                   /* init main configuration */

  NULL,                                   /* create server configuration */
  NULL,                                   /* merge server configuration */

  ngx_http_auth_jwt_create_loc_conf,      /* create location configuration */
  ngx_http_auth_jwt_merge_loc_conf        /* merge location configuration */
};

// Definition for the module
ngx_module_t ngx_http_auth_jwt_module = {
  NGX_MODULE_V1,
  &ngx_http_auth_jwt_module_ctx,    /* module context */
  ngx_http_auth_jwt_commands,       /* module directives */
  NGX_HTTP_MODULE,                  /* module type */
  NULL,                             /* init master */
  NULL,                             /* init module */
  NULL,                             /* init process */
  NULL,                             /* init thread */
  NULL,                             /* exit thread */
  NULL,                             /* exit process */
  NULL,                             /* exit master */
  NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_auth_jwt_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_auth_jwt_handler;

  return NGX_OK;
}

static void *
ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_auth_jwt_loc_conf_t * conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_jwt_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  // Set by pcalloc:
  // ssize_t    active         = 0;
  // ngx_str_t  realm          = {data = NULL; len = 0;}
  // ngx_str_t  key            = {data = NULL; len = 0;}
  // ngx_uint_t jwt_algorithm  = 0;
  // ngx_int_t  variable_index = 0;

  conf->variable_index = -1;
  conf->jwt_algorithm = NGX_CONF_UNSET_UINT;

  return conf;
}

static char *
ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_auth_jwt_loc_conf_t  *prev = parent;
  ngx_http_auth_jwt_loc_conf_t  *conf = child;

  ngx_conf_merge_str_value(conf->realm, prev->realm, "");
  ngx_conf_merge_str_value(conf->key, prev->key, "");
  ngx_conf_merge_uint_value(conf->jwt_algorithm, prev->jwt_algorithm, JWT_ALG_NONE);

  if (conf->active == 0) {
    conf->active = prev->active;
  }

  if (conf->variable_index == -1) {
    conf->variable_index = prev->variable_index;
  }

  return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_auth_jwt_handler(ngx_http_request_t *r)
{
  ngx_http_auth_jwt_loc_conf_t  *alcf;
  ngx_http_variable_value_t     *v;

  if (r->main->internal) {
    return NGX_DECLINED;
  }

  r->main->internal = 1;

  alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);

  if (alcf->active == 0 || alcf->active == NGX_HTTP_AUTH_JWT_DISABLED) {
    return NGX_DECLINED;
  }

  ngx_str_t jwt = ngx_string("");

  // Retrieve authorization token from header
  if (alcf->active == NGX_HTTP_AUTH_JWT_ENABLED && r->headers_in.authorization) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Authorization header provided");
    if (ngx_strncmp(r->headers_in.authorization->value.data, "Bearer ", 7) == 0) {
      jwt.data = r->headers_in.authorization->value.data + 7;
      jwt.len = r->headers_in.authorization->value.len - 7;
    }
  }

  // Retrieve autorization token from cookie
  if (alcf->active == NGX_HTTP_AUTH_JWT_TOKEN) {
    v = ngx_http_get_indexed_variable(r, alcf->variable_index);
    if (v->not_found) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
          "cookie spedified in configuration was not provided for authentication");

      return ngx_http_auth_jwt_set_realm(r, &alcf->realm);
    }
    jwt.data = v->data;
    jwt.len = v->len;
  }

  if (jwt.len == 0) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "no jwt was provided for authentication");

    return ngx_http_auth_jwt_set_realm(r, &alcf->realm);
  }

  if (alcf->key.len == 0) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "no key to decode jwt was provided");

    return ngx_http_auth_jwt_set_realm(r, &alcf->realm);
  }

  // Do no accept JWT_ALG_NONE as algorithm
  if (alcf->jwt_algorithm == JWT_ALG_NONE) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "no valid algorithm to decode jwt was provided");

    return ngx_http_auth_jwt_set_realm(r, &alcf->realm);
  }

  // the cookie data is not necessarily null terminated... we need a null terminated character pointer
  char *token_data = ngx_pcalloc(r->pool, jwt.len + 1);
  if (token_data == NULL) {
    return NGX_ERROR;
  }
  ngx_memcpy(token_data, jwt.data, jwt.len);

  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "jwt_verify: authorization=%s", token_data);

  jwt_t* token;
  int err = jwt_decode(&token, token_data, alcf->key.data, alcf->key.len);
  if (err) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_verify: error on decode: %s", strerror(errno));
    return ngx_http_auth_jwt_set_realm(r, &alcf->realm);
  }

  if (jwt_get_alg(token) != alcf->jwt_algorithm) {
    jwt_free(token);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_verify: alg not accepted, rejected");
    return ngx_http_auth_jwt_set_realm(r, &alcf->realm);
  }

  // validate the exp date of the JWT
  time_t exp = (time_t)jwt_get_grant_int(token, "exp");
  time_t now = time(NULL);
  if (exp < now)
  {
    jwt_free(token);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                  "jwt_verify: token expired, rejected");
    return ngx_http_auth_jwt_set_realm(r, &alcf->realm);
  }

  return NGX_DECLINED;
}

static ngx_int_t
ngx_http_auth_jwt_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
  size_t   len;
  u_char  *bearer, *p;

  r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
  if (r->headers_out.www_authenticate == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  len = sizeof("Bearer realm=\"\"") - 1 + realm->len;

  bearer = ngx_pnalloc(r->pool, len);
  if (bearer == NULL) {
    r->headers_out.www_authenticate->hash = 0;
    r->headers_out.www_authenticate = NULL;
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  p = ngx_cpymem(bearer, "Bearer realm=\"", sizeof("Bearer realm=\"") - 1);
  p = ngx_cpymem(p, realm->data, realm->len);
  *p = '"';

  r->headers_out.www_authenticate->hash = 1;
  ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
  r->headers_out.www_authenticate->value.data = bearer;
  r->headers_out.www_authenticate->value.len = len;

  return NGX_HTTP_UNAUTHORIZED;
}

// auth_jwt_key_file config directive callback
static char *
ngx_http_auth_jwt_key_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_auth_jwt_loc_conf_t * plcf = conf;
  ngx_str_t *args = cf->args->elts;
  char *key_file = (char *)args[1].data;
  // Determine file size (avoiding fseek)
  struct stat fstat;
  if (stat(key_file, &fstat) < 0) {
    ngx_conf_log_error(NGX_LOG_ERR, cf, errno, strerror(errno));
    return NGX_CONF_ERROR;
  }
  FILE *fp = fopen(key_file, "rb");
  if (fp == NULL) {
    ngx_conf_log_error(NGX_LOG_ERR, cf, errno, strerror(errno));
    return NGX_CONF_ERROR;
  }
  plcf->key.len = fstat.st_size - 1;
  plcf->key.data = calloc(plcf->key.len, 1);
  if (fread(plcf->key.data, 1, plcf->key.len, fp) != plcf->key.len) {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                       "auth_jwt_key_file: unexpected end of file");
    fclose(fp);
    return NGX_CONF_ERROR;
  }
  fclose(fp);
  return NGX_CONF_OK;
}

static char *
ngx_http_auth_jwt_auth_jwt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_auth_jwt_loc_conf_t * plcf = conf;

  ngx_str_t                  *value;

  value = cf->args->elts;

  if (ngx_strcmp(value[1].data, "off") == 0) {
    plcf->active = NGX_HTTP_AUTH_JWT_DISABLED;
    return NGX_CONF_OK;
  }

  // set realm
  plcf->active = NGX_HTTP_AUTH_JWT_ENABLED;
  plcf->realm.data = value[1].data;
  plcf->realm.len = value[1].len;

  if (cf->args->nelts > 2) {

    // check to see if second argument starts with "token="
    if (value[2].len > sizeof("token=") - 1
        && ngx_strncmp(value[2].data, "token=", sizeof("token=") - 1)
        == 0)
    {

      value[2].data = value[2].data + sizeof("token=") - 1;
      value[2].len = value[2].len - (sizeof("token=") - 1);

      // check if second part is a variable
      if (value[2].data[0] != '$') {

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid variable name \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
      }

      plcf->active = NGX_HTTP_AUTH_JWT_TOKEN;
      value[2].data++;
      value[2].len--;

      plcf->variable_index = ngx_http_get_variable_index(cf, &value[2]);
      if (plcf->variable_index == NGX_ERROR) {

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid variable name \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
      }


    } else {

      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
          "invalid optional token argument \"%V\"", &value[2]);
      return NGX_CONF_ERROR;
    }

  }

  return NGX_CONF_OK;
}
