/**
 *  Copyright 2017, ScaleFT Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "apr_strings.h"

#include <curl/curl.h>

#include "xjwt/xjwt.h"

#include "af_types.h"
#include "af_fetch.h"
#include "af_cache.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(auth_accessfabric);
#endif

module AP_MODULE_DECLARE_DATA auth_accessfabric_module;

#define AF_DEFAULT_ISSUER "https://app.scaleft.com"
#define AF_DEFAULT_HEADER "Authenticated-User-JWT"

/* Keys for setting on r->notes  */
#define NOTE_AF_SUB "auth_accessfabric_sub"
#define NOTE_AF_EMAIL "auth_accessfabric_email"

typedef struct tcb_baton_t {
  uint64_t now;
} tcb_baton_t;

static uint64_t tcb(void *baton) { return ((tcb_baton_t *)baton)->now; }

static const char *auth_af_xjwt_reasonstr(XJWT_VERIFY_FAILURES r) {
  switch (r) {
    case XJWT_VERIFY_UNKNOWN:
      return "UNKNOWN";
    case XJWT_VERIFY_NOT_PRESENT:
      return "NOT_PRESENT";
    case XJWT_VERIFY_EXPIRED:
      return "EXPIRED";
    case XJWT_VERIFY_INVALID_SIGNATURE:
      return "INVALID_SIGNATURE";
    case XJWT_VERIFY_NO_VALIDATORS:
      return "NO_VALIDATORS";
    case XJWT_VERIFY_MALFORMED:
      return "MALFORMED";
    case XJWT_VERIFY_EXPECT_MISMATCH:
      return "EXPECT_MISMATCH";
  }
  return "INTERNAL_UNKNOWN";
}

static int auth_af_check_authn(request_rec *r) {
  const char *current_auth;
  auth_af_dir_rec *conf =
      ap_get_module_config(r->per_dir_config, &auth_accessfabric_module);
  auth_af_srv_rec *srv = (auth_af_srv_rec *)ap_get_module_config(
      r->server->module_config, &auth_accessfabric_module);
  int st = HTTP_UNAUTHORIZED;
  apr_status_t rv = APR_SUCCESS;
  const char *jwthdr = NULL;
  auth_af_keyset_t *keyset = NULL;

  current_auth = ap_auth_type(r);
#if AP_MODULE_MAGIC_AT_LEAST(20160608, 1)
  if (!current_auth || ap_cstr_casecmp("accessfabric", current_auth)) {
#else
  if (!current_auth || strcasecmp("accessfabric", current_auth) != 0) {
#endif
    st = DECLINED;
    goto cleanup;
  }

  if (conf->audience == NULL) {
    ap_log_rerror(
        APLOG_MARK, APLOG_ERR, 0, r,
        "AuthAccessFabric: AuthAccessFabricAudience must be set for path: %s",
        r->uri);
    st = HTTP_INTERNAL_SERVER_ERROR;
    goto cleanup;
  }

  rv = auth_af_jwk_cache_get(r, srv, r->pool, conf->trusted_jwks, &keyset);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                  "AuthAccessFabric: Failed to get JWK Cache entry");
    st = HTTP_INTERNAL_SERVER_ERROR;
    goto cleanup;
  }

  jwthdr = apr_table_get(r->headers_in, conf->header);
  if (jwthdr == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "AuthAccessFabric: Empty JWT Request Header: %s",
                  conf->header);
    st = HTTP_UNAUTHORIZED;
    goto cleanup;
  }

  do {
    tcb_baton_t baton = {0};
    xjwt_verify_options_t opts = {0};
    xjwt_verify_failure_t *failed = NULL;
    xjwt_verify_success_t *success = NULL;

    opts.keyset = keyset->keyset;
    opts.expected_issuer = conf->issuer;
    opts.expected_subject = NULL;
    opts.expected_audience = conf->audience;
    opts.now = tcb;
    opts.baton = &baton;
    baton.now = apr_time_sec(apr_time_now());

    xjwt_verify(&opts, jwthdr, strlen(jwthdr), &success, &failed);

    if (success != NULL) {
      json_t *sub = NULL;
      json_t *email = NULL;
      /* json_dumpf(success->payload, stderr, JSON_INDENT(2)); */
      sub = json_object_get(success->payload, "sub");
      if (!json_is_string(sub)) {
        xjwt_verify_success_destroy(success);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "AuthAccessFabric: Payload did not contain sub");
        st = HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
      }

      email = json_object_get(success->payload, "email");
      if (!json_is_string(email)) {
        xjwt_verify_success_destroy(success);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "AuthAccessFabric: Payload did not contain email");
        st = HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
      }

      st = OK;

      r->user = apr_pstrdup(r->pool, json_string_value(email));
      r->ap_auth_type = apr_pstrdup(r->pool, "AccessFabric");

      apr_table_setn(r->notes, NOTE_AF_EMAIL, r->user);
      apr_table_setn(r->notes, NOTE_AF_SUB,
                     apr_pstrdup(r->pool, json_string_value(sub)));

      xjwt_verify_success_destroy(success);

    } else { /* failed != NULL */

      if (failed->err != NULL) {
        ap_log_rerror(
            APLOG_MARK, APLOG_ERR, 0, r,
            "AuthAccessFabric: request validation failed with '%s': (%d) %s",
            auth_af_xjwt_reasonstr(failed->reason), failed->err->err,
            failed->err->msg);
      } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "AuthAccessFabric: request validation failed with '%s'",
                      auth_af_xjwt_reasonstr(failed->reason));
      }
      xjwt_verify_failure_destroy(failed);

      st = HTTP_UNAUTHORIZED;
      goto cleanup;
    }
  } while (0);

cleanup:
  if (keyset != NULL) {
    auth_af_jwk_cache_release(conf->trusted_jwks, keyset);
  }

  return st;
}

static const char *set_af_audience(cmd_parms *cmd, void *config,
                                   const char *audience) {
  auth_af_dir_rec *conf = (auth_af_dir_rec *)config;
  conf->audience = audience;
  return NULL;
}

static const char *set_af_issuer(cmd_parms *cmd, void *config,
                                 const char *issuer) {
  auth_af_dir_rec *conf = (auth_af_dir_rec *)config;
  conf->issuer = issuer;
  return NULL;
}

static const char *set_af_header(cmd_parms *cmd, void *config,
                                 const char *header) {
  auth_af_dir_rec *conf = (auth_af_dir_rec *)config;
  conf->header = header;
  return NULL;
}

static const char *set_af_trusted_jwks(cmd_parms *cmd, void *config,
                                       const char *trusted_jwks) {
  auth_af_dir_rec *conf = (auth_af_dir_rec *)config;
  conf->trusted_jwks = trusted_jwks;
  return NULL;
}

static void *create_dir_conf(apr_pool_t *p, char *d) {
  auth_af_dir_rec *conf = apr_pcalloc(p, sizeof(auth_af_dir_rec));
  conf->audience = NULL;
  conf->issuer = AF_DEFAULT_ISSUER;
  conf->header = AF_DEFAULT_HEADER;
  conf->trusted_jwks = "scaleft";
  return conf;
}

static void *merge_dir_conf(apr_pool_t *p, void *basev, void *addv) {
  auth_af_dir_rec *new =
      (auth_af_dir_rec *)apr_pcalloc(p, sizeof(auth_af_dir_rec));
  auth_af_dir_rec *add = (auth_af_dir_rec *)addv;
  auth_af_dir_rec *base = (auth_af_dir_rec *)basev;

  new->audience = (add->audience == NULL) ? base->audience : add->audience;
  new->issuer = (add->issuer == NULL) ? base->issuer : add->issuer;
  new->header = (add->header == NULL) ? base->header : add->header;
  new->trusted_jwks =
      (add->trusted_jwks == NULL) ? base->trusted_jwks : add->trusted_jwks;

  return new;
}

static const char *set_srv_cache_dir(cmd_parms *cmd, void *dummy,
                                     const char *arg) {
  auth_af_srv_rec *conf = ap_get_module_config(cmd->server->module_config,
                                               &auth_accessfabric_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 2)
  conf->cache_root = ap_runtime_dir_relative(cmd->pool, arg);
#else
#error "port to 2.2.x without ap_runtime_dir_relative"
#endif
  if (!conf->cache_root) {
    return apr_pstrcat(cmd->pool,
                       "AuthAccessFabric: Invalid AccessFabricCacheDir path",
                       arg, NULL);
  }
  return NULL;
}

static const char *set_srv_fetch_urls(cmd_parms *cmd, void *dummy,
                                      const char *name, const char *url) {
  auth_af_srv_rec *srv = ap_get_module_config(cmd->server->module_config,
                                              &auth_accessfabric_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }

  if (apr_strnatcasecmp(url, "unset") == 0) {
    apr_table_unset(srv->fetch_urls, name);
  } else {
    /* TODO(pquerna): validate url more? */
    if (strncmp("https://", url, 8) != 0) {
      return apr_pstrcat(cmd->pool,
                         "AuthAccessFabric: Invalid AccessFabricFetchJWKs: URL "
                         "must start with https://: ",
                         url, NULL);
    }
    apr_table_set(srv->fetch_urls, name, url);
  }

  return NULL;
}

static void *create_srv_conf(apr_pool_t *p, server_rec *s) {
  auth_af_srv_rec *c =
      (auth_af_srv_rec *)apr_pcalloc(p, sizeof(auth_af_srv_rec));

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 2)
  c->cache_root = ap_runtime_dir_relative(p, "accessfabric-jwk-cache");
#else
#error "port to 2.2.x without ap_runtime_dir_relative"
#endif

  c->fetch_urls = apr_table_make(p, 2);
  apr_table_set(c->fetch_urls, "scaleft",
                "https://app.scaleft.com/v1/oauth/access_fabric_certs");
  return c;
}

static const command_rec directives[] = {
    AP_INIT_TAKE1("AccessFabricCacheDir", set_srv_cache_dir, NULL, RSRC_CONF,
                  "The directory to store cache files"),
    AP_INIT_TAKE2("AccessFabricFetchJWKs", set_srv_fetch_urls, NULL, RSRC_CONF,
                  "Set of URLs to fetch for JWKs"),
    AP_INIT_TAKE1("AuthAccessFabricAudience", set_af_audience, NULL, OR_AUTHCFG,
                  "Audience Name that must match the client provided header"),
    AP_INIT_TAKE1(
        "AuthAccessFabricIssuer", set_af_issuer, NULL, OR_AUTHCFG,
        "Issuer Name to require an exact match. default: " AF_DEFAULT_ISSUER),
    AP_INIT_TAKE1("AuthAccessFabricHeader", set_af_header, NULL, OR_AUTHCFG,
                  "HTTP Header to look for Access Fabric JWT. "
                  "default: " AF_DEFAULT_HEADER),
    AP_INIT_TAKE1("AuthAccessFabricTrustedJWKs", set_af_trusted_jwks, NULL,
                  OR_AUTHCFG, "Name of a JWK key to use"),
    {NULL}};

static apr_status_t af_curl_cleanup(void *data) {
  curl_global_cleanup();
  return APR_SUCCESS;
}

static int auth_af_post_config(apr_pool_t *p, apr_pool_t *plog,
                               apr_pool_t *ptemp, server_rec *s) {
  apr_status_t rv;
  auth_af_srv_rec *srv =
      ap_get_module_config(s->module_config, &auth_accessfabric_module);
  void *userdata_data = NULL;
  const char *userdata_key = "auth_accessfabric_init";

  apr_pool_userdata_get(&userdata_data, userdata_key, s->process->pool);
  if (userdata_data == NULL) {
    apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null,
                          s->process->pool);
    return OK;
  }

  curl_global_init(CURL_GLOBAL_DEFAULT);
  apr_pool_pre_cleanup_register(p, NULL, af_curl_cleanup);

  rv = apr_dir_make_recursive(srv->cache_root, APR_FPROT_OS_DEFAULT, p);
  if (rv != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                 "AuthAccessFabric: AccessFabricCacheDir: Failed to create "
                 "cache directory: %s (%pm) ",
                 srv->cache_root, &rv);
    return !OK;
  }

  if (ap_state_query(AP_SQ_MAIN_STATE) != AP_SQ_MS_CREATE_PRE_CONFIG &&
      !getenv("AP_PARENT_PID")) {
    int ret = auth_af_cache_fill_start(s, srv->cache_root, srv->fetch_urls);
    if (ret != OK) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, ret, s,
                   "AuthAccessFabric: Failed to create JWK Cache: (%d)", ret);
      return ret;
    }
  }
  return OK;
}

static void auth_af_child_init(apr_pool_t *p, server_rec *s) {
  auth_af_jwk_cache_child_init(s->process);
}

static void register_hooks(apr_pool_t *pool) {
  ap_hook_child_init(auth_af_child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_post_config(auth_af_post_config, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_check_authn(auth_af_check_authn, NULL, NULL, APR_HOOK_MIDDLE,
                      AP_AUTH_INTERNAL_PER_CONF);
}

module AP_MODULE_DECLARE_DATA auth_accessfabric_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_conf,
    merge_dir_conf,
    create_srv_conf,
    NULL,
    directives,
    register_hooks};
