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

#include "apr.h"
#include "apr_atomic.h"
#include "apr_strings.h"

#include "ap_mpm.h"
#include "http_log.h"

#include "af_fetch.h"

#include "xjwt/xjwt.h"

#include <curl/curl.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(auth_accessfabric);
#endif

typedef struct {
  apr_uint32_t stop;
  apr_thread_t *thread;
  server_rec *server;
  apr_pool_t *root_pool;
  const char *server_admin;
  const char *cache_root;
  apr_table_t *jwks;

  apr_array_header_t *entries;
} auth_af_fetcher_t;

typedef struct {
  apr_time_t next_check;
  const char *url;
  const char *destpath;
} fetcher_entry_t;

typedef struct {
  fetcher_entry_t *entry;
  CURL *curl;
  apr_pool_t *pool;
  char *tempfile;
  apr_file_t *tempfd;
} fetcher_req_t;

static apr_status_t fetcher_req_cleanup(void *baton) {
  fetcher_req_t *req = (fetcher_req_t *)baton;

  if (req->curl != NULL) {
    curl_easy_cleanup(req->curl);
  }

  if (req->tempfd != NULL) {
    apr_file_close(req->tempfd);
    apr_file_remove(req->tempfile, req->pool);
    req->tempfd = NULL;
  }
  req->tempfile = NULL;

  return APR_SUCCESS;
}

static size_t fetcher_req_write_func(void *data, size_t len, size_t nmemb,
                                     void *baton) {
  fetcher_req_t *req = (fetcher_req_t *)baton;
  size_t blen = len * nmemb;
  apr_status_t rv;

  rv = apr_file_write_full(req->tempfd, data, blen, NULL);
  if (rv != APR_SUCCESS) {
    return 0;
  }
  return blen;
}

static fetcher_req_t *fetcher_req_make(auth_af_fetcher_t *fetcher,
                                       fetcher_entry_t *entry, apr_pool_t *p) {
  fetcher_req_t *req = (fetcher_req_t *)apr_pcalloc(p, sizeof(fetcher_req_t));

  CURL *curl = curl_easy_init();
  /* uncomment for more debugging: */
  /* curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L); */
  curl_easy_setopt(curl, CURLOPT_USERAGENT,
                   apr_psprintf(p, "mod_auth_accessfabric/0.1.0 (admin=%s)",
                                fetcher->server_admin));
  curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(curl, CURLOPT_URL, entry->url);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
  curl_easy_setopt(curl, CURLOPT_MAXFILESIZE, 512000L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fetcher_req_write_func);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, req);

  req->curl = curl;
  req->pool = p;
  req->entry = entry;
  req->tempfile = apr_pstrcat(p, entry->destpath, ".XXXXXX", NULL);

  apr_pool_cleanup_register(p, req, fetcher_req_cleanup, apr_pool_cleanup_null);

  return req;
}

static void auth_af_process_entry(auth_af_fetcher_t *fetcher,
                                  fetcher_entry_t *entry, apr_pool_t *p) {
  fetcher_req_t *req;
  uint64_t random = 0;
  apr_status_t rv;
  char *buf;
  apr_file_t *testfd = NULL;
  apr_finfo_t testinfo;
  CURLcode curle;
  long response_code;
  xjwt_keyset_t *ks = NULL;
  xjwt_error_t *xerr = NULL;

  apr_time_t now = apr_time_now();
  if (entry->next_check > now) {
    return;
  }

  ap_log_error(APLOG_MARK, APLOG_INFO, 0, fetcher->server,
               "AuthAccessFabric: Refreshing JWK cache: %s -> %s", entry->url,
               entry->destpath);

  req = fetcher_req_make(fetcher, entry, p);

  rv = apr_file_mktemp(&req->tempfd, req->tempfile,
                       APR_CREATE | APR_WRITE | APR_BINARY | APR_EXCL, p);
  if (rv != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, fetcher->server,
                 "AuthAccessFabric: Error creating temp file for %s",
                 entry->destpath);
    return;
  }

  curle = curl_easy_perform(req->curl);
  if (curle != CURLE_OK) {
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, fetcher->server,
                 "AuthAccessFabric: Error Fetching '%s': (%d) %s", entry->url,
                 curle, curl_easy_strerror(curle));
    return;
  }

  curle = curl_easy_getinfo(req->curl, CURLINFO_RESPONSE_CODE, &response_code);
  if (curle != CURLE_OK) {
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, fetcher->server,
                 "AuthAccessFabric: Error Reading Response Code '%s': (%d) %s",
                 entry->url, curle, curl_easy_strerror(curle));
    return;
  }

  if (response_code != 200) {
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, fetcher->server,
                 "AuthAccessFabric: Error Fetching '%s': HTTP Status %ld",
                 entry->url, response_code);
    return;
  }

  apr_file_close(req->tempfd);
  req->tempfd = NULL;

  rv = apr_file_perms_set(req->tempfile,
                          /* 0644 */ APR_FPROT_UWRITE | APR_FPROT_UREAD |
                              APR_FPROT_GREAD | APR_FPROT_WREAD);
  if (rv && rv != APR_INCOMPLETE && rv != APR_ENOTIMPL) {
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, fetcher->server,
                 "AuthAccessFabric: Unable to set file permissions on: %s",
                 req->tempfile);
    return;
  }

  rv = apr_file_open(&testfd, req->tempfile, APR_READ | APR_BINARY,
                     APR_OS_DEFAULT, p);
  if (rv != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, fetcher->server,
                 "AuthAccessFabric: Failed to open tempfile: %s",
                 req->tempfile);
    return;
  }

  rv = apr_file_info_get(&testinfo, APR_FINFO_SIZE, testfd);
  if (rv != APR_SUCCESS) {
    apr_file_close(testfd);
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, fetcher->server,
                 "AuthAccessFabric: Failed to stat tempfile: %s",
                 req->tempfile);
    return;
  }

  buf = calloc(1, testinfo.size + 1);
  rv = apr_file_read_full(testfd, buf, testinfo.size, NULL);
  if (rv != APR_SUCCESS) {
    apr_file_close(testfd);
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, fetcher->server,
                 "AuthAccessFabric: Failed to read tempfile: %s",
                 req->tempfile);
    return;
  }
  apr_file_close(testfd);

  xerr = xjwt_keyset_create_from_memory(buf, testinfo.size, &ks);
  if (xerr != XJWT_SUCCESS) {
    free(buf);
    ap_log_error(
        APLOG_MARK, APLOG_ERR, 0, fetcher->server,
        "AuthAccessFabric: Failed to parse JWKs in tempfile: %s: (%d) %s",
        req->tempfile, xerr->err, xerr->msg);
    xjwt_error_destroy(xerr);
    return;
  }

  free(buf);
  xjwt_keyset_destroy(ks);

  rv = apr_file_rename(req->tempfile, entry->destpath, p);
  if (rv != APR_SUCCESS) {
    apr_file_remove(req->tempfile, req->pool);
    ap_log_error(APLOG_MARK, APLOG_ERR, rv, fetcher->server,
                 "AuthAccessFabric: Error Saving into cache path: %s",
                 entry->destpath);
    return;
  }

  ap_log_error(APLOG_MARK, APLOG_INFO, 0, fetcher->server,
               "AuthAccessFabric: Updated JWK cache: %s", entry->destpath);

  /**
   * TODO: we should be smarter about this, use cache-control header, etc.
   *
   * right now: simple random spreading of next checking over the next 16 to 30
   * minutes
   */
  ap_random_insecure_bytes(&random, sizeof(uint64_t));
  entry->next_check =
      now + apr_time_from_sec((random % (1800 + 1 - 1000)) + 1800);
}

static void auth_af_daemon_cycle(auth_af_fetcher_t *fetcher, apr_pool_t *p) {
  apr_pool_t *ptemp = NULL;
  int i;
  apr_pool_create(&ptemp, p);
  apr_pool_tag(ptemp, "auth_af_cache_cycle");

  for (i = 0; i < fetcher->entries->nelts; i++) {
    fetcher_entry_t *entry = ((fetcher_entry_t **)fetcher->entries->elts)[i];
    auth_af_process_entry(fetcher, entry, ptemp);
    apr_pool_clear(ptemp);
  }
  return;
}

static void *auth_af_daemon_thread(apr_thread_t *me, void *threaddata) {
  int count = 0;
  apr_status_t rv = APR_SUCCESS;
  apr_pool_t *ptemp = NULL;
  auth_af_fetcher_t *fetcher = (auth_af_fetcher_t *)threaddata;

  apr_pool_create(&ptemp, fetcher->root_pool);
  apr_pool_tag(ptemp, "auth_af_cache_temp");
  auth_af_daemon_cycle(fetcher, ptemp);
  apr_pool_destroy(ptemp);

  while (1) {
    int mpmq_s = 0;
    apr_uint32_t stop;

    /* TODO: use a pollset / other timer+signaler? */
    apr_sleep(apr_time_from_sec(1));
    stop = apr_atomic_read32(&fetcher->stop);

    if (stop == 0) {
      break;
    }
    if ((rv = ap_mpm_query(AP_MPMQ_MPM_STATE, &mpmq_s)) != APR_SUCCESS) {
      break;
    }
    if (mpmq_s == AP_MPMQ_STOPPING) {
      break;
    }

    if (++count >= 30) {
      count = 0;
      apr_pool_create(&ptemp, fetcher->root_pool);
      apr_pool_tag(ptemp, "auth_af_cache_temp");
      auth_af_daemon_cycle(fetcher, ptemp);
      apr_pool_destroy(ptemp);
      ptemp = NULL;
    }
  }

  return NULL;
}

static int fetcher_add_entry(void *rec, const char *key, const char *value) {
  auth_af_fetcher_t *fetcher = rec;
  fetcher_entry_t *entry = (fetcher_entry_t *)apr_pcalloc(
      fetcher->root_pool, sizeof(fetcher_entry_t));
  entry->next_check = 0;
  entry->url = value;
  entry->destpath = apr_pstrcat(fetcher->root_pool, fetcher->cache_root, "/",
                                key, ".json", NULL);

  APR_ARRAY_PUSH(fetcher->entries, fetcher_entry_t *) = entry;

  return 1;
}

static apr_status_t auth_af_wait_for_thread(void *data) {
  auth_af_fetcher_t *fetcher = data;
  apr_status_t retval = APR_SUCCESS;

  apr_atomic_set32(&fetcher->stop, 0);
  apr_thread_join(&retval, fetcher->thread);
  return APR_SUCCESS;
}

int auth_af_cache_fill_start(server_rec *s, const char *cache_root,
                             apr_table_t *jwks) {
  apr_pool_t *p = NULL;
  auth_af_fetcher_t *fetcher = NULL;
  apr_status_t rv;

  apr_pool_create(&p, s->process->pool);
  apr_pool_tag(p, "auth_af_cache_background");

  fetcher = (auth_af_fetcher_t *)apr_pcalloc(p, sizeof(auth_af_fetcher_t));
  fetcher->server = s;
  fetcher->root_pool = p;
  fetcher->cache_root = apr_pstrdup(p, cache_root);
  fetcher->jwks = apr_table_clone(p, jwks);
  fetcher->server_admin = apr_pstrdup(p, s->server_admin);
  apr_atomic_set32(&fetcher->stop, 1);
  fetcher->entries = apr_array_make(p, 0, sizeof(fetcher_entry_t *));

  apr_table_do(fetcher_add_entry, fetcher, fetcher->jwks, NULL);

  rv = apr_thread_create(&fetcher->thread, NULL, auth_af_daemon_thread, fetcher,
                         p);
  if (rv != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                 "Could not create worker thread for auth_accessfabric");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  apr_pool_pre_cleanup_register(p, fetcher, auth_af_wait_for_thread);
  return OK;
}
