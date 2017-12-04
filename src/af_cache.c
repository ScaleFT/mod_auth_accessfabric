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

#include "apr_atomic.h"
#include "apr_hash.h"
#include "apr_thread_rwlock.h"
#include "apr_reslist.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_log.h"
#include "http_main.h"
#include "ap_mpm.h"

#include "af_cache.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(auth_accessfabric);
#endif

typedef struct {
  apr_pool_t *pool;

  /* locks access to the hash itself, a entry is never destroyed, only added. */
  apr_thread_rwlock_t *mtx;
  apr_hash_t *entries;
  int mpm_max_threads;
} auth_af_cache_t;

typedef struct {
  /* read and set atomically */
  apr_uint32_t active_generation;
  /* reslist does its own locking */
  apr_reslist_t *keysets;

  /* locks access to the data used to create new keysets */
  apr_thread_mutex_t *mtx;
  const char *jwks;
  size_t jwks_len;
  apr_time_t jwks_refresh_at;

  apr_pool_t *pool;
} auth_af_cache_entry_t;

static auth_af_cache_t *g_cache;

void auth_af_jwk_cache_child_init(process_rec *proc) {
  g_cache = (auth_af_cache_t *)apr_pcalloc(proc->pool, sizeof(auth_af_cache_t));
  apr_pool_create(&g_cache->pool, proc->pool);
  apr_pool_tag(g_cache->pool, "auth_af_g_cache");

  apr_thread_rwlock_create(&g_cache->mtx, g_cache->pool);
  g_cache->entries = apr_hash_make(g_cache->pool);
  ap_mpm_query(AP_MPMQ_MAX_THREADS, &g_cache->mpm_max_threads);
}

static apr_status_t cb_cache_entry_create(void **resource, void *params,
                                          apr_pool_t *pool) {
  auth_af_keyset_t *out = NULL;
  xjwt_keyset_t *ks = NULL;
  xjwt_error_t *xerr = NULL;
  auth_af_cache_entry_t *entry = params;
  apr_status_t rv;
  apr_uint32_t gen;

  rv = apr_thread_mutex_lock(entry->mtx);
  if (rv != APR_SUCCESS) {
    return rv;
  }

  gen = apr_atomic_read32(&entry->active_generation);
  xerr = xjwt_keyset_create_from_memory(entry->jwks, entry->jwks_len, &ks);
  apr_thread_mutex_unlock(entry->mtx);

  if (xerr != XJWT_SUCCESS) {
    rv = APR_EINVAL;
    ap_log_error(
        APLOG_MARK, APLOG_ERR, rv, ap_server_conf,
        "AuthAccessFabric: Failed to parse JWKs in memory cache: (%d) %s",
        xerr->err, xerr->msg);
    xjwt_error_destroy(xerr);
    return rv;
  }

  out = calloc(1, sizeof(auth_af_keyset_t));
  out->keyset = ks;
  out->generation = gen;
  *resource = out;
  return rv;
}

static apr_status_t cb_cache_entry_destroy(void *resource, void *params,
                                           apr_pool_t *pool) {
  auth_af_keyset_t *ks = resource;

  if (ks != NULL) {
    if (ks->keyset != NULL) {
      xjwt_keyset_destroy(ks->keyset);
    }
    free(ks);
  }

  return APR_SUCCESS;
}

static apr_status_t auth_af_jwk_cache_refresh_from_disk(
    auth_af_srv_rec *srv, const char *key, apr_pool_t *ptemp,
    auth_af_cache_entry_t *entry);

static apr_status_t auth_af_jwk_cache_get_hit(
    request_rec *r, auth_af_srv_rec *srv, const char *key, apr_pool_t *ptemp,
    auth_af_cache_entry_t *entry, auth_af_keyset_t **outks) {
  int tries = 0;
  apr_status_t rv;
  auth_af_keyset_t *ks;
  apr_uint32_t gen;

  if (entry->jwks_refresh_at == 0 || entry->jwks_refresh_at > r->request_time) {
    rv = auth_af_jwk_cache_refresh_from_disk(srv, key, ptemp, entry);
    if (rv != APR_SUCCESS) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                    "AuthAccessFabric: Failed to refresh JWK cache from disk");
      return rv;
    }
  }

HAVE_ENTRY:
  ks = NULL;
  rv = apr_reslist_acquire(entry->keysets, (void **)&ks);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                  "AuthAccessFabric: reslist failed to find JWK cache entry");
    return rv;
  }

  gen = apr_atomic_read32(&entry->active_generation);
  if (gen != ks->generation) {
    apr_reslist_invalidate(entry->keysets, ks);
    tries++;
    if (tries > g_cache->mpm_max_threads) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, r,
                    "AuthAccessFabric: reslist exhausted with old entries");
      return APR_EGENERAL;
    }
    goto HAVE_ENTRY;
  }

  *outks = ks;
  return APR_SUCCESS;
}

/* constraint: called with entry->mtx unlocked; */
static apr_status_t auth_af_jwk_cache_refresh_from_disk(
    auth_af_srv_rec *srv, const char *key, apr_pool_t *ptemp,
    auth_af_cache_entry_t *entry) {
  apr_file_t *fp = NULL;
  apr_status_t rv;
  apr_finfo_t finfo;
  char *buf = NULL;
  const char *fn = apr_pstrcat(ptemp, srv->cache_root, "/", key, ".json", NULL);

  rv = apr_thread_mutex_lock(entry->mtx);
  if (rv != APR_SUCCESS) {
    return rv;
  }

  rv = apr_file_open(&fp, fn, APR_READ | APR_BINARY, APR_OS_DEFAULT, ptemp);
  if (rv != APR_SUCCESS) {
    apr_thread_mutex_unlock(entry->mtx);
    return rv;
  }

  rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, fp);
  if (rv != APR_SUCCESS) {
    apr_thread_mutex_unlock(entry->mtx);
    return rv;
  }

  buf = calloc(1, finfo.size + 1);
  rv = apr_file_read_full(fp, buf, finfo.size, NULL);
  if (rv != APR_SUCCESS) {
    apr_thread_mutex_unlock(entry->mtx);
    return rv;
  }
  if (entry->jwks != NULL) {
    free((void *)entry->jwks);
  }

  apr_atomic_inc32(&entry->active_generation);
  entry->jwks = buf;
  entry->jwks_len = finfo.size;
  /* TODO: this could be calculated based on the last modified time, but meh */
  entry->jwks_refresh_at = apr_time_now();

  apr_thread_mutex_unlock(entry->mtx);
  return APR_SUCCESS;
}

static apr_status_t auth_af_jwk_cache_get_miss(request_rec *r,
                                               auth_af_srv_rec *srv,
                                               apr_pool_t *ptemp,
                                               const char *key,
                                               auth_af_keyset_t **outks) {
  apr_ssize_t keylen = strlen(key);
  apr_status_t rv;
  auth_af_cache_entry_t *entry = NULL;
  apr_pool_t *newpool = NULL;
  rv = apr_thread_rwlock_wrlock(g_cache->mtx);
  if (rv != APR_SUCCESS) {
    return rv;
  }

  entry = apr_hash_get(g_cache->entries, key, keylen);
  if (entry != NULL) {
    rv = apr_thread_rwlock_unlock(g_cache->mtx);
    if (rv != APR_SUCCESS) {
      return rv;
    }
    return auth_af_jwk_cache_get_hit(r, srv, key, ptemp, entry, outks);
  }

  rv = apr_pool_create_ex(&newpool, NULL, NULL, NULL);
  if (rv != APR_SUCCESS) {
    return rv;
  }
  apr_pool_tag(newpool, "auth_af_entry_cache");

  entry = apr_pcalloc(newpool, sizeof(auth_af_cache_entry_t));
  entry->pool = newpool;
  rv = apr_thread_mutex_create(&entry->mtx, APR_THREAD_MUTEX_DEFAULT,
                               entry->pool);
  if (rv != APR_SUCCESS) {
    return rv;
  }

  rv = apr_reslist_create(&entry->keysets, 0, 1, g_cache->mpm_max_threads, 0,
                          cb_cache_entry_create, cb_cache_entry_destroy, entry,
                          newpool);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                  "AuthAccessFabric: failed to initialize reslist");
    apr_thread_rwlock_unlock(g_cache->mtx);
    apr_pool_destroy(newpool);
    return rv;
  }

  apr_hash_set(g_cache->entries, key, keylen, entry);

  apr_thread_rwlock_unlock(g_cache->mtx);

  return auth_af_jwk_cache_get_hit(r, srv, key, ptemp, entry, outks);
}

apr_status_t auth_af_jwk_cache_get(request_rec *r, auth_af_srv_rec *srv,
                                   apr_pool_t *ptemp, const char *key,
                                   auth_af_keyset_t **outks) {
  apr_ssize_t keylen = strlen(key);
  apr_status_t rv;
  auth_af_cache_entry_t *entry = NULL;
  rv = apr_thread_rwlock_rdlock(g_cache->mtx);
  if (rv != APR_SUCCESS) {
    return rv;
  }

  entry = apr_hash_get(g_cache->entries, key, keylen);

  rv = apr_thread_rwlock_unlock(g_cache->mtx);
  if (rv != APR_SUCCESS) {
    return rv;
  }

  if (entry != NULL) {
    return auth_af_jwk_cache_get_hit(r, srv, key, ptemp, entry, outks);
  }
  return auth_af_jwk_cache_get_miss(r, srv, ptemp, key, outks);
}

void auth_af_keyset_destroy(auth_af_keyset_t *ks) {
  xjwt_keyset_destroy(ks->keyset);
  free(ks);
}

apr_status_t auth_af_jwk_cache_release(const char *key, auth_af_keyset_t *ks) {
  apr_ssize_t keylen = strlen(key);
  apr_status_t rv;
  auth_af_cache_entry_t *entry = NULL;
  apr_uint32_t gen;

  rv = apr_thread_rwlock_rdlock(g_cache->mtx);
  if (rv != APR_SUCCESS) {
    return rv;
  }

  entry = apr_hash_get(g_cache->entries, key, keylen);

  rv = apr_thread_rwlock_unlock(g_cache->mtx);
  if (rv != APR_SUCCESS) {
    return rv;
  }

  /* this should never happen? */
  if (entry == NULL) {
    auth_af_keyset_destroy(ks);
    return APR_SUCCESS;
  }

  gen = apr_atomic_read32(&entry->active_generation);
  if (gen != ks->generation) {
    apr_reslist_invalidate(entry->keysets, ks);
    return APR_SUCCESS;
  }
  apr_reslist_release(entry->keysets, ks);

  return APR_SUCCESS;
}
