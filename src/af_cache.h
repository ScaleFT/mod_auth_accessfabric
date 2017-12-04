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

#ifndef _af_cache_h_
#define _af_cache_h_

#include "httpd.h"
#include "xjwt/xjwt.h"
#include "af_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void auth_af_jwk_cache_child_init(process_rec *proc);

typedef struct {
  xjwt_keyset_t *keyset;
  apr_uint32_t generation;
} auth_af_keyset_t;

apr_status_t auth_af_jwk_cache_get(request_rec *r, auth_af_srv_rec *srv,
                                   apr_pool_t *ptemp, const char *key,
                                   auth_af_keyset_t **keyset);

apr_status_t auth_af_jwk_cache_release(const char *key,
                                       auth_af_keyset_t *keyset);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _af_cache_h_ */
