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

#ifndef _af_types_h_
#define _af_types_h_

#include "httpd.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
  const char *audience;
  const char *issuer;
  const char *header;
  const char *trusted_jwks;
} auth_af_dir_rec;

typedef struct {
  const char *cache_root;
  apr_table_t *fetch_urls;
} auth_af_srv_rec;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _af_types_h_ */
