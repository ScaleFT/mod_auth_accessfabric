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

#ifndef _af_fetch_h_
#define _af_fetch_h_

#include "httpd.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int auth_af_cache_fill_start(server_rec *s, const char *cache_root,
                             apr_table_t *jwks);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _af_fetch_h_ */
