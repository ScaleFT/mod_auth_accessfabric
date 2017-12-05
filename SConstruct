#!/usr/bin/env scons
#
#  Copyright 2017, ScaleFT Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

import os, subprocess, platform
from site_scons.utils import get_files, apxs_query
from os.path import join as pjoin

# Ubuntu LTS 14.04 Trusty includes SCons 2.3.0, so thats our minimum bar for now.
EnsureSConsVersion(2, 3, 0)

platform_name = platform.system().upper()

opts = Variables(['build.py', 'build-%s.py' % (platform_name.lower())])

available_profiles = ['debug', 'release']
available_build_types = ['static','shared']

opts.Add(PathVariable('APXS', 'Path to apxs', '/usr/local/bin/apxs'))
opts.Add(EnumVariable('profile', 'build profile', 'release', available_profiles, {}, True))
opts.Add(EnumVariable('build_type', 'build profile', 'shared', available_build_types, {}, True))
opts.Add(PathVariable('with_jansson',
                      'Prefix to Jansson installation', None))
opts.Add(PathVariable('with_openssl',
                      'Prefix to OpenSSL installation', None))
opts.Add(PathVariable('with_xjwt',
                      'Prefix to libxjwt installation', None))
opts.Add(PathVariable('with_curl',
                      'Prefix to libxjwt installation', None))

env = Environment(options=opts,
                  ENV = os.environ.copy(),
                  tools=['default'])

conf = Configure(env, custom_tests = {})

conf.env.Replace(CC = apxs_query(conf.env["APXS"], 'CC'))
conf.env.Replace(CPP = apxs_query(conf.env["APXS"], 'CPP'))
# clang-analyzer support
conf.env["CC"] = os.getenv("CC") or env["CC"]
conf.env["CXX"] = os.getenv("CXX") or env["CXX"]
conf.env["ENV"].update(x for x in os.environ.items() if x[0].startswith("CCC_"))

apr_config = apxs_query(conf.env["APXS"], 'APR_CONFIG')
apu_config = apxs_query(conf.env["APXS"], 'APU_CONFIG')

conf.env.ParseConfig(apr_config + ' --cflags --cppflags --includes')
conf.env.ParseConfig(apu_config + ' --includes')
conf.env.ParseConfig(conf.env['APXS'] + ' -q EXTRA_CFLAGS')
conf.env.ParseConfig(conf.env['APXS'] + ' -q EXTRA_CPPFLAGS')

if not conf.CheckCC():
  print 'Unable to find a functioning compiler, tried %s' % (conf.env.get('CC'))
  Exit(-1)

mod_path = apxs_query(conf.env["APXS"], 'exp_libexecdir')
conf.env.AppendUnique(CPPPATH = [apxs_query(conf.env['APXS'], 'exp_includedir')])


if conf.env.get('with_xjwt'):
    conf.env.AppendUnique(LIBPATH=["${with_xjwt}/lib"])
    conf.env.AppendUnique(CPPPATH=["${with_xjwt}/include"])

if not conf.CheckLibWithHeader('libxjwt', 'xjwt/xjwt.h', 'C', 'xjwt_keyset_destroy(NULL);', True):
    print 'Unable to use libxjwt development enviroment: with_xjwt=%s' %  conf.env.get('with_xjwt')
    Exit(1)

if conf.env.get('with_jansson'):
    conf.env.AppendUnique(LIBPATH=["${with_jansson}/lib"])
    conf.env.AppendUnique(CPPPATH=["${with_jansson}/include"])

if not conf.CheckLibWithHeader('jansson', 'jansson.h', 'c'):
    print 'Unable to use Jansson development enviroment: with_jansson=%s' %  conf.env.get('with_jansson')
    Exit(1)

if conf.env.get('with_openssl'):
    conf.env.AppendUnique(LIBPATH=["${with_openssl}/lib"])
    conf.env.AppendUnique(CPPPATH=["${with_openssl}/include"])

if not conf.CheckLibWithHeader('libssl', 'openssl/ssl.h', 'C', 'SSL_library_init();', True):
    print 'Unable to use OpenSSL development enviroment: with_openssl=%s' %  conf.env.get('with_openssl')
    Exit(1)

if not conf.CheckLibWithHeader('libcrypto', 'openssl/err.h', 'C', 'ERR_load_crypto_strings();', True):
    print 'Unable to use OpenSSL development enviroment (missing libcrypto?): with_openssl=%s' %  conf.env.get('with_openssl')
    Exit(1)

if conf.env.get('with_curl'):
    conf.env.AppendUnique(LIBPATH=["${with_curl}/lib"])
    conf.env.AppendUnique(CPPPATH=["${with_curl}/include"])

if not conf.CheckLibWithHeader('curl', 'curl/curl.h', 'c'):
    print 'Did not find curl/curl.h.h or libcurl, exiting!'
    Exit(1)

for flag in ['-pedantic', '-std=gnu89', '-Wno-variadic-macros', '-Wno-deprecated-declarations']:
  conf.env.AppendUnique(CCFLAGS=flag)
  if not conf.CheckCC():
    print 'Checking for compiler support of %s ... no' % flag
    conf.env['CCFLAGS'] = filter(lambda x: x != flag, conf.env['CCFLAGS'])
  else:
    print 'Checking for compiler support of %s ... yes' % flag

env = conf.Finish()

selected_variant = '%s-%s-%s' % (platform_name.lower(), env['profile'].lower(), env['build_type'].lower())
print "Selected %s variant build..." % (selected_variant)

variants = []

bt = [env['build_type'].upper()]
for profile in available_profiles:
    for build in available_build_types:
        variants.append({'PROFILE': profile.upper(), 'BUILD': build.upper(), 'PLATFORM': platform_name})

rootenv = env

options = {
  'PLATFORM': {
    'DARWIN': {
      'CPPDEFINES': ['DARWIN'],
    },
    'LINUX': {
      'CPPDEFINES': ['LINUX', '_DEFAULT_SOURCE'],
    },
    'FREEBSD': {
      'CPPDEFINES': ['FREEBSD'],
    },
  },
  'PROFILE': {
    'DEBUG': {
      'CCFLAGS': ['-Wall', '-O0', '-ggdb', '-Wno-long-long'],
      'CPPDEFINES': ['DEBUG'],
    },
    'RELEASE': {
      'CCFLAGS': ['-Wall', '-O2', '-Wno-long-long'],
      'CPPDEFINES': ['NODEBUG'],
    },
  },
}
append_types = ['CCFLAGS', 'CFLAGS', 'CPPDEFINES', 'LIBS', 'LINKFLAGS']
replace_types = ['CC']

all_targets = {}
all_test_targets = {}
all_install_targets = {}

for vari in variants:
    targets = []
    test_targets = []
    install_targets = []

    env = rootenv.Clone()

    for k in sorted(options.keys()):
        ty = vari.get(k)
        if options[k].has_key(ty):
            for key,value in options[k][ty].iteritems():
                if key in append_types:
                    p = {key: value}
                    env.AppendUnique(**p)
                elif key in replace_types:
                    env[key] = value
                else:
                    print('Fix the SConsscript, its missing support for %s' % (key))
                    Exit(1)

    profile = vari['PROFILE']
    build = vari['BUILD']
    variant = '%s-%s-%s' % (vari['PLATFORM'].lower(), profile.lower(), build.lower())
    vdir = pjoin('build', variant)
    env['PROFILE'] = profile 
    env['BUILD'] = build
    env['PLATFORM'] = vari['PLATFORM'].lower()

    module = SConscript('src/SConscript', exports=['env'], variant_dir=pjoin(vdir, 'mod_auth_accessfabric'), duplicate=0)
    targets.append(module)

    if variant == selected_variant and not env.GetOption('clean'):
        imod = env.Install(mod_path, source = [module])
        install_targets.append(imod)

    all_targets[variant] = targets
    all_test_targets[variant] = test_targets
    all_install_targets[variant] = install_targets

fenv = env.Clone()

all_source_files = get_files(fenv, 'src', ['*.c', '*.h'])

fenv['CLANG_FORMAT'] = 'clang-format'
fenv['CLANG_FORMAT_OPTIONS'] = '-style=file -i'
formatit = fenv.Command('.clang-format-all-source', all_source_files,
                    '$CLANG_FORMAT $CLANG_FORMAT_OPTIONS $SOURCES')
fenv.AlwaysBuild(formatit)

env.Alias('format', formatit)

env.Alias('install', all_install_targets[selected_variant])
env.Alias('test', all_test_targets[selected_variant])

if env.GetOption('clean'):
  env.Clean(all_targets.values()[0], get_files(env, 'build', ['*.gcda', '*.gcno']))
  env.Default([all_targets.values(),
               all_test_targets.values(),
               all_install_targets.values()])
else:
  env.Default([all_targets[selected_variant]])