#!/usr/bin/env python
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

import os, sys, fnmatch, subprocess

def get_output(cmd):
    s = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    out = s.communicate()[0]
    s.wait()
    return out.strip()

def apxs_query(path, key):
    cmd = [path, "-q", key]
    return get_output(cmd)

def get_files(env, source, globs, reldir=os.curdir):
  results = []
  if not os.path.isdir(source):
    return results
  for entry in os.listdir(source):
    fullpath = os.path.join(source, entry)
    if os.path.islink(fullpath):
      continue
    if os.path.isfile(fullpath):
      if any((fnmatch.fnmatchcase(fullpath, i) for i in globs)):
        results.append(fullpath)
    elif os.path.isdir(fullpath):
      newrel = os.path.join(reldir, entry)
      results.extend(get_files(env, fullpath, globs, newrel))
  return results

def InstallPerm(env, dest, files, perm):
  obj = env.Install(dest, files)
  for i in obj:
    env.AddPostAction(i, env.Chmod(str(i), perm))
  return obj
  
InstallHeader = lambda env, dest, files: InstallPerm(env, dest, files, 0644)
