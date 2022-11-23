#!/bin/sh
# Copyright 2022 MobiledgeX, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


REPO=$1
OUT=version.yaml
# if no local/branch commits beyond master, master and head will be the same
BUILD_MASTER=`git describe --tags --always origin/master`
BUILD_HEAD=`git describe --tags --always --dirty=+`
BUILD_AUTHOR=`git config user.name`
DATE=`date`

cat <<EOF > $OUT
buildtag: "$BUILD_TAG"
buildmaster: "$BUILD_MASTER"
buildhead: "$BUILD_HEAD"
buildauthor: "$BUILD_AUTHOR"
builddate: "$DATE"
EOF

GOOUT=../version_embedded/version_embedded.go
cat <<EOF > $GOOUT.tmp
package version_embedded

// These are used for binaries distributed individually.
// For binaries distributed in containers, use the version
// package instead to prevent binaries from changing due to
// every change to the git commit id.
var BuildTag = "$BUILD_TAG"
var BuildMaster = "$BUILD_MASTER"
var BuildHead = "$BUILD_HEAD"
var BuildAuthor = "$BUILD_AUTHOR"
var BuildDate = "$BUILD_DATE"
EOF

gofmt $GOOUT.tmp > $GOOUT
rm $GOOUT.tmp
