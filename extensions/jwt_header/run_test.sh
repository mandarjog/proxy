# Copyright 2020 Istio Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

WD=$(dirname $0)
WD=$(cd $WD; pwd)
TOPDIR=$(cd ${WD}/../..; pwd)
cd ${TOPDIR}

BAZEL_BIN="${TOPDIR}/bazel-bin"

set -ex
pwd
# --allow-unknown-fields
${BAZEL_BIN}/src/envoy/envoy -c ${WD}/testdata/server.yaml --concurrency 1 -l debug  --bootstrap-version 3
