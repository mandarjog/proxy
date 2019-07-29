/* Copyright 2019 Istio Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "extensions/common/node_info.pb.h"

// WASM_PROLOG
#ifndef NULL_PLUGIN
#include "api/wasm/cpp/proxy_wasm_intrinsics.h"

#else  // NULL_PLUGIN

#include "extensions/common/wasm/null/null.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Wasm {
namespace Null {
namespace Plugin {
#endif  // NULL_PLUGIN

// END WASM_PROLOG

namespace Common {

using StringView = absl::string_view;

// Node metadata
constexpr StringView kIstioMetadataKey = "istio.io/metadata";
constexpr StringView kMetadataPodNameKey = "name";
constexpr StringView kMetadataNamespaceKey = "namespace";
constexpr StringView kMetadataOwnerKey = "owner";
constexpr StringView kMetadataWorkloadNameKey = "workload_name";
constexpr StringView kMetadataContainersKey = "ports_to_containers";
constexpr StringView kPlatformMetadataKey = "platform_metadata";

constexpr StringView kUpstreamMetadataIdKey =
    "envoy.wasm.metadata_exchange.upstream_id";
constexpr StringView kUpstreamMetadataKey =
    "envoy.wasm.metadata_exchange.upstream";

constexpr StringView kDownstreamMetadataIdKey =
    "envoy.wasm.metadata_exchange.downstream_id";
constexpr StringView kDownstreamMetadataKey =
    "envoy.wasm.metadata_exchange.downstream";

// Header keys
constexpr StringView kAuthorityHeaderKey = ":authority";
constexpr StringView kMethodHeaderKey = ":method";

// Misc
constexpr double kNanosecondsPerMillisecond = 1000000.0;
constexpr StringView kIstioProxyContainerName = "istio-proxy";
constexpr StringView kMutualTLS = "MUTUAL_TLS";
constexpr StringView kNone = "NONE";

// RequestInfo represents the information collected from filter stream
// callbacks. This is used to fill metrics and logs.
struct RequestInfo {
  // Start timestamp in nanoseconds.
  int64_t start_timestamp = 0;

  // End timestamp in nanoseconds.
  int64_t end_timestamp = 0;

  // Request total size in bytes, include header, body, and trailer.
  int64_t request_size = 0;

  // Response total size in bytes, include header, body, and trailer.
  int64_t response_size = 0;

  // Node information of the peer that the request sent to or came from.
  common::NodeInfo downstream_node_info;
  common::NodeInfo upstream_node_info;

  // Destination port that the request targets.
  int64_t destination_port = 0;

  // Protocol used the request (HTTP/1.1, gRPC, etc).
  std::string request_protocol;

  // Response code of the request.
  int64_t response_code = 0;

  // Host name of destination service.
  std::string destination_service_host;

  // Operation of the request, i.e. HTTP method or gRPC API method.
  std::string request_operation;

  // Indicates if the request uses mTLS.
  bool mTLS = false;

  // Principal of source and destination workload extracted from TLS
  // certificate.
  std::string source_principal;
  std::string destination_principal;
};

// Extracts NodeInfo from proxy node metadata passed in as a protobuf struct.
// It converts the metadata struct to a JSON struct and parse NodeInfo proto
// from that JSON struct.
// Returns status of protocol/JSON operations.
google::protobuf::util::Status extractNodeMetadata(
    const google::protobuf::Struct &metadata, common::NodeInfo *node_info);

// populateRequestInfo populates the RequestInfo struct. It needs access to
// the request context.
void populateRequestInfo(RequestInfo *request_info);
}  // namespace Common

// WASM_EPILOG
#ifdef NULL_PLUGIN
}  // namespace Plugin
}  // namespace Null
}  // namespace Wasm
}  // namespace Common
}  // namespace Extensions
}  // namespace Envoy
#endif
