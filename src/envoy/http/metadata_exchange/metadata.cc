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

#include "src/envoy/http/metadata_exchange/metadata.h"
#include "common/common/base64.h"

namespace Envoy {
  namespace Extensions {
    namespace Wasm {
      namespace MetadataExchange {

google::protobuf::util::Status extractNodeMetadata(const google::protobuf::Struct &metadata,
                                                   wasm::metadataexchange::Metadata  *meta) {
  google::protobuf::util::JsonOptions json_options;
  std::string metadata_json_struct;
  auto status =
    MessageToJsonString(metadata, &metadata_json_struct, json_options);
  if (status != google::protobuf::util::Status::OK) {
    return status;
  }
  google::protobuf::util::JsonParseOptions json_parse_options;
  json_parse_options.ignore_unknown_fields = true;
  return JsonStringToMessage(metadata_json_struct, meta,
                             json_parse_options);
}

      }
    }
  }
}

