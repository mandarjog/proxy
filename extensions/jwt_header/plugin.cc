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

#include "extensions/jwt_header/plugin.h"

//#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

#include "absl/strings/str_cat.h"
#include "google/protobuf/util/json_util.h"

#ifndef NULL_PLUGIN
#include "extensions/common/wasm/base64.h"

#else  // NULL_PLUGIN

#include "common/common/base64.h"

namespace proxy_wasm {
namespace null_plugin {
namespace JwtHeader {
namespace Plugin {

PROXY_WASM_NULL_PLUGIN_REGISTRY;


//using proxy_wasm::null_plugin::clearRouteCache;
#endif  // NULL_PLUGIN

using google::protobuf::util::JsonParseOptions;
using google::protobuf::util::Status;

static RegisterContextFactory register_JwtHeader(
    CONTEXT_FACTORY(PluginContext), ROOT_FACTORY(PluginRootContext));

bool PluginRootContext::onConfigure(size_t configuration_size) {
  auto configuration = getBufferBytes(WasmBufferType::PluginConfiguration,
                                           0, configuration_size);

  JsonParseOptions json_options;
  auto status =
      JsonStringToMessage(configuration->toString(), &config_, json_options);
  if (status != Status::OK) {
    LOG_WARN(absl::StrCat("Cannot parse plugin configuration JSON string ",
                          configuration->toString()));
    return false;
  }

  return true;
}

FilterHeadersStatus PluginContext::onRequestHeaders(uint32_t, bool) {
  google::protobuf::Struct jwtPayloadStruct;
  JsonParseOptions json_options;


  auto md = getProperty({"metadata", "filter_metadata", "envoy.filters.http.jwt_authn"});
  if (!md.has_value()) {
    LOG_WARN("envoy.filters.http.jwt_authn metadata not found.");
    return FilterHeadersStatus::Continue;
  }

  // 
  const auto pairs = md.value()->pairs();
  if (pairs.size()==0){
    LOG_WARN("Empty jwt metadata");
    return FilterHeadersStatus::Continue;
  }
  // we expect only one entry.
  if (pairs.size()!=1){
    LOG_WARN("Multiple jwt entries found, using the 1st entry");
  }


  auto jwt_entry = pairs[0].second;  // std::string_view
  char *wptr = static_cast<char *>(::malloc(jwt_entry.size()));
  jwt_entry.copy(wptr, jwt_entry.size());
  WasmData ws(wptr, jwt_entry.size());
  wptr = nullptr;

  auto claims = ws.pairs();
  // pairs[0].second 
  for (const auto& p: claims) {
     LOG_WARN(absl::StrCat("airs ", p.first, " ----> ", p.second));
  } 

  // jwt validation filter uses the jwt-auth dynamic metadata
  // with issuer as the key in struct.
  //if (!getMessageValue({"metadata", "filter_metadata", "envoy.filters.http.jwt_authn"},
  if (!getMessageValue({"metadata", "filter_metadata"},
                       &jwtPayloadStruct)) {
    LOG_WARN("No jwt-auth metadata present");
    return FilterHeadersStatus::Continue;
  }

  // Istio jwt filter adds exactly one entry to the map
  // The 'issuer' is not relevant.
  auto it = jwtPayloadStruct.fields().begin();

  if (jwtPayloadStruct.fields().end() == it) {
    LOG_WARN("Empty jwt metadata");
    return FilterHeadersStatus::Continue;
  }


  google::protobuf::Struct jwtStruct;
  std::string jsonJwt;

  google::protobuf::util::MessageToJsonString(it->second.struct_value(), &jsonJwt);

  //auto jwtStruct = it->second.struct_value();

  
  //auto jsonJwt = it->second.string_value();

  auto status = JsonStringToMessage(jsonJwt, &jwtStruct, json_options);

  if (status != Status::OK) {
    LOG_WARN(absl::StrCat("Cannot parse JSON string ", jsonJwt));
    return FilterHeadersStatus::Continue;
  }
   

  bool modified_headers = false;
  const auto end_it = jwtStruct.fields().end();

  for (const auto& mapping : rootContext()->config().header_map()) {
    const auto claim_it = jwtStruct.fields().find(mapping.second);
    if (claim_it == end_it) {
      LOG_DEBUG(
          absl::StrCat("Claim ", mapping.second, " missing from ", jsonJwt));

      // Remove mapping request header if present so that it is not used to
      // decide routes.
      auto found = getRequestHeader(mapping.first);
      if (found) {
        removeRequestHeader(mapping.first);
        modified_headers = true;
      }
      continue;
    }

    if (WasmResult::Ok !=
        replaceRequestHeader(mapping.first, claim_it->second.string_value())) {
      LOG_WARN(absl::StrCat("Unable to set header ", mapping.first, " to ",
                            claim_it->second.string_value()));
    } else {
      LOG_DEBUG(absl::StrCat("SetHeader ", mapping.first, " = ",
                             claim_it->second.string_value()));
      modified_headers = true;
    }
  }

  if (modified_headers) {
    //clearRouteCache();
  }

  return FilterHeadersStatus::Continue;
}

#ifdef NULL_PLUGIN
}  // namespace Plugin
}  // namespace JwtHeader
}  // namespace null_plugin
}  // namespace proxy_wasm
#endif
