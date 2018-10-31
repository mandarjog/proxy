/* Copyright 2017 Istio Authors. All Rights Reserved.
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

#ifndef ISTIO_CONTROL_CLIENT_CONTEXT_BASE_H
#define ISTIO_CONTROL_CLIENT_CONTEXT_BASE_H

#include "include/istio/mixerclient/client.h"
#include "include/istio/utils/attribute_names.h"
#include "include/istio/utils/local_attributes.h"
#include "mixer/v1/config/client/client_config.pb.h"
#include "request_context.h"
#include <dlfcn.h>
#include "libmixc.h"

typedef GoUint8 (*ReportFunc)(GoString p0);

void toGoString(const std::string& str, GoString* out) {
    out->n = str.length();
    out->p = str.c_str();
}

namespace istio {
namespace control {

// The global context object to hold the mixer client object
// to call Check/Report with cache.
class ClientContextBase {
 public:
  ClientContextBase(
      const ::istio::mixer::v1::config::client::TransportConfig& config,
      const ::istio::mixerclient::Environment& env, bool outbound,
      const ::istio::utils::LocalNode& local_node);

  // A constructor for unit-test to pass in a mock mixer_client
  ClientContextBase(
      std::unique_ptr<::istio::mixerclient::MixerClient> mixer_client,
      bool outbound, ::istio::utils::LocalAttributes& local_attributes)
      : mixer_client_(std::move(mixer_client)),
        outbound_(outbound),
        local_attributes_(local_attributes) {}
  // virtual destrutor
  virtual ~ClientContextBase() {}

  // Use mixer client object to make a Check call.
  ::istio::mixerclient::CancelFunc SendCheck(
      ::istio::mixerclient::TransportCheckFunc transport,
      ::istio::mixerclient::CheckDoneFunc on_done, RequestContext* request);

  // Use mixer client object to make a Report call.
  void SendReport(const RequestContext& request);

  // Get statistics.
  void GetStatistics(::istio::mixerclient::Statistics* stat) const;

  void AddLocalNodeAttributes(::istio::mixer::v1::Attributes* request) const;

  void AddLocalNodeForwardAttribues(
      ::istio::mixer::v1::Attributes* request) const;

 private:
  // The mixer client object with check cache and report batch features.
  std::unique_ptr<::istio::mixerclient::MixerClient> mixer_client_;

  // If this is an outbound client context.
  bool outbound_;

  // local attributes - owned by the client context.
  ::istio::utils::LocalAttributes local_attributes_;

  // dynamically loaded report function
  ReportFunc reportFunc_;
};

}  // namespace control
}  // namespace istio

#endif  // ISTIO_CONTROL_CLIENT_CONTEXT_BASE_H
