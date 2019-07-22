licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

cc_proto_library(
    name = "metadata_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":metadata_proto"],
)

proto_library(
    name = "metadata_proto",
    srcs = ["metadata.proto"],
)

envoy_cc_library(
    name = "metadata_access_lib",
    srcs = [
        "metadata.cc"
    ],
    hdrs = [
        "metadata.h",
    ],
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        "@envoy//source/common/common:base64_lib",
        "@envoy//source/extensions/common/wasm/null:null_lib",
        ":metadata_cc_proto",
    ],
)

envoy_cc_library(
    name = "metadata_exchange_lib",
    srcs = [
        "config.cc",
    ],
    hdrs = [
        "config.h",
        "metadata.h",
    ],
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        "@envoy//source/common/common:base64_lib",
        "@envoy//source/extensions/common/wasm/null:null_lib",
        ":metadata_access_lib",
        ":metadata_cc_proto",
    ],
)
