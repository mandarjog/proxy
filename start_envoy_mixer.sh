./bazel-bin/src/envoy/envoy -c ./envoy_with_mixer.yaml --service-cluster istio-proxy \
       	--service-node sidecar~10.40.46.129~svc07-0-6-0-754db656bf-7ghvq.service-graph07~service-graph07.svc.cluster.local \
       	--max-obj-name-len 189 --allow-unknown-fields -l warn --concurrency 2 --v2-config-only
