# Pinned Xray API bindings

The protobuf Go files in this directory are generated from Xray-core `v26.9.8`
(commit `37ceb8b4b65ee919fb772a8034e572f76a6e87a2`) and kept as a small local
subset so the control plane does not import the full Xray runtime. `handler` is
used for live add/remove/list operations. Per-user counters are read in-process
by the embedded Xray runtime and exposed through the Xray Runtime and Controller
protobuf contracts; this package intentionally has no Xray StatsService client.
The `core`, `protocol` and `serial` packages contain generated wire dependencies
required by HandlerService. The default runtime is Xray `v26.7.28`.
