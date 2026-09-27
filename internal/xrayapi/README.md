# Pinned Xray API bindings

The protobuf Go files in this directory are generated from Xray-core `v26.9.8`
(commit `37ceb8b4b65ee919fb772a8034e572f76a6e87a2`) and kept as a small local
subset so the control plane does not import the full Xray runtime. `stats` is
used for per-user counters and `handler` is used for live add/remove operations;
the `core`, `protocol` and `serial` packages contain only their generated wire
dependencies.
