# eSeMeshA

## Performance metrics visualization and graphs
```bash
conda create -f graphs/environment.yml -y
# or
micromamba create -f graphs/environment.yml -y
```

## Service meshes

## Workloads
- [ping echo](./workloads/ping-echo)

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`
2. `cargo install bindgen-cli`

## Build

1. eBPF
  ```bash
  cargo run --bin xtask build-ebpf
  ```

2. Userspace
  ```bash
  cargo build
  ```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Run

```bash
RUST_LOG=info cargo run --bin xtask run
```
