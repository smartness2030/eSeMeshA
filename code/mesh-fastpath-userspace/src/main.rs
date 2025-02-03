use anyhow::Context;
use aya::{
    include_bytes_aligned,
    Ebpf,
    maps::SockHash,
    programs::{
        CgroupAttachMode,
        SockOps,
        SkMsg,
    },
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;

use mesh_fastpath_common::SockId;

use std::{
    fs::File,
    mem,
    os::fd::AsFd,
};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup/")]
    cgroup: String,
}

const LOAD_SKMSG: bool = true;
const LOAD_SOCKOPS: bool = true;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/debug/mesh-fastpath-ebpf"))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/mesh-fastpath-ebpf"))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let cgroup_file = File::open(opt.cgroup)?;
    let cgroup_fd = cgroup_file.as_fd();

    if LOAD_SOCKOPS {
        let program_name = "intercept_active_sockets";
        let intercept_active_sockets: &mut SockOps = bpf.program_mut(program_name).unwrap().try_into()?;
        intercept_active_sockets.load()?;
        intercept_active_sockets.attach(cgroup_fd, CgroupAttachMode::default())
            .context(format!("failed to attach the SockOps program `{program_name}`"))?;

        info!("SockOps program `{program_name}` -> LOADED");
    }

    if LOAD_SKMSG {
        let sockets: SockHash<_, [u8; mem::size_of::<SockId>()]> = bpf.map("SOCKETS").unwrap().try_into()?;
        let sockets_fd = sockets.fd().try_clone()?;

        let program_name = "redirect_between_sockets";
        let redirect_between_sockets: &mut SkMsg = bpf.program_mut(program_name).unwrap().try_into()?;
        redirect_between_sockets.load()?;
        redirect_between_sockets.attach(&sockets_fd)
            .context(format!("failed to attach the SkMsg program `{program_name}`"))?;

        info!("SkMsg program `{program_name}` -> LOADED");
    }

    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
