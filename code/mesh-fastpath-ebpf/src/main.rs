#![no_std]
#![no_main]

use core::{
    mem::{transmute}
};
use aya_ebpf::{
    bindings::{
        BPF_ANY,
        BPF_F_INGRESS,
        BPF_F_NO_PREALLOC,
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,
        sk_action,
    },
    macros::{
        map,
        sock_ops,
        sk_msg,
    },
    programs::{
        SockOpsContext,
        SkMsgContext,
    },
    maps::{
        HashMap,
    }
};
use aya_log_ebpf::{info, warn, error};

use mesh_fastpath_common::{SockPairTuple, SockId};
mod sock_hash;
mod sock_map;

const DIRECTION_CLIENT: u8 = 0;
const DIRECTION_SERVER: u8 = 1;

const AF_INET: u8 = 2;

#[map]
static mut SOCKETS_REVERSED: HashMap<SockPairTuple, SockId> = HashMap::with_max_entries(65_536, BPF_F_NO_PREALLOC);

#[map]
static SOCKETS: sock_hash::SockHash<SockId> = sock_hash::SockHash::with_max_entries(65_536, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

/// `intercept_active_sockets` (`sock_ops` hook)
///
/// adds the socket to `SockHash`
/// .
#[sock_ops]
fn intercept_active_sockets(ctx: SockOpsContext) -> u32 {
    match try_intercept_active_sockets(&ctx) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "`intercept_active_sockets` errored: {}", ret);
            return 0;
        },
    }
}

fn try_intercept_active_sockets<'a>(ctx: &SockOpsContext) -> Result<u32, &'a str> {
    let ops = unsafe { *ctx.ops };

    let family = ops.family as u8;

    let local_ip = if family == AF_INET {
        [0, 0, 0xffff, ops.local_ip4.swap_bytes()]
    } else {
        ops.local_ip6
    };
    let local_port = ops.local_port as u16;

    let remote_ip = if family == AF_INET {
        [0, 0, 0xffff, ops.remote_ip4.swap_bytes()]
    } else {
        ops.remote_ip6
    };
    let remote_port = ops.remote_port.swap_bytes() as u16;

    if
        !(ops.op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || ops.op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
    {
        return Ok(0);
    }

    let sock_pair_tuple = SockPairTuple {
        local_ip,
        local_port,
        remote_ip,
        remote_port,
    };

    let mut sock_id = if ops.op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB {
        // the current socket is from the CLIENT side. getting LOCAL ip and port
        SockId {
            direction:  DIRECTION_CLIENT,
            ip: local_ip,
            port: local_port,
        }
    } else {
        // the current socket is from the SERVER side. getting REMOTE ip and port
        SockId {
            direction:  DIRECTION_SERVER,
            ip: remote_ip,
            port: remote_port,
        }
    };

    let op_str = match ops.op {
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB =>  " active",
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => "passive",
        _ => "",
    };

    let result = SOCKETS.update(sock_id, ctx.ops, BPF_ANY as u64);

    // reverse the direction and save the socket
    sock_id.direction = if sock_id.direction == DIRECTION_CLIENT { DIRECTION_SERVER } else { DIRECTION_CLIENT };
    unsafe { SOCKETS_REVERSED.insert(&sock_pair_tuple, &sock_id, 0) };

    if let Err(e) = result {
        info!(ctx, "[intercept_active_sockets] op {}; failed {}; {:i}:{} -> {:i}:{}",
            op_str,
            e,
            unsafe { transmute::<[u32; 4], [u8; 16]>(local_ip) },
            local_port,
            unsafe { transmute::<[u32; 4], [u8; 16]>(remote_ip) },
            remote_port,
        );
    } else {
        info!(ctx, "[intercept_active_sockets] op {};  saved; {:i}:{} -> {:i}:{}",
            op_str,
            unsafe { transmute::<[u32; 4], [u8; 16]>(local_ip) },
            local_port,
            unsafe { transmute::<[u32; 4], [u8; 16]>(remote_ip) },
            remote_port,
        );
    };

    return Ok(0);
}

/// `redirect_between_sockets` (`sk_msg` hook)
///
/// intercepts packet to bypass the network stack by redirecting it from a socket to another socket
/// .
#[sk_msg]
fn redirect_between_sockets(ctx: SkMsgContext) -> u32 {
    match try_redirect_between_sockets(&ctx) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "`redirect_between_sockets` errored: {}", ret);
            return sk_action::SK_PASS;
        },
    }
}

fn try_redirect_between_sockets<'a>(ctx: &SkMsgContext) -> Result<u32, &'a str> {
    let msg = unsafe { *ctx.msg };

    let family = msg.family as u8;

    let local_ip = if family == AF_INET {
        [0, 0, 0xffff, msg.local_ip4.swap_bytes()]
    } else {
        msg.local_ip6
    };
    let local_port = msg.local_port as u16;

    let remote_ip = if family == AF_INET {
        [0, 0, 0xffff, msg.remote_ip4.swap_bytes()]
    } else {
        msg.remote_ip6
    };
    let remote_port = msg.remote_port.swap_bytes() as u16;

    let sock_pair_tuple = SockPairTuple {
        local_ip,
        local_port,

        remote_ip,
        remote_port,
    };

    let socket_id = match unsafe { SOCKETS_REVERSED.get(&sock_pair_tuple) } {
        Some(id) => id,
        None => {
            return Ok(sk_action::SK_PASS);
        },
    };

    let result = SOCKETS.redirect_msg(&ctx, *socket_id, BPF_F_INGRESS as u64) as u32;

    if result == sk_action::SK_PASS {
        info!(ctx, "[redirect_between_sockets] redirected {:i}:{} -> {:i}:{}",
            unsafe { transmute::<[u32; 4], [u8; 16]>(local_ip) },
            local_port,
            unsafe { transmute::<[u32; 4], [u8; 16]>(remote_ip) },
            remote_port,
        );
    } else {
        warn!(ctx, "[redirect_between_sockets]   fallback {:i}:{} -> {:i}:{}",
            unsafe { transmute::<[u32; 4], [u8; 16]>(local_ip) },
            local_port,
            unsafe { transmute::<[u32; 4], [u8; 16]>(remote_ip) },
            remote_port,
        );
    };

    return Ok(sk_action::SK_PASS);
}
