#![no_std]

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct SockPairTuple {
    pub local_ip: [u32; 4usize],
    pub local_port: u16,

    pub remote_ip: [u32; 4usize],
    pub remote_port: u16,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct SockId {
    pub direction: u8,
    pub ip: [u32; 4usize],
    pub port: u16,
}

// IPv4 mapped IPv6
// ::ffff:xy:zw = x.y.z.w
