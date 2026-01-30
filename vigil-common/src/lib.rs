#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub pid: u32,
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectEvent {}
