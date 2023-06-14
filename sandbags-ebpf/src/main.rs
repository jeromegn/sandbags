#![no_std]
#![no_main]

use aya_bpf::{macros::tracepoint, programs::TracePointContext};

use crate::accept::try_accept;

mod accept;
pub(crate) mod bindings;

#[tracepoint(name = "acceptbag")]
pub fn accept(ctx: TracePointContext) -> u32 {
    match try_accept(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
