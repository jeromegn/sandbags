use aya_bpf::{
    bindings::sockaddr,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read},
    programs::TracePointContext,
};
use aya_log_ebpf::{error, info};

pub fn try_accept(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    info!(&ctx, "hello from acceptbag pid tgid: {}", pid_tgid);

    const SOCKADDR_OFFSET: usize = 24;

    let addr: *const sockaddr = unsafe { ctx.read_at(SOCKADDR_OFFSET)? };
    let addr = unsafe { bpf_probe_read(addr)? };

    info!(&ctx, "family: {}", addr.sa_family);
    // info!(&ctx, "data: {}", sa_data);

    if addr.sa_family > 0 {
        error!(&ctx, "hot damn!");
    }

    Ok(0)
}
