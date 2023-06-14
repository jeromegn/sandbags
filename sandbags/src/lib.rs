use aya::{include_bytes_aligned, programs::TracePoint, Bpf, BpfLoader};
use aya_log::BpfLogger;
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::{debug, warn};

static SANDBAGS_BPF_OBJ: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sandbags"));

pub fn start() -> Result<DropGuard, Error> {
    let mut bpf_loader = BpfLoader::new();
    let mut bpf = bpf_loader.load(SANDBAGS_BPF_OBJ)?;
    debug!("loaded bpf programs object");

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    let program: &mut TracePoint = bpf
        .program_mut("acceptbag")
        .ok_or(Error::BpfProgramNotFound("acceptbag"))?
        .try_into()?;
    debug!("found acceptbag program");
    program.load()?;
    debug!("loaded acceptbag program");
    let link_id = program.attach("syscalls", "sys_enter_accept4")?;
    debug!("attached __sys_accept4 program w/ id: {link_id:?}");

    let cancel = CancellationToken::new();

    let drop_guard = cancel.clone().drop_guard();
    tokio::spawn(just_wait(bpf, cancel));

    Ok(drop_guard)
}

async fn just_wait(_bpf: Bpf, cancel: CancellationToken) {
    cancel.cancelled().await;
    debug!("cancel dropped");
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Bpf(#[from] aya::BpfError),
    #[error(transparent)]
    BpfProgram(#[from] aya::programs::ProgramError),
    #[error("bpf program '{0}' not found!")]
    BpfProgramNotFound(&'static str),
}
