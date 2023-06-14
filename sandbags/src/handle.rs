use std::future::Future;

use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::{tc, SchedClassifier, TcAttachType},
    util::online_cpus,
    Bpf, BpfLoader,
};

use eyre::{eyre, Context};
use flycast_common::logging::Log;
use tripwire::{Outcome, PreemptibleFutureExt};

static BPF_CODE: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sandbags"));

/// A handle for the flycast BPF program
pub struct Handle {
    bpf: Bpf,
}

impl Handle {
    pub fn new() -> eyre::Result<Self> {
        let mut bpf_loader = BpfLoader::new();

        let bpf = bpf_loader
            .load(BPF_CODE)
            .map_err(|e| eyre!("could not load flycast bpf program: {:?}", e))?;
        let handle = Handle { bpf };

        Ok(handle)
    }

    pub fn attach(&mut self, iface: &str) -> eyre::Result<()> {
        let _ = tc::qdisc_add_clsact(iface);

        let program: &mut SchedClassifier = self.bpf.program_mut("flycast").unwrap().try_into()?;
        program.load()?;

        // detach the previous program
        let detached = tc::qdisc_detach_program(iface, TcAttachType::Egress, "flycast");
        if let Err(e) = detached {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }

        // attach the new program
        let link_id = program.attach(iface, TcAttachType::Egress).map_err(|e| {
            eyre!(
                "could not attach flycast program to network interface, err: {}",
                e
            )
        })?;

        // forget the bpf program so it is not shutdown when the proxy is shutdown
        let owned_link = program.take_link(link_id)?;
        std::mem::forget(owned_link);

        Ok(())
    }

    pub fn spawn_logger(
        &self,
        tripwire: impl Future<Output = ()> + Clone + Unpin + Send + 'static,
    ) -> eyre::Result<()> {
        let mut perf_array = AsyncPerfEventArray::try_from(self.bpf.map_mut("flycast_events")?)?;
        for cpu in online_cpus()? {
            let mut buf = perf_array.open(cpu, None)?;

            let mut tw = tripwire.clone();
            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| bytes::BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();

                loop {
                    match buf.read_events(&mut buffers).preemptible(&mut tw).await {
                        Outcome::Preempted => return,
                        Outcome::Completed(events) => {
                            let events = events.unwrap();
                            for buf in buffers.iter_mut().take(events.read) {
                                let ptr = buf.as_ptr() as *const Log;
                                let data = unsafe { ptr.read_unaligned() };
                                tracing::debug!("flycast bpf: {}", data);
                            }
                        }
                    }
                }
            });
        }

        Ok(())
    }

    /// Start the flycast BPF program.
    pub async fn run(
        &self,
        tripwire: impl Future<Output = ()> + Clone + Unpin + Send + 'static,
    ) -> eyre::Result<()> {
        self.spawn_logger(tripwire.clone())
            .wrap_err("Failed to spawn flycast bpf logger")?;
        tripwire.await;
        Ok(())
    }
}
