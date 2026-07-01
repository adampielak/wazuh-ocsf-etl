use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{info, warn};

// How long to wait for a message before treating the connection as dead.
// A CLOSE-WAIT socket never returns an error from recv() — timeout forces a reconnect.
const RECV_TIMEOUT_SECS: u64 = 30;

// ─── ZeroMQ subscriber reader task ───────────────────────────────────────────

pub(crate) async fn zmq_reader_task(uri: String, tx: mpsc::Sender<(u64, String)>) {
    use zeromq::{Socket, SocketRecv, SubSocket};

    info!("ZeroMQ input: connecting to {uri}");
    loop {
        let mut socket = SubSocket::new();

        if let Err(e) = socket.connect(&uri).await {
            warn!("ZeroMQ connect {uri}: {e:#}. Retrying in 5s…");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        if let Err(e) = socket.subscribe("").await {
            warn!("ZeroMQ subscribe: {e:#}. Retrying in 5s…");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        info!("ZeroMQ input: subscribed to {uri}");

        loop {
            match tokio::time::timeout(Duration::from_secs(RECV_TIMEOUT_SECS), socket.recv()).await
            {
                Err(_elapsed) => {
                    warn!(
                        "ZeroMQ recv timeout ({}s, socket may be in CLOSE-WAIT). Reconnecting…",
                        RECV_TIMEOUT_SECS
                    );
                    break;
                }
                Ok(Err(e)) => {
                    warn!("ZeroMQ recv: {e:#}. Reconnecting in 5s…");
                    break;
                }
                Ok(Ok(msg)) => {
                    // Wazuh sends 2-frame multipart: [topic="ossec.alerts", JSON].
                    // Take the last frame as the payload; skip topic/prefix frames.
                    let raw = msg
                        .iter()
                        .rev()
                        .find_map(|frame| std::str::from_utf8(frame.as_ref()).ok())
                        .unwrap_or("")
                        .to_string();
                    let trimmed = raw.trim().to_string();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if tx.send((0, trimmed)).await.is_err() {
                        return;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
