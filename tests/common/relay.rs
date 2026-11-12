//! UDP relay between one client and one server, with fault switches.

use {
    std::{
        net::SocketAddr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    },
    tokio::net::UdpSocket,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct RelayOptions {
    /// Hold every server→client datagram until [`Relay::release`].
    pub hold_server_to_client: bool,
    /// Added to each datagram, each way.
    pub delay: Duration,
}

#[derive(Default)]
struct S2c {
    hold: bool,
    drop: bool,
    held: Vec<Vec<u8>>,
}

pub struct Relay {
    addr: SocketAddr,
    front: Arc<UdpSocket>,
    client: Arc<Mutex<Option<SocketAddr>>>,
    server: Arc<Mutex<SocketAddr>>,
    s2c: Arc<Mutex<S2c>>,
    s2c_seen: Arc<AtomicUsize>,
    s2c_forwarded: Arc<AtomicUsize>,
    /// QUIC version of each client→server datagram's first packet; `None` = short header.
    c2s_versions: Arc<Mutex<Vec<Option<u32>>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

async fn forward(socket: &Arc<UdpSocket>, data: Vec<u8>, to: SocketAddr, delay: Duration) {
    if delay.is_zero() {
        let _ = socket.send_to(&data, to).await;
    } else {
        let socket = Arc::clone(socket);
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = socket.send_to(&data, to).await;
        });
    }
}

impl Relay {
    pub async fn start(server: SocketAddr, opts: RelayOptions) -> Self {
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = front.local_addr().unwrap();
        let client = Arc::new(Mutex::new(None));
        let server = Arc::new(Mutex::new(server));
        let s2c = Arc::new(Mutex::new(S2c {
            hold: opts.hold_server_to_client,
            drop: false,
            held: Vec::new(),
        }));
        let s2c_seen = Arc::new(AtomicUsize::new(0));
        let s2c_forwarded = Arc::new(AtomicUsize::new(0));
        let c2s_versions = Arc::new(Mutex::new(Vec::new()));

        let up = {
            let (front, back, client, server, versions) = (
                Arc::clone(&front),
                Arc::clone(&back),
                Arc::clone(&client),
                Arc::clone(&server),
                Arc::clone(&c2s_versions),
            );
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let Ok((n, from)) = front.recv_from(&mut buf).await else {
                        return;
                    };
                    *client.lock().unwrap() = Some(from);
                    let d = &buf[..n];
                    let version = (d.len() >= 5 && d[0] & 0x80 != 0)
                        .then(|| u32::from_be_bytes([d[1], d[2], d[3], d[4]]));
                    versions.lock().unwrap().push(version);
                    let to = *server.lock().unwrap();
                    forward(&back, d.to_vec(), to, opts.delay).await;
                }
            })
        };

        let down = {
            let (front, back, client, s2c, seen, fwd) = (
                Arc::clone(&front),
                Arc::clone(&back),
                Arc::clone(&client),
                Arc::clone(&s2c),
                Arc::clone(&s2c_seen),
                Arc::clone(&s2c_forwarded),
            );
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let Ok((n, _)) = back.recv_from(&mut buf).await else {
                        return;
                    };
                    seen.fetch_add(1, Ordering::SeqCst);
                    {
                        let mut st = s2c.lock().unwrap();
                        if st.drop {
                            continue;
                        }
                        if st.hold {
                            st.held.push(buf[..n].to_vec());
                            continue;
                        }
                    }
                    let Some(to) = *client.lock().unwrap() else {
                        continue;
                    };
                    forward(&front, buf[..n].to_vec(), to, opts.delay).await;
                    fwd.fetch_add(1, Ordering::SeqCst);
                }
            })
        };

        Self {
            addr,
            front,
            client,
            server,
            s2c,
            s2c_seen,
            s2c_forwarded,
            c2s_versions,
            tasks: vec![up, down],
        }
    }

    pub fn endpoint(&self) -> String {
        self.addr.to_string()
    }

    /// Send further client datagrams to `server` (a restarted server).
    pub fn retarget(&self, server: SocketAddr) {
        *self.server.lock().unwrap() = server;
    }

    /// Discard (not hold) every server→client datagram while `on`.
    pub fn drop_server_to_client(&self, on: bool) {
        self.s2c.lock().unwrap().drop = on;
    }

    /// Stop holding and deliver every held datagram in order.
    pub async fn release(&self) {
        let held = {
            let mut st = self.s2c.lock().unwrap();
            st.hold = false;
            std::mem::take(&mut st.held)
        };
        let to = self.client.lock().unwrap().expect("client seen");
        for d in held {
            let _ = self.front.send_to(&d, to).await;
            self.s2c_forwarded.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub fn s2c_seen(&self) -> usize {
        self.s2c_seen.load(Ordering::SeqCst)
    }

    pub fn s2c_forwarded(&self) -> usize {
        self.s2c_forwarded.load(Ordering::SeqCst)
    }

    pub fn c2s_versions(&self) -> Vec<Option<u32>> {
        self.c2s_versions.lock().unwrap().clone()
    }
}
