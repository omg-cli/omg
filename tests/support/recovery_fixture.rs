//! Private missing-package and transport fixtures. No upstream proxy requests.

use std::io::{Read as _, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

pub struct RejectedProxy {
    url: String,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Default for RejectedProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl RejectedProxy {
    pub fn new() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind isolated proxy");
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let count = Arc::clone(&requests);
        let stopped = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        count.fetch_add(1, Ordering::SeqCst);
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        let mut request = [0; 4096];
                        // A client can close before sending or reading. Neither
                        // case permits forwarding; the connection still counts.
                        let _ = stream.read(&mut request);
                        let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("isolated proxy accept failed: {error}"),
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    pub fn env(&self) -> Vec<(&str, &str)> {
        [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ]
        .into_iter()
        .map(|key| (key, self.url.as_str()))
        .chain([("NO_PROXY", ""), ("no_proxy", "")])
        .collect()
    }

    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for RejectedProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker
            .take()
            .unwrap()
            .join()
            .expect("isolated proxy worker panicked");
    }
}
