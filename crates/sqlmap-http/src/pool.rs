//! Worker pool for concurrent HTTP requests (the port's answer to sqlmap's
//! `--threads`): independent requests run in parallel on a fixed set of
//! worker threads that share the client's connection agent. Results come
//! back in request order.

use crate::client::{Client, RequestSpec, Response};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Run `specs` concurrently on `threads` worker threads (clamped to at least
/// 1 and at most the number of specs). The returned Vec has exactly one
/// entry per spec, in the same order; a failed request yields its Err in
/// place and does not stop the others.
pub fn run_requests(
    client: &Client,
    specs: Vec<RequestSpec>,
    threads: usize,
) -> Vec<Result<Response, String>> {
    let n = specs.len();
    let workers = threads.max(1).min(n.max(1));
    let queue = Arc::new(Mutex::new(
        specs.into_iter().enumerate().collect::<VecDeque<_>>(),
    ));
    let slots: Vec<Mutex<Option<Result<Response, String>>>> =
        (0..n).map(|_| Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..workers {
            let queue = Arc::clone(&queue);
            let slots = &slots;
            s.spawn(move || {
                loop {
                    let next = queue.lock().unwrap().pop_front();
                    let Some((i, spec)) = next else { break };
                    let res = client.request(&spec);
                    *slots[i].lock().unwrap() = Some(res);
                }
            });
        }
    });
    slots
        .into_iter()
        .map(|m| m.into_inner().unwrap().expect("every spec is taken by a worker"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input() {
        let conf = sqlmap_core::config::Config::default();
        let client = Client::new(&conf);
        assert!(run_requests(&client, Vec::new(), 4).is_empty());
    }
}
