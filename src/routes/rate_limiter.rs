use std::{sync::Arc, time::Duration};
use tokio::{sync::{Mutex, Semaphore}, time::Instant};

#[derive(Debug, Clone)]
pub struct RateLimiter {
    pub semaphore: Arc<Mutex<Semaphore>>,
    pub last_used: Arc<Mutex<Instant>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            semaphore: Arc::new(Mutex::new(Semaphore::new(3))),
            last_used: Arc::new(Mutex::new(Instant::now())),
        }
    }

    pub async fn try_acquire(&self) -> bool {
        let mut last_used_lock = self.last_used.lock().await;
        let semaphore_lock = self.semaphore.lock().await;
        let now = Instant::now();
        let mut return_value = false;

        if let Ok(permit) = semaphore_lock.try_acquire() {
            permit.forget();
            
            return_value = true;
        }

        if now.duration_since(*last_used_lock) > Duration::from_secs(60) {
            *last_used_lock = now;

            semaphore_lock.add_permits(25);
        }

        drop(last_used_lock);

        return_value
    }
}

