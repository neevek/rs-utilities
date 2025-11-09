use std::time::{Duration, Instant};

pub struct CachedValue<T, E, F>
where
    F: Fn() -> Result<T, E>,
{
    value: Option<T>,
    fetched_at: Option<Instant>,
    ttl: Duration,
    fetcher: F,
}

impl<T: Clone, E, F: Fn() -> Result<T, E>> CachedValue<T, E, F> {
    pub fn new(ttl: Duration, fetcher: F) -> Self {
        Self {
            value: None,
            fetched_at: None,
            ttl,
            fetcher,
        }
    }

    pub fn get(&mut self) -> Result<T, E> {
        let expired = self.fetched_at.is_none_or(|t| t.elapsed() >= self.ttl);
        if expired {
            let new_value = (self.fetcher)()?;
            self.value = Some(new_value);
            self.fetched_at = Some(Instant::now());
        }

        Ok(self.value.as_ref().unwrap().clone())
    }

    pub fn invalidate(&mut self) {
        self.fetched_at = None;
    }
}
