use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

/**
 * UserManager struct responsible for resolving UIDs to usernames.
 * Uses a cache to store resolved usernames to avoid repeated shell command executions.
 */
#[derive(Clone)]
pub struct UserManager {
    cache: Arc<Mutex<HashMap<u32, String>>>,
}

impl UserManager {
    /**
     * Creates a new UserManager with an empty cache.
     */
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /**
     * Resolves a UID to a username.
     * First checks the cache, if not found, executes `id -nu <uid>`.
     * Returns "unknown" if resolution fails.
     */
    pub fn get_user(&self, uid: u32) -> String {
        // First check cache
        {
            let cache = self.cache.lock().unwrap();
            if let Some(username) = cache.get(&uid) {
                return username.clone();
            }
        }

        // Resolution logic
        let username = self.resolve_user(uid);

        // Update cache
        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(uid, username.clone());
        }

        username
    }

    fn resolve_user(&self, uid: u32) -> String {
        match Command::new("id").arg("-nu").arg(uid.to_string()).output() {
            Ok(output) => {
                if output.status.success() {
                    String::from_utf8_lossy(&output.stdout).trim().to_string()
                } else {
                    "unknown".to_string()
                }
            }
            Err(_) => "unknown".to_string(),
        }
    }
}
