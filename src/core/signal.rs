use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use ctrlc;

/// Sets up a Ctrl+C handler that sets a shared atomic `running` flag to false
///
/// # Arguments
///
/// * `running_flag` - A shared atomic boolean flag used to gracefully terminate the capture loop
///
/// # Panics
///
/// Will panic if setting the handler fails
pub fn setup_ctrlc_handler(running_flag: Arc<AtomicBool>) {
    let flag_clone = Arc::clone(&running_flag);

    ctrlc::set_handler(move || {
        flag_clone.store(false, Ordering::SeqCst);
    }).expect("Failed to set Ctrl+C handler");
}