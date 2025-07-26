#[derive(Debug, Clone)]
pub enum UiMode {
    Capture,
    HelpOverlay,
    DeviceMenu {
        options: Vec<String>,
        selected: usize,
    },
    FilterMenu {
        interface: String,
        input: String,
        cursor_pos: usize,
        options: Vec<(String, String)>,
        selected: usize,
    },
}

#[derive(Debug)]
pub struct UiState {
    pub mode: UiMode,
    pub error_msg: Option<String>,
    pub info_msg: Option<String>
}

impl UiState {
    pub fn new() -> Self {
        UiState {
            mode: UiMode::Capture,
            error_msg: None,
            info_msg: None,
        }
    }
    pub fn set_error(&mut self, msg: impl Into<String>) {
        self.error_msg = Some(msg.into());
    }

    pub fn clear_error(&mut self) {
        self.error_msg = None;
    }

    pub fn set_info(&mut self, msg: impl Into<String>) {
        self.info_msg = Some(msg.into());
        self.error_msg = None;  // clear error when info is set
    }

    pub fn clear_info(&mut self) {
        self.info_msg = None;
    }
}
