use crate::error::Error;
use crossbeam_channel::Sender;
use std::fmt::Debug;

pub mod controller_tasks;
pub mod kel_tasks;
pub mod key_manager_tasks;
pub mod tel_tasks;

pub trait Task {
    fn handle(&self) -> Result<HandleResult, Error>;
}

impl Debug for dyn Task {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub trait DebugableTask: Task + Debug {}

// #[derive(Debug)]
pub struct AddressedTask {
    task: Box<dyn Task + Send + Sync>,
    sender: Sender<HandleResult>,
}

impl AddressedTask {
    pub fn new(task: Box<dyn Task + Send + Sync>, sender: Sender<HandleResult>) -> Self {
        Self { task, sender }
    }

    pub fn handle_and_send(&self) {
        self.sender.send(self.task.handle().unwrap()).unwrap();
    }
}

#[derive(Debug)]
pub enum HandleResult {
    GotTel(Vec<u8>),
    GotKel(Vec<u8>),
    Issued(Vec<u8>),
    Revoked,
    MessageSigned(Vec<u8>),
}
