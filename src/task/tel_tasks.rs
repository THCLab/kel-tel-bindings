use std::sync::Arc;

use keri::signer::KeyManager;

use super::{HandleResult, Task};
use crate::controller::{Controller, MessageHash};
use crate::error::Error;

#[derive(Debug)]
pub struct GetTelTask<K: KeyManager + Send + Sync + 'static> {
    message_hash: MessageHash,
    controller: Arc<Controller<K>>,
}

impl<K: KeyManager + Send + Sync + 'static> Task for GetTelTask<K> {
    fn handle(&self) -> Result<HandleResult, Error> {
        Ok(HandleResult::GotTel(
            self.controller.get_tel(self.message_hash.clone())?,
        ))
    }
}
impl<K: KeyManager + Send + Sync + 'static> GetTelTask<K> {
    pub fn new(controller: Arc<Controller<K>>, message_hash: MessageHash) -> Self {
        Self {
            message_hash,
            controller,
        }
    }
}
