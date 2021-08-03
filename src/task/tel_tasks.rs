use std::sync::{Arc, RwLock};

use keri::signer::KeyManager;

use super::{HandleResult, Task};
use crate::controller::{Controller, MessageHash};
use crate::error::Error;

#[derive(Debug)]
pub struct GetTelTask<K: KeyManager + Send + Sync + 'static> {
    message_hash: MessageHash,
    controller: Arc<RwLock<Controller<K>>>,
}

impl<K: KeyManager + Send + Sync + 'static> Task for GetTelTask<K> {
    fn handle(&self) -> Result<HandleResult, Error> {
        Ok(
            match self
                .controller
                .read()
                .unwrap()
                .get_tel(self.message_hash.clone())
            {
                Ok(tel) => HandleResult::GotTel(tel),
                Err(e) => HandleResult::Failure(e.to_string()),
            },
        )
    }
}
impl<K: KeyManager + Send + Sync + 'static> GetTelTask<K> {
    pub fn new(controller: Arc<RwLock<Controller<K>>>, message_hash: MessageHash) -> Self {
        Self {
            message_hash,
            controller,
        }
    }
}
