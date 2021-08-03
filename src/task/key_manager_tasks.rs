use std::{
    fmt::Debug,
    sync::{Arc, RwLock},
};

use crate::{controller::Controller, error::Error};
use keri::signer::KeyManager;

use super::{HandleResult, Task};

#[derive(Debug)]
pub struct SignMessageTask<K: KeyManager + Send + Sync + 'static> {
    message: Vec<u8>,
    controller: Arc<RwLock<Controller<K>>>,
}

impl<K: KeyManager + Send + Sync + 'static> Task for SignMessageTask<K> {
    fn handle(&self) -> Result<HandleResult, Error> {
        let signature = self
            .controller
            .read()
            .unwrap()
            .sign(&self.message.clone())?;
        Ok(HandleResult::MessageSigned(signature))
    }
}

impl<K: KeyManager + Send + Sync + 'static> SignMessageTask<K> {
    pub fn new(controller: Arc<RwLock<Controller<K>>>, message: Vec<u8>) -> Self {
        SignMessageTask {
            controller,
            message,
        }
    }
}
