use std::sync::{Arc, RwLock};

use keri::signer::KeyManager;

use crate::{controller::Controller, error::Error};

use super::{HandleResult, Task};

#[derive(Debug)]
pub struct GetKelTask<K: KeyManager + Send + Sync + 'static> {
    controller: Arc<RwLock<Controller<K>>>,
}

impl<K: KeyManager + Send + Sync + 'static> Task for GetKelTask<K> {
    fn handle(&self) -> Result<HandleResult, Error> {
        Ok(match self.controller.read().unwrap().get_kerl() {
            Ok(kel) => HandleResult::GotKel(kel.unwrap()),
            Err(e) => HandleResult::Failure(e.to_string()),
        })
    }
}

impl<K: KeyManager + Send + Sync + 'static> GetKelTask<K> {
    pub fn new(controller: Arc<RwLock<Controller<K>>>) -> Self {
        Self { controller }
    }
}
