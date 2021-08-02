use std::sync::Arc;

use keri::signer::KeyManager;

use crate::{controller::Controller, error::Error};

use super::{HandleResult, Task};

#[derive(Debug)]
pub struct GetKelTask<K: KeyManager + Send + Sync + 'static> {
    controller: Arc<Controller<K>>,
}

impl<K: KeyManager + Send + Sync + 'static> Task for GetKelTask<K> {
    fn handle(&self) -> Result<HandleResult, Error> {
        let kel = self.controller.get_kerl()?.unwrap();
        Ok(HandleResult::GotKel(kel))
    }
}
impl<K: KeyManager + Send + Sync + 'static> GetKelTask<K> {
    pub fn new(controller: Arc<Controller<K>>) -> Self {
        Self { controller }
    }
}
