use std::{
    fmt::Debug,
    sync::{Arc, RwLock},
};

use crate::error::Error;
use keri::signer::KeyManager;

use crate::controller::{Controller, MessageHash, UpdateType};

use super::{HandleResult, Task};

#[derive(Debug)]
pub struct IssueTask<K: KeyManager + Send + Sync + 'static> {
    message: String,
    controller: Arc<RwLock<Controller<K>>>,
}

// impl<K: KeyManager + Debug> DebugableTask for IssueTask<K> {}

impl<K: KeyManager + Send + Sync + 'static> Task for IssueTask<K> {
    fn handle(&self) -> Result<HandleResult, Error> {
        let op_type = UpdateType::Issue(self.message.clone());
        let signature = {
            let cont = self.controller.write().unwrap();
            cont.update(op_type)?;

            cont.sign(&self.message.as_bytes().to_vec()).unwrap()
        };
        Ok(HandleResult::Issued(signature))
    }
}

impl<K: KeyManager + Send + Sync> IssueTask<K> {
    pub fn new(message: String, controller: Arc<RwLock<Controller<K>>>) -> Self {
        IssueTask {
            message,
            controller,
        }
    }
}

#[derive(Debug)]
pub struct RevokeTask<K: KeyManager + Send + Sync + 'static> {
    message_hash: MessageHash,
    controller: Arc<RwLock<Controller<K>>>,
}

// impl<K: KeyManager + Debug> DebugableTask for IssueTask<K> {}

impl<K: KeyManager + Send + Sync + 'static> Task for RevokeTask<K> {
    fn handle(&self) -> Result<HandleResult, Error> {
        let op_type = UpdateType::Revoke(self.message_hash.clone());
        {
            self.controller.write().unwrap().update(op_type)?;
        }
        Ok(HandleResult::Revoked)
    }
}

impl<K: KeyManager + Send + Sync> RevokeTask<K> {
    pub fn new(message_hash: String, controller: Arc<RwLock<Controller<K>>>) -> Self {
        RevokeTask {
            message_hash: message_hash.parse().unwrap(),
            controller,
        }
    }
}
