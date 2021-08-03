use std::{
    fmt::{Debug, Display},
    path::Path,
    str::FromStr,
    sync::{Arc, RwLock},
};

use crate::{
    error::Error,
    task::{
        controller_tasks::{IssueTask, RevokeTask},
        kel_tasks::GetKelTask,
        key_manager_tasks::SignMessageTask,
        tel_tasks::GetTelTask,
        HandleResult,
    },
    task_manager::TaskManager,
};
use crate::{kerl::KERL, tel::Tel};
use crossbeam_channel::Sender;
use keri::{
    derivation::self_addressing::SelfAddressing,
    event::{
        sections::seal::{EventSeal, Seal},
        EventMessage,
    },
    prefix::{Prefix, SelfAddressingPrefix},
    signer::KeyManager,
};
use teliox::{event::Event, seal::EventSourceSeal};

#[derive(Clone, Debug)]
pub struct MessageHash {
    sai: SelfAddressingPrefix,
}

impl MessageHash {
    pub fn new(data: &[u8]) -> Self {
        Self {
            sai: SelfAddressing::Blake3_256.derive(data),
        }
    }
}

impl Display for MessageHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.sai.to_str())
    }
}

impl Into<SelfAddressingPrefix> for MessageHash {
    fn into(self) -> SelfAddressingPrefix {
        self.sai
    }
}

impl FromStr for MessageHash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sai = s
            .parse()
            .map_err(|_| Error::Generic("Can't parse message hash".into()))?;
        Ok(Self { sai })
    }
}

pub enum UpdateType {
    Issue(String),
    Revoke(MessageHash),
}

#[derive(Debug)]
pub struct Controller<K: KeyManager + Send + Sync + 'static> {
    key_manager: Arc<K>,
    kerl: Arc<KERL>,
    tel: Arc<Tel>,
}

impl<K: KeyManager + Send + Sync> Controller<K> {
    pub fn init(km: K, db_dir_path: &Path) -> Result<Self, Error> {
        let tel_db_path = db_dir_path.join(Path::new("./kel"));
        let kel_db_path = db_dir_path.join(Path::new("./tel"));
        let mut tel = Tel::new(tel_db_path.as_path())?;
        let mut kerl = KERL::new(kel_db_path.as_path())?;
        kerl.incept(&km)?;

        let vcp = tel.make_inception_event(kerl.get_prefix(), vec![], 0, vec![])?;

        let seal = to_event_seal(&vcp)?;
        let ixn = kerl.make_ixn_with_seal(&vec![seal], &km)?;

        let ixn_source_seal = to_source_seal(&ixn.event_message)?;

        tel.incept_tel(vcp, ixn_source_seal)?;

        Ok(Controller {
            key_manager: Arc::new(km),
            kerl: Arc::new(kerl),
            tel: Arc::new(tel),
            // TODO remove magic number
        })
    }

    pub fn update(&self, up_type: UpdateType) -> Result<(), Error> {
        let ev = match up_type {
            UpdateType::Issue(message) => self.tel.make_issuance_event(&message),
            UpdateType::Revoke(hash) => self.tel.make_revoke_event(&hash.to_string()),
        }?;

        let seal = to_event_seal(&ev)?;
        let ixn = self.kerl.make_ixn_seal(&vec![seal])?;
        let serialized_ixn = ixn.serialize().unwrap();
        let signature = self.key_manager.sign(&ixn.serialize().unwrap()).unwrap();
        self.kerl.process(&serialized_ixn, &signature)?;

        let ixn_source_seal = to_source_seal(&ixn)?;

        self.tel.process(ev, ixn_source_seal)?;
        Ok(())
    }

    // TODO:
    // rotate()
    // get_pub_key(message_hash)
    // verify(message, signature)

    pub fn get_tel(&self, message_hash: MessageHash) -> Result<Vec<u8>, Error> {
        Ok(self
            .tel
            .get_tel(&message_hash.clone().into())
            .unwrap()
            .iter()
            .map(|e| e.serialize().unwrap())
            .flatten()
            .collect::<Vec<u8>>())
    }

    pub fn get_kerl(&self) -> Result<Option<Vec<u8>>, Error> {
        self.kerl.get_kerl()
    }

    pub fn sign(&self, message: &Vec<u8>) -> Result<Vec<u8>, Error> {
        self.key_manager.sign(&message).map_err(|e| e.into())
    }
}

fn to_event_seal(event: &Event) -> Result<Seal, Error> {
    Ok(Seal::Event(EventSeal {
        prefix: event.get_prefix(),
        sn: event.get_sn(),
        event_digest: SelfAddressing::Blake3_256.derive(&event.serialize()?),
    }))
}

fn to_source_seal(event_message: &EventMessage) -> Result<EventSourceSeal, Error> {
    Ok(EventSourceSeal {
        sn: event_message.event.sn,
        digest: SelfAddressing::Blake3_256.derive(&event_message.serialize()?),
    })
}

pub struct Dispatcher<K: KeyManager + Send + Sync + 'static> {
    controller: Arc<RwLock<Controller<K>>>,
    task_manager: Arc<TaskManager>,
}

impl<K: KeyManager + Send + Sync> Dispatcher<K> {
    pub fn init(km: K, db_dir_path: &Path) -> Result<Self, Error> {
        Ok(Dispatcher {
            controller: Arc::new(RwLock::new(Controller::init(km, db_dir_path)?)),
            // TODO remove magic number
            task_manager: Arc::new(TaskManager::new(5)),
        })
    }

    pub fn issue(&self, msg: String, sender: Sender<HandleResult>) -> Result<(), Error> {
        let task = IssueTask::new(msg, Arc::clone(&self.controller));
        self.task_manager.push(Box::new(task), sender)
    }

    pub fn revoke(&self, msg_hash: String, sender: Sender<HandleResult>) -> Result<(), Error> {
        let task = RevokeTask::new(msg_hash, Arc::clone(&self.controller));
        self.task_manager.push(Box::new(task), sender)
    }

    pub fn get_kel(&self, sender: Sender<HandleResult>) -> Result<(), Error> {
        let task = GetKelTask::new(Arc::clone(&self.controller));
        self.task_manager.push(Box::new(task), sender)
    }

    pub fn get_tel(&self, msg: MessageHash, sender: Sender<HandleResult>) -> Result<(), Error> {
        let task = GetTelTask::new(Arc::clone(&self.controller), msg);
        self.task_manager.push(Box::new(task), sender)
    }

    pub fn sign(&self, msg: Vec<u8>, sender: Sender<HandleResult>) -> Result<(), Error> {
        let task = SignMessageTask::new(Arc::clone(&self.controller), msg);
        self.task_manager.push(Box::new(task), sender)
    }

    pub fn listen(&self) -> Result<(), Error> {
        TaskManager::listen(Arc::clone(&self.task_manager))?;
        Ok(())
    }
}

#[test]
pub fn test_responses() -> Result<(), Error> {
    use crossbeam_channel::bounded;
    use keri::signer::CryptoBox;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let km = CryptoBox::new().unwrap();
    let controller = Arc::new(Dispatcher::init(km, dir.path())?);

    let c = Arc::clone(&controller);
    c.listen()?;

    let cont = Arc::clone(&controller);
    let (s1, r1) = bounded(0);
    cont.issue("vc2".to_owned(), s1.clone()).unwrap();
    assert!(matches!(r1.recv(), Ok(HandleResult::Issued(_))));

    let cont = Arc::clone(&controller);
    let (s2, r2) = bounded(0);
    cont.sign("msg".as_bytes().to_vec(), s2).unwrap();
    assert!(matches!(r2.recv(), Ok(HandleResult::MessageSigned(_))));

    let cont = Arc::clone(&controller);
    let (s3, r3) = bounded(0);
    cont.get_kel(s3.clone()).unwrap();
    assert!(matches!(r3.recv(), Ok(HandleResult::GotKel(_))));

    Ok(())
}
