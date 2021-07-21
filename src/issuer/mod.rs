use std::path::Path;

use crate::{error::Error, kerl::KERL, tel::Tel};
use keri::{database::sled::SledEventDatabase, derivation::{self_addressing::SelfAddressing, self_signing::SelfSigning}, event::{event_data::EventData, sections::seal::{EventSeal, Seal}}, prefix::{BasicPrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix}, signer::KeyManager};
use teliox::{
    database::EventDatabase,
    event::{manager_event::Config, verifiable_event::VerifiableEvent, Event},
    seal::EventSourceSeal,
    state::vc_state::TelState,
};

pub struct Controller<K: KeyManager> {
    key_manager: K,
    kerl: KERL,
    tel: Tel,
}

impl<K: KeyManager> Controller<K> {
    fn new(root: &Path, tel_db: &Path, key_manager: K) -> Self {
        let db = SledEventDatabase::new(root).unwrap();
        let tel_db = EventDatabase::new(tel_db).unwrap();
        let tel = Tel::new(
            tel_db,
            keri::event::SerializationFormats::JSON,
            SelfAddressing::Blake3_256,
        );

        Controller {
            key_manager,
            kerl: KERL::new(db, IdentifierPrefix::default()).unwrap(),
            tel,
        }
    }

    pub fn init(
        kel_db_path: &Path,
        tel_db_path: &Path,
        km: K,
        backers: Option<Vec<IdentifierPrefix>>,
        backer_threshold: u64,
    ) -> Result<Self, Error> {
        let mut controller = Controller::new(kel_db_path, tel_db_path, km);
        controller.incept_kel()?;
        controller.incept_tel(backers, backer_threshold)?;
        Ok(controller)
    }

    /// Generate and process tel inception event for given backers and backer
    /// threshold. None in backers argument sets config to no backers.
    fn incept_tel(
        &mut self,
        backers: Option<Vec<IdentifierPrefix>>,
        backer_threshold: u64,
    ) -> Result<(), Error> {
        let (config, b) = match backers {
            Some(backers) => (vec![], backers),
            None => (vec![Config::NoBackers], vec![]),
        };
        let vcp = self.tel.make_inception_event(
            self.kerl.get_state().unwrap().unwrap().prefix.clone(),
            config,
            backer_threshold,
            b,
        )?;

        // create vcp seal which will be inserted into issuer kel (ixn event)
        let vcp_seal = Seal::Event(EventSeal {
            prefix: vcp.clone().prefix,
            sn: vcp.sn,
            event_digest: SelfAddressing::Blake3_256.derive(&vcp.serialize()?),
        });

        let ixn = self.kerl.make_ixn_with_seal(&vec![vcp_seal], &self.key_manager)?;

        let ixn_source_seal = EventSourceSeal {
            sn: ixn.event_message.event.sn,
            digest: SelfAddressing::Blake3_256.derive(&ixn.event_message.serialize()?),
        };

        // before applying vcp to management tel, insert anchor event seal to be able to verify that operation.
        let verifiable_vcp =
            VerifiableEvent::new(Event::Management(vcp.clone()), ixn_source_seal.into());
        self.tel.process(verifiable_vcp)?;

        Ok(())
    }

    // Generate and process kel inception event.
    fn incept_kel(&mut self) -> Result<(), Error> {
        self.kerl.incept(&self.key_manager)?;
        Ok(())
    }

    // Generate and process management tel rotation event for given backers to
    // add (ba) and backers to remove (br).
    pub fn update_backers(
        &mut self,
        ba: &[IdentifierPrefix],
        br: &[IdentifierPrefix],
    ) -> Result<(), Error> {
        let rcp = self.tel.make_rotation_event(ba, br)?;

        // create rcp seal which will be inserted into issuer kel (ixn event)
        let rcp_seal = Seal::Event(EventSeal {
            prefix: rcp.prefix.clone(),
            sn: rcp.sn,
            event_digest: SelfAddressing::Blake3_256.derive(&rcp.serialize()?),
        });

        let ixn = self.kerl.make_ixn_with_seal(&vec![rcp_seal], &self.key_manager)?;

        let ixn_source_seal = EventSourceSeal {
            sn: ixn.event_message.event.sn,
            digest: SelfAddressing::Blake3_256.derive(&ixn.serialize()?),
        };

        // before applying vcp to management tel, insert anchor event seal to be able to verify that operation.
        let verifiable_rcp =
            VerifiableEvent::new(Event::Management(rcp.clone()), ixn_source_seal.into());
        self.tel.process(verifiable_rcp.clone())?;
        Ok(())
    }

    pub fn issue(&mut self, message: &str) -> Result<Vec<u8>, Error> {
        let iss = self.tel.make_issuance_event(message)?;
        // create vcp seal which will be inserted into issuer kel (ixn event)
        let iss_seal = Seal::Event(EventSeal {
            prefix: iss.prefix.clone(),
            sn: iss.sn,
            event_digest: SelfAddressing::Blake3_256.derive(&iss.serialize()?),
        });

        let ixn = self.kerl.make_ixn_with_seal(&vec![iss_seal], &self.key_manager)?;

        let ixn_source_seal = EventSourceSeal {
            sn: ixn.event_message.event.sn,
            digest: SelfAddressing::Blake3_256.derive(&ixn.event_message.serialize()?),
        };

        let verifiable_vcp = VerifiableEvent::new(Event::Vc(iss.clone()), ixn_source_seal.into());
        self.tel.process(verifiable_vcp.clone())?;
        self.key_manager.sign(&message.as_bytes().to_vec()).map_err(|e| e.into())
    }

    pub fn revoke(&mut self, message: &str) -> Result<(), Error> {
        let message_id = SelfAddressing::Blake3_256.derive(message.as_bytes());
        let rev_event = self.tel.make_revoke_event(&message_id)?;
        // create rev seal which will be inserted into issuer kel (ixn event)
        let rev_seal = Seal::Event(EventSeal {
            prefix: rev_event.prefix.clone(),
            sn: rev_event.sn,
            event_digest: SelfAddressing::Blake3_256.derive(&rev_event.serialize()?),
        });

        let ixn = self.kerl.make_ixn_with_seal(&vec![rev_seal], &self.key_manager)?;

        // Make source seal.
        let ixn_source_seal = EventSourceSeal {
            sn: ixn.event_message.event.sn,
            digest: SelfAddressing::Blake3_256.derive(&ixn.serialize()?),
        };

        let verifiable_rev =
            VerifiableEvent::new(Event::Vc(rev_event.clone()), ixn_source_seal.into());

        self.tel.process(verifiable_rev.clone())?;
        Ok(())
    }

    pub fn rotate(&mut self) -> Result<(), Error> {
        self.key_manager.rotate()?;
        self.kerl.rotate(&self.key_manager)?;
        Ok(())
    }

    /// Check the state of message of given digest.
    pub fn get_vc_state(&self, hash: &SelfAddressingPrefix) -> Result<TelState, Error> {
        self.tel.get_vc_state(hash).map_err(|e| e.into())
    }

    pub fn get_tel(&self, hash: &SelfAddressingPrefix) -> Result<Vec<VerifiableEvent>, Error> {
        self.tel.get_tel(hash)
    }

    /// Returns keys that was used to sign message of given hash. Returns error,
    /// if message was revoked or not yet issued.
    pub fn get_pub_key(
        &self,
        message_hash: SelfAddressingPrefix,
    ) -> Result<Vec<BasicPrefix>, Error> {
        let (tel_event, source_seal) = {
            let ver_event = self
            .tel
            .get_tel(&message_hash)?
            // TODO what if events are out of order?
            .last()
            .ok_or(Error::Generic("No events in tel".into()))?.to_owned();
            (ver_event.event, ver_event.seal.seal)
        };

        let event_prefix = match tel_event {
            Event::Management(ref man) => &man.prefix,
            Event::Vc(ref vc) => &vc.prefix,
        };
        
        let serialized_event = match tel_event {
            Event::Management(ref man) => man.serialize()?,
            Event::Vc(ref ev) => ev.serialize()?,
        };
        if self.kerl.check_seal(source_seal.sn, event_prefix, &serialized_event)?{

        let k = self.kerl.get_state_for_seal(
            &self.tel.get_issuer()?,
            source_seal.sn,
            &source_seal.digest,
        )?;

        match k {
            Some(state) => Ok(state.current.public_keys),
            None => Err(Error::Generic("No key data".into())),
        }} else {
            Err(Error::Generic("improper seal".into()))
        }
    }

    /// Verify signature for given message.
    pub fn verify(&self, message: &str, signature: &[u8]) -> Result<bool, Error> {
        let message_hash = SelfAddressing::Blake3_256.derive(message.as_bytes());
        match self.get_vc_state(&message_hash)? {
            TelState::NotIsuued => Err(Error::Generic("Not yet issued".into())),
            TelState::Issued(_) => {
                let key = self.get_pub_key(message_hash)?;
                Ok(key.into_iter().fold(true, |acc, k| {
                    let sspref = SelfSigning::Ed25519Sha512.derive(signature.to_vec());
                    acc && k.verify(message.as_bytes(), &sspref).unwrap()
                }))
            }
            TelState::Revoked => Err(Error::Generic("VC was revoked".into())),
        }
    }
}

#[cfg(test)]
mod test {
    use keri::{
        derivation::self_addressing::SelfAddressing,
        signer::CryptoBox,
    };
    use teliox::state::vc_state::TelState;

    use crate::{error::Error, issuer::Controller};

    #[test]
    pub fn test_issuing() -> Result<(), Error> {
        use tempfile::Builder;
        // Create test db and key manager.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        let tel_root = Builder::new().prefix("tel-test-db").tempdir().unwrap();
        let km = CryptoBox::new()?;

        let message = "some vc";

        let mut issuer = Controller::init(root.path(), tel_root.path(), km, Some(vec![]), 0)?;

        let message_hash = SelfAddressing::Blake3_256.derive(message.as_bytes());

        let signature = issuer.issue(message)?;
        let verification_result = issuer.verify(message, &signature);
        assert!(matches!(verification_result, Ok(true)));

        // Chcek if iss event is in db.
        let o = issuer.get_tel(&message_hash)?;
        assert_eq!(o.len(), 1);

        let state = issuer.get_vc_state(&message_hash)?;
        assert!(matches!(state, TelState::Issued(_)));

        // Try to verify message after key rotation.
        issuer.rotate()?;

        let verification_result = issuer.verify(message, &signature);
        assert!(matches!(verification_result, Ok(true)));

        issuer.revoke(message)?;
        let state = issuer.get_vc_state(&message_hash)?;
        assert!(matches!(state, TelState::Revoked));

        // Check if revoke event is in db.
        let o = issuer.get_tel(&message_hash)?;
        assert_eq!(o.len(), 2);

        // Message verification should return error, because it was revoked.
        let verification_result = issuer.verify(message, &signature);
        assert!(verification_result.is_err());

        Ok(())
    }
}
