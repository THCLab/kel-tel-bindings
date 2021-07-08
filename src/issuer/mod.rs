use crate::{error::Error, kerl::KERL};
use keri::{
    database::{sled::SledEventDatabase},
    derivation::self_addressing::SelfAddressing,
    event::sections::seal::{EventSeal, Seal},
    prefix::{IdentifierPrefix},
    signer::KeyManager,
};
use teliox::{
    database::EventDatabase,
    event::{manager_event::Config, verifiable_event::VerifiableEvent, Event},
    seal::EventSourceSeal,
    tel::Tel,
};

pub struct Issuer<'d, 't> {
    prefix: IdentifierPrefix,
    kerl: KERL<'d>,
    tel: Tel<'t>,
}

impl<'d, 't> Issuer<'d, 't> {
    pub fn new(db: &'d SledEventDatabase, tel_db: &'t EventDatabase) -> Self {
        let kerl = KERL::new(&db, IdentifierPrefix::default()).unwrap();
        let tel = Tel::new(
            tel_db,
            keri::event::SerializationFormats::JSON,
            SelfAddressing::Blake3_256,
        );

        Issuer {
            prefix: IdentifierPrefix::default(),
            kerl,
            tel: tel,
        }
    }

    pub fn incept_tel<K: KeyManager>(&mut self, km: &K) -> Result<(), Error> {
        let vcp = self.tel.make_inception_event(
            self.prefix.clone(),
            vec![Config::NoBackers],
            0,
            vec![],
        )?;

        let management_tel_prefix = vcp.clone().prefix;

        // create vcp seal which will be inserted into issuer kel (ixn event)
        let vcp_seal = Seal::Event(EventSeal {
            prefix: management_tel_prefix.clone(),
            sn: vcp.sn,
            event_digest: SelfAddressing::Blake3_256.derive(&vcp.serialize()?),
        });

        let ixn = self.kerl.make_ixn_with_seal(&vec![vcp_seal], km)?;

        let ixn_source_seal = EventSourceSeal {
            sn: ixn.event_message.event.sn,
            digest: SelfAddressing::Blake3_256.derive(&ixn.serialize()?),
        };

        // before applying vcp to management tel, insert anchor event seal to be able to verify that operation.
        let verifiable_vcp =
            VerifiableEvent::new(Event::Management(vcp.clone()), ixn_source_seal.into());
        self.tel.process(verifiable_vcp.clone())?;

        Ok(())
    }

    pub fn incept_kel<K: KeyManager>(&mut self, km: &K) -> Result<(), Error> {
        self.kerl.incept(km)?;
        self.prefix = self.kerl.get_state().unwrap().unwrap().prefix;
        Ok(())
    }

    pub fn update_backers<K: KeyManager>(
        &mut self,
        ba: &[IdentifierPrefix],
        br: &[IdentifierPrefix],
        km: &K,
    ) -> Result<(), Error> {
        let rcp = self.tel.make_rotation_event(ba.to_vec(), br.to_vec())?;

        // create rcp seal which will be inserted into issuer kel (ixn event)
        let rcp_seal = Seal::Event(EventSeal {
            prefix: rcp.prefix.clone(),
            sn: rcp.sn,
            event_digest: SelfAddressing::Blake3_256.derive(&rcp.serialize()?),
        });

        let ixn = self.kerl.make_ixn_with_seal(&vec![rcp_seal], km)?;

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

    pub fn issue<K: KeyManager>(&mut self, vc: &str, km: &K) -> Result<(), Error> {
        let iss = self.tel.make_issuance_event(vc)?;

        // let management_tel_prefix = vcp.clone().prefix;

        // create vcp seal which will be inserted into issuer kel (ixn event)
        let iss_seal = Seal::Event(EventSeal {
            prefix: iss.prefix.clone(),
            sn: iss.sn,
            event_digest: SelfAddressing::Blake3_256.derive(&iss.serialize()?),
        });

        let ixn = self.kerl.make_ixn_with_seal(&vec![iss_seal], km)?;

        let ixn_source_seal = EventSourceSeal {
            sn: ixn.event_message.event.sn,
            digest: SelfAddressing::Blake3_256.derive(&ixn.serialize()?),
        };

        // before applying vcp to management tel, insert anchor event seal to be able to verify that operation.
        let verifiable_vcp = VerifiableEvent::new(Event::Vc(iss.clone()), ixn_source_seal.into());
        self.tel.process(verifiable_vcp.clone())?;
        Ok(())
    }

    pub fn revoke<K: KeyManager>(&mut self, message: &str, km: &K) -> Result<(), Error> {
        let rev_event = self.tel.make_revoke_event(message)?;
        // create rev seal which will be inserted into issuer kel (ixn event)
        let rev_seal = Seal::Event(EventSeal {
            prefix: rev_event.prefix.clone(),
            sn: rev_event.sn,
            event_digest: SelfAddressing::Blake3_256.derive(&rev_event.serialize()?),
        });

        let ixn = self.kerl.make_ixn_with_seal(&vec![rev_seal], km)?;

        // Make source seal.
        let ixn_source_seal = EventSourceSeal {
            sn: ixn.event_message.event.sn,
            digest: SelfAddressing::Blake3_256.derive(&ixn.serialize()?),
        };

        // before applying iss to tel, insert anchor event seal to be able to verify that operation.
        let verifiable_rev =
            VerifiableEvent::new(Event::Vc(rev_event.clone()), ixn_source_seal.into());

        self.tel.process(verifiable_rev.clone())?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::fs;

    use keri::{
        database::sled::SledEventDatabase, derivation::self_addressing::SelfAddressing,
        prefix::IdentifierPrefix, signer::CryptoBox,
    };
    use teliox::{database::EventDatabase, state::vc_state::TelState};

    use crate::{error::Error, issuer::Issuer};

    #[test]
    pub fn test_issuing() -> Result<(), Error> {
        use tempfile::Builder;
        // Create test db and key manager.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        fs::create_dir_all(root.path()).unwrap();
        let db = SledEventDatabase::new(root.path()).unwrap();
        let km = CryptoBox::new()?;

        let message = "some vc";

        let tel_root = Builder::new().prefix("tel-test-db").tempdir().unwrap();
        fs::create_dir_all(tel_root.path()).unwrap();
        let tel_db = EventDatabase::new(tel_root.path()).unwrap();

        let mut issuer = Issuer::new(&db, &tel_db);

        issuer.incept_kel(&km)?;
        issuer.incept_tel(&km)?;

        let management_tel_prefix = issuer.tel.get_management_tel_state().unwrap().prefix;
        // Chcek if iss event is in db.
        let o = issuer
            .tel
            .processor
            .get_management_events(&management_tel_prefix)?;
        assert!(o.is_some());
        println!("{}", String::from_utf8(o.unwrap()).unwrap());

        let vc_hash = SelfAddressing::Blake3_256.derive(message.as_bytes());
        issuer.issue(message, &km)?;

        // Chcek if iss event is in db.
        let o = issuer
            .tel
            .processor
            .get_events(&IdentifierPrefix::SelfAddressing(vc_hash))?;
        assert!(o.is_some());

        let state = issuer.tel.get_vc_state(message.as_bytes())?;
        assert!(matches!(state, TelState::Issued(_)));

        issuer.revoke(message, &km)?;
        let state = issuer.tel.get_vc_state(message.as_bytes())?;
        assert!(matches!(state, TelState::Revoked));

        assert!(issuer.update_backers(&vec![], &vec![], &km).is_err());

        Ok(())
    }
}
