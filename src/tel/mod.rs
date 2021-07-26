use keri::{
    derivation::self_addressing::SelfAddressing,
    prefix::{IdentifierPrefix, SelfAddressingPrefix},
};
use teliox::{
    database::EventDatabase,
    event::{manager_event::Config, verifiable_event::VerifiableEvent, Event},
    processor::EventProcessor,
    state::{vc_state::TelState, ManagerTelState, State},
    tel::event_generator,
};

use crate::error::Error;

pub struct Tel {
    tel_prefix: IdentifierPrefix,
    pub database: EventDatabase,
}

impl Tel {
    pub fn new(
        db: EventDatabase,
    ) -> Self {
        Self {
            database: db,
            tel_prefix: IdentifierPrefix::default(),
        }
    }

    pub fn make_inception_event(
        &self,
        issuer_prefix: IdentifierPrefix,
        config: Vec<Config>,
        backer_threshold: u64,
        backers: Vec<IdentifierPrefix>,
    ) -> Result<Event, Error> {
        event_generator::make_inception_event(
            issuer_prefix,
            config,
            backer_threshold,
            backers,
            None,
            None,
        )
        .map_err(|e| Error::from(e))
    }

    pub fn make_rotation_event(
        &self,
        ba: &[IdentifierPrefix],
        br: &[IdentifierPrefix],
    ) -> Result<Event, Error> {
        event_generator::make_rotation_event(
            &self.get_management_tel_state()?,
            ba,
            br,
            None,
            None,
        )
        .map_err(|e| Error::from(e))
    }

    pub fn make_issuance_event(&self, derivation: SelfAddressing, message: &str) -> Result<Event, Error> {
        let message_hash = derivation.derive(message.as_bytes());
        event_generator::make_issuance_event(
            &self.get_management_tel_state()?,
            message_hash,
            None,
            None,
        )
        .map_err(|e| Error::from(e))
    }

    pub fn make_revoke_event(&self, message_hash: &SelfAddressingPrefix) -> Result<Event, Error> {
        let vc_state = self.get_vc_state(message_hash)?;
        let last = match vc_state {
            TelState::Issued(last) => last,
            _ => return Err(Error::Generic("Inproper vc state".into())),
        };
        event_generator::make_revoke_event(
            message_hash,
            &last,
            &self.get_management_tel_state()?,
            None,
            None,
        )
        .map_err(|e| Error::from(e))
    }

    // Process verifiable event. It doesn't check if source seal is correct. Just add event to tel.
    pub fn process(&mut self, event: VerifiableEvent) -> Result<State, Error> {
        let processor = EventProcessor::new(&self.database);
        let state = processor.process(event)?;
        // If tel prefix is not set yet, set it to first processed management event identifier prefix.
        if self.tel_prefix == IdentifierPrefix::default() {
            if let State::Management(ref man) = state {
                self.tel_prefix = man.prefix.to_owned()
            }
        }
        Ok(state)
    }

    pub fn get_vc_state(&self, message_hash: &SelfAddressingPrefix) -> Result<TelState, Error> {
        let message_prefix = IdentifierPrefix::SelfAddressing(message_hash.to_owned());
        EventProcessor::new(&self.database)
            .get_vc_state(&message_prefix)
            .map_err(|e| Error::from(e))
    }

    pub fn get_tel(
        &self,
        message_hash: &SelfAddressingPrefix,
    ) -> Result<Vec<VerifiableEvent>, Error> {
        EventProcessor::new(&self.database)
            .get_events(message_hash)
            .map_err(|e| Error::from(e))
    }

    pub fn get_management_tel_state(&self) -> Result<ManagerTelState, Error> {
        EventProcessor::new(&self.database)
            .get_management_tel_state(&self.tel_prefix)
            .map_err(|e| Error::from(e))
    }

    pub fn get_management_events(&self) -> Result<Option<Vec<u8>>, Error> {
        EventProcessor::new(&self.database)
            .get_management_events(&self.tel_prefix)
            .map_err(|e| Error::from(e))
    }

    pub fn get_issuer(&self) -> Result<IdentifierPrefix, Error> {
        Ok(self.get_management_tel_state()?.issuer)
    }
}
