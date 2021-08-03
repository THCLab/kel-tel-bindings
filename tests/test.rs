use std::sync::Arc;

use crossbeam_channel::unbounded;
use keri::{event::event_data::EventData, event_message::parse::Deserialized, signer::CryptoBox};
use solid_adventure::{controller::Dispatcher, error::Error, task::HandleResult};
use tempfile::tempdir;

#[test]
pub fn test_issuing() -> Result<(), Error> {
    let dir = tempdir().unwrap();
    let km = CryptoBox::new()?;

    let controller = Dispatcher::init(km, dir.path())?;
    controller.listen().unwrap();

    let (issuing_sender, issuing_receiver) = unbounded();

    let msg = "hi".to_string();
    controller.issue(msg, issuing_sender.clone())?;
    let _recv = issuing_receiver.recv().unwrap();

    controller.get_kel(issuing_sender.clone())?;
    match issuing_receiver.recv().unwrap() {
        HandleResult::GotKel(kel) => {
            let parsed_kel = keri::event_message::parse::signed_event_stream(&kel)
                .unwrap()
                .1;
            let mut ilks = parsed_kel.into_iter().map(|ev| match ev {
                Deserialized::Event(e) => e.event.event.event.event_data,
                Deserialized::NontransferableRct(_) => todo!(),
                Deserialized::TransferableRct(_) => todo!(),
            });
            assert!(matches!(ilks.next(), Some(EventData::Icp(_))));
            assert!(matches!(ilks.next(), Some(EventData::Ixn(_))));
            assert!(matches!(ilks.next(), Some(EventData::Ixn(_))));
            assert!(matches!(ilks.next(), None));
            Ok(())
        }
        _ => Err(Error::Generic("Wrong result type.".into())),
    }?;

    Ok(())
}

#[test]
pub fn test_multithread_response() -> Result<(), Error> {
    let dir = tempdir().unwrap();
    let km = CryptoBox::new()?;

    let controller = Arc::new(Dispatcher::init(km, dir.path())?);
    controller.listen().unwrap();

    for i in 0..50 {
        let (sender0, receiver0) = unbounded();
        let (issuing_sender, issuing_receiver) = unbounded();
        let msg = i.to_string();
        std::thread::spawn(move || {
            let cont: Arc<Dispatcher<CryptoBox>> = receiver0.recv().unwrap();
            cont.issue(msg.clone(), issuing_sender).unwrap();
        });

        let (sender1, receiver1) = unbounded();
        let (kel_sender, kel_receiver) = unbounded();
        std::thread::spawn(move || {
            let cont: Arc<Dispatcher<CryptoBox>> = receiver1.recv().unwrap();
            cont.get_kel(kel_sender).unwrap();
        });

        std::thread::spawn(move || {
            assert!(matches!(
                issuing_receiver.recv(),
                Ok(HandleResult::Issued(_))
            ));
        });

        std::thread::spawn(move || {
            assert!(matches!(kel_receiver.recv(), Ok(HandleResult::GotKel(_))));
        });

        sender0.send(Arc::clone(&controller)).unwrap();
        sender1.send(Arc::clone(&controller)).unwrap();
    }
    Ok(())
}
