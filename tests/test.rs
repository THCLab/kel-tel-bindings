use std::{error::Error, sync::Arc};

use crossbeam_channel::unbounded;
use keri::signer::CryptoBox;
use solid_adventure::{controller::Dispatcher, task::HandleResult};
use tempfile::tempdir;

#[test]
pub fn test_multithread_response() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
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
