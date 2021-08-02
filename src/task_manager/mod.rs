use std::sync::Arc;

use crossbeam_channel::Sender;
use crossbeam_queue::ArrayQueue;

use crate::{
    error::Error,
    task::{AddressedTask, HandleResult, Task},
};

pub struct TaskManager {
    queue: ArrayQueue<AddressedTask>,
}

impl TaskManager {
    pub fn new(n: usize) -> TaskManager {
        Self {
            queue: ArrayQueue::new(n),
        }
    }

    pub fn push(
        &self,
        task: Box<dyn Task + Send + Sync>,
        sender: Sender<HandleResult>,
    ) -> Result<(), Error> {
        let at = AddressedTask::new(task, sender);
        self.queue.push(at).map_err(|_at| Error::QueueError)
    }

    // Spawn thread which check if queue was updated.
    pub fn listen(tm: Arc<TaskManager>) -> Result<(), Error> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(3)
            .build()
            .unwrap();

        pool.spawn(move || loop {
            tm.process_queue().unwrap();
        });
        Ok(())
    }

    // Process task from queue if there is any.
    fn process_queue(&self) -> Result<(), Error> {
        let task = self.queue.pop();
        if task.is_some() {
            std::thread::spawn(move || {
                task.unwrap().handle_and_send();
            });
        }

        Ok(())
    }
}
