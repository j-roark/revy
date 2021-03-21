use std::sync::{mpsc, Arc, Mutex};
use std::thread;

type Job = Box<dyn FnOnce() + Send + 'static>;
enum ChildMsg {Do(Job), Die}
pub struct Pool { workers: Vec<Worker>, sender: mpsc::Sender<ChildMsg> }

impl Pool {

    pub fn new(size: usize) -> Pool {
        assert!(size > 0);
        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(size);
        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)));
        }
        Pool { workers, sender }
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);
        self.sender.send(ChildMsg::Do(job)).unwrap();
    }

}

impl Drop for Pool {
    fn drop(&mut self) {
        for _ in &self.workers { self.sender.send(ChildMsg::Die).unwrap() }
        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}

struct Worker { id: usize, thread: Option<thread::JoinHandle<()>>, }

impl Worker {

    fn new(id: usize, receiver: Arc<Mutex<mpsc::Receiver<ChildMsg>>>) -> Worker {
        let thread = thread::spawn(move || loop {
            let msg = receiver.lock().unwrap().recv().unwrap();
            match msg {
                ChildMsg::Do(job) => job(),
                ChildMsg::Die => break
            }
        });
        Worker { id: id, thread: Some(thread) }
    }

}