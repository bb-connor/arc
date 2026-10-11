use super::*;

/// A work-stealing stack.
#[derive(Debug)]
pub(super) struct Stack {
    /// This thread's index.
    index: usize,
    /// The thread-local stack.
    deque: Deque<Message>,
    /// The work stealers.
    stealers: Arc<[Stealer<Message>]>,
}

impl Stack {
    /// Create a work-stealing stack for each thread. The given messages
    /// correspond to the initial paths to start the search at. They will
    /// be distributed automatically to each stack in a round-robin fashion.
    pub(super) fn new_for_each_thread(threads: usize, init: Vec<Message>) -> Vec<Stack> {
        // Using new_lifo() ensures each worker operates depth-first, not
        // breadth-first. We do depth-first because a breadth first traversal
        // on wide directories with a lot of gitignores is disastrous (for
        // example, searching a directory tree containing all of crates.io).
        let deques: Vec<Deque<Message>> =
            std::iter::repeat_with(Deque::new_lifo).take(threads).collect();
        let stealers = Arc::<[Stealer<Message>]>::from(
            deques.iter().map(Deque::stealer).collect::<Vec<_>>(),
        );
        let stacks: Vec<Stack> = deques
            .into_iter()
            .enumerate()
            .map(|(index, deque)| Stack {
                index,
                deque,
                stealers: stealers.clone(),
            })
            .collect();
        // Distribute the initial messages, reverse the order to cancel out
        // the other reversal caused by the inherent LIFO processing of the
        // per-thread stacks which are filled here.
        init.into_iter()
            .rev()
            .zip(stacks.iter().cycle())
            .for_each(|(m, s)| s.push(m));
        stacks
    }

    /// Push a message.
    pub(super) fn push(&self, msg: Message) {
        self.deque.push(msg);
    }

    /// Pop a message.
    pub(super) fn pop(&self) -> Option<Message> {
        self.deque.pop().or_else(|| self.steal())
    }

    /// Steal a message from another queue.
    fn steal(&self) -> Option<Message> {
        // For fairness, try to steal from index + 1, index + 2, ... len - 1,
        // then wrap around to 0, 1, ... index - 1.
        let (left, right) = self.stealers.split_at(self.index);
        // Don't steal from ourselves
        let right = &right[1..];

        right
            .iter()
            .chain(left.iter())
            .map(|s| s.steal_batch_and_pop(&self.deque))
            .find_map(|s| s.success())
    }
}
