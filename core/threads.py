"""Professional thread pool: dynamic scaling, locking, error tracking."""
import queue
import threading


class ThreadPoolManager:
    """Runs batches of jobs concurrently with per-item error isolation.

    This is the doc's ``ThreadPoolManager`` fixed: counters are guarded by a
    lock and ``map()`` uses ``get_nowait()`` so no queued item is ever lost
    to a race on ``Queue.empty()``.
    """

    def __init__(self, output_callback=None, max_workers=50):
        self.output_callback = output_callback
        self.max_workers = max_workers
        self.completed_tasks = 0
        self.failed_tasks = 0
        self._lock = threading.Lock()

    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)

    def map(self, items, func, workers=None):
        """Run ``func(item)`` for each item concurrently.

        Returns the collected non-None results.  One failing item never
        kills the batch.
        """
        results = []
        q = queue.Queue()
        for it in items:
            q.put(it)
        rlock = threading.Lock()

        def worker():
            while True:
                try:
                    item = q.get_nowait()
                except queue.Empty:
                    return
                try:
                    res = func(item)
                    with rlock:
                        if res is not None:
                            results.append(res)
                        self.completed_tasks += 1
                except Exception as exc:
                    with self._lock:
                        self.failed_tasks += 1
                        self.log(f"Task failed: {exc}", "error")
                finally:
                    q.task_done()

        n = min(workers or self.max_workers, max(1, len(items)))
        threads = [threading.Thread(target=worker, daemon=True) for _ in range(n)]
        for t in threads:
            t.start()
        q.join()
        return results

    def submit(self, fn, *args, **kwargs):
        """Fire-and-forget async task on a daemon thread."""
        def runner():
            try:
                fn(*args, **kwargs)
                with self._lock:
                    self.completed_tasks += 1
            except Exception as exc:
                with self._lock:
                    self.failed_tasks += 1
                    self.log(f"Async task failed: {exc}", "error")
        threading.Thread(target=runner, daemon=True).start()
