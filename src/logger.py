import time
import logging
import queue
import threading

class LogRequest:
    def __init__(self, msg: str, delay: float, logger: logging.Logger):
        self.msg = msg
        self.logger = logger
        self.scheduled_time = int(time.time()) + delay

    def log_msg(self) -> bool:
        if time.time() >= self.scheduled_time:
            self.logger.warning(self.msg)
            return True
        else:
            return False

def delayed_logger_thread(
        packet_id: int,
        log_queue: queue.Queue[LogRequest],
        exit_event: threading.Event
    ) -> None:
    """
    A thread for processing logging, with added delay function

    Args:
        packet_id (int): packet_id that this logger is assigned to process
        log_queue (queue.Queue[LogRequest]): queue to log

    """
    logging.info(f"Logger processing packet_id {hex(packet_id)} starting up.")
    while not exit_event.is_set():
        # Fetch data from packet queue
        try:
            log_req = log_queue.get(block=True, timeout=1)
        except queue.Empty:
            continue
        
        while log_req.log_msg() is False:
            time.sleep(1)
            continue
        
    logging.info(f"Logger processing packet_id {hex(packet_id)} shutting down.")
