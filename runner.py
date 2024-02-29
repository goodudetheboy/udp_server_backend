import time
import logging
from hotreload import Loader


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    script = Loader("server.py")

    while True:
        # Check if script has been modified since last poll.
        if script.has_changed():
            # Execute a function from script if it has been modified.
            host = "127.0.0.1"  # Use "0.0.0.0" to listen on all available interfaces
            port = 1337

            # Start the UDP server
            script.udp_server(host, port)

        time.sleep(1)