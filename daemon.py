import logging
import pynetsim.lib.core as core
from concurrent.futures import ThreadPoolExecutor
from pynetsim.lib.listener import UDPSocketListener, TCPSocketListener

log = logging.getLogger("pynetsim.daemon")


def main():
    config = core.get_config()
    core.init_logging("pynetsim", log_level=getattr(logging, config.get("main").get("log_level", "debug").upper()))
    log.debug("Starting socket listeners")
    listener_pool = ThreadPoolExecutor(max_workers=2)
    futures = []
    tcp_listener = TCPSocketListener(config)
    udp_listener = UDPSocketListener(config)
    futures.append(listener_pool.submit(tcp_listener.start))
    futures.append(listener_pool.submit(udp_listener.start))
    core.wait()

    log.debug("Stopping socket listeners")
    tcp_listener.shutdown()
    udp_listener.shutdown()
    for future in futures:
        if future.running():
            future.cancel()
    tcp_listener.shutdown()
    udp_listener.shutdown()
    log.debug("Exiting...")

if __name__ == "__main__":
    main()