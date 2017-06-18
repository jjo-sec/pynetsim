PyNetSim
========

About
--

PyNetSim is designed to be a replacement for the original INetSim project and an alternative to the excellent FakeNet-NG 
created by FireEye's FLARE team

PyNetSim's goal is to do dynamically detect protocols and the need for wrapping a connection via SSL/TLS in addition to 
trying to "speak" malware protocols for collecting network traffic, directing execution via commands sent back and 
keeping a malware sample running in memory to acquire viable memory dumps

PyNetSim by default only speaks protocols that are used by malware and only attempts to speak enough to deal with 
malware - it is not currently a viable tool to test our accurate implementations of network protocols by legitimate 
clients. 

PyNetSim *should* function correctly as a route under Cuckoo Sandbox's per-analysis networking functionality described 
here http://docs.cuckoosandbox.org/en/latest/installation/host/routing/

PyNetSim was originally presented at FIRST 2017 in San Juan, Puerto Rico. Slides are available in the repository.

PyNetSim is written in Python3 and is currently licensed under the GPLv3 license


Protocol Support
----------------
The following protocols are supported

* UDP and TCP DNS
  * A, AAAA, MX requests currently supported. TXT and special request handling to be added
* SMTP, SSL both via SMTP-SSL and STARTTLS
* FTP
* HTTP, sub-protocols supported
  * Drive DDoS bot
  * Andromeda trojan
* Default TCP protocol
  * Mirai
  * LizardStresser

Setup
-----
PyNetSim achieves traffic redirection via the REDIRECT target in IPTABLES and by default listens on port 12345 which 
allows the daemon to be run as a normal user instead of as root

IPTables Setup using an external IP of 192.168.56.101 and a default interface named enp0s3:

    sudo iptables -t nat -I PREROUTING --in-interface enp0s3 ! -d 192.168.56.101 -p tcp -j REDIRECT --to-port 12345
    sudo iptables -t nat -I PREROUTING --in-interface enp0s3 ! -d 192.168.56.101 -p udp -j REDIRECT --to-port 12345
   
And the daemon can be run via launching the daemon.py in the root directory

    python3 daemon.py

Any traffic that comes in not destined for the original source IP will now get sent to the PyNetSim daemon and all that needs to be done to setup a client to route to pynetsim is to change the default route

    route add default gw 192.168.56.101
    
   

TODO
----
There are a number of known issues to be fixed and a number of other features to be added that are in the planning stages. Please submit any issues or feature requests via GitHub
* Deal with shutdown bug that sometimes prevents a clean shutdown and may temporarily 
* Dynamically generate certificates using the hostname passed in via SNI
* Fix broken telnet and IRC support
* Create a UI to dynamically issue commands / sequences of commands to avoid hardcoding
* Store packets / payloads / connection information for later retrieval
* Make FTP protocol support more robust
* More malware protocol support
* More UDP / TCP protocol support
* Unit Tests