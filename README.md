PyNetSim
========

PyNetSim is designed to be a replacement for the original INetSim project and an alternative to the excellent FakeNet-NG created by FireEye's FLARE team

The goal is to do dynamically detect protocols and the need for wrapping a connection via SSL/TLS in addition to trying to "speak" malware protocols for collecting network traffic, directing execution via commands sent back and keeping a malware sample running in memory to acquire viable memory dumps

PyNetSim by default only speaks protocols that are used by malware and only attempts to speak enough to deal with malware - it is not currently a viable tool to test our accurate implementations of network protocols by legitimate clients. 

PyNetSim was originally presented at FIRST 2017 in San Juan, Puerto Rico. Slides are available in the repository.

Protocol Support
----------------
The following protocols are supported

* UDP and TCP DNS
* SMTP, SSL both via SMTP-SSL and STARTTLS
* FTP
* HTTP, sub-protocols supported
  * Drive DDoS bot
  * Andromeda trojan
* Default TCP protocol
  * Mirai
  * LizardStresser

TODO
----
* Dynamically generate certificates using the hostname passed in via SNI
* Fix broken telnet and IRC support
* Create a UI to dynamically issue commands / sequences of commands to avoid hardcoding
* Store packets / payloads / connection information for later retrieval
* Make FTP protocol support more robust
* More malware protocol support
* More UDP / TCP protocol support