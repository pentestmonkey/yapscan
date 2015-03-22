Yapscan is primarily an TCP port scanner and ICMP scanner (Echo, Timestamp, Address Mask, Info).  The features that make it useful are real-world pentests are:
  * It sends traffic at a smooth user-defined rate - so you can always predict when your scan will finish!
  * No limitation on scan size (breaks scans into chunks to avoid hogging all your memory)
  * Sends retries in case of dropped packets

Some limitations:
  * Only works on Linux
  * Can also send UDP packets, but isn't a functional UDP port scanner
  * Doesn't do banner grabbing

Lots more info is available at:
http://pentestmonkey.net/tools/yapscan/