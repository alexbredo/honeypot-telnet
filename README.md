honeypot-telnet
===============

TELNET Honeypot (Windows NT)

Features:
 * TELNET with simple NT OS
 * Catch actions

Dependencies:
 * Twisted
 * My site-packages(3) --> common-modules

Usage:
```bash
# Generate Config
python telnet.py -d config.xml
# Run
python telnet.py
```

TODO: 
 * implement more interactions (filesystem, executables, etc.)
 * merge logic with ssh honeypot
 
Contribution welcome.

All rights reserved.
(c) 2014 by Alexander Bredo