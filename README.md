Marscoin Core integration/staging tree
======================================

http://www.marscoin.org  
http://www.marscoin.org/foundation  
Copyright (c) 2009-2013 Bitcoin Developers  
Copyright (c) 2011-2013 Litecoin Developers  
Copyright (c) 2013-2025 Marscoin Developers  


What is Marscoin?
----------------

Marscoin targets to become the blockchain for Mars, and functions as a proof of concept for incentivizing and privatizing space exploration funding.

- scrypt Litecoin-based cryptocurrency
- ASERT difficulty adjustment algorithm 
- confirmation block every 2 Mars minutes (123 seconds)
- subsidy halves every Mars year (668 sols)
- 721 blocks per sol
- 40 million total coins by ~2025 (39569900 exactly)
- 1M donation for non-profit The Mars Society
- developed and supported by The Marscoin Foundation, LLC (a non-profit).
- check out the MartianRepublic.org for our experimental governance platform

For more information, as well as an immediately useable, binary version of
the Marscoin client sofware, see http://www.marscoin.org and http://www.marscoinfoundation.org


How do I build the software?
----------------------------

The easiest way to build the repository is via the depends method:

    apt update
    apt install -y build-essential automake autotools-dev cmake pkg-config python3 bison git make libtool
    git clone https://github.com/marscoin/marscoin
    cd marscoin/depends
    make HOST=x86_64-pc-linux-gnu -j4
    cd ..
    ./autogen.sh
    CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site ./configure
    make -j4


