# ek_cheat

Exploding Kittens cheat.
Only tested on core deck, and Android app.
Doesn't guarantee you'll win, but does give you an advantage. :)

Expected use case:
1. Open EK mobile app
2. Run this script
3. Join a game
4. Watch script output to see where opponents place EK card in deck, and cards drawn from deck.

Notes
Helpful Wireshark filters
    udp.port == 5056 and frame contains "Activity"
    udp.port == 5056 and eth.dst==b4:81:a7:61:25:d3

Better capture performance with
    $ python3 -m pip install --upgrade libpcap

How to run.
./python3 ekgui.py <local network interface name> <ip address of device running EK>

Known bugs:
Sometimes the terminal rceives what appear to be control characters.
TODO: Investigate if better sanitization of bytes from the wire is needed.
