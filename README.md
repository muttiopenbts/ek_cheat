# Exploding Kittens cheat
Only tested on core deck, and Android app.
Doesn't guarantee you'll win, but does give you an advantage. :)

## Notes
Helpful Wireshark filters
    udp.port == 5056 and frame contains "Activity"
    udp.port == 5056 and eth.dst==b4:81:a7:61:25:d3

Better capture performance with
    $ python3 -m pip install --upgrade libpcap

## How to run
### Install
```
$ git clone https://github.com/muttiopenbts/ek_cheat.git
$ cd ek_cheat
$ pipenv install
```
### Play
1. Open EK mobile app
2. Run this script
```
$ ./ekgui.py <network interface name> <ip address of where EK mobile app is running>
```
3. Join an EK game on the app
4. Watch script output to see where opponents place EK card in deck, and cards drawn from deck.

## Tested on
MacOS Monterey