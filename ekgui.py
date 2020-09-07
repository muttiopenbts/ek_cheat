'''Exploding Kittens cheat.
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
    udp.port == 5056 and eth.dst==a4:83:e7:61:25:d6

Better capture performance with
    $ python3 -m pip install --upgrade libpcap

How to run.
./python3 <script name> <local network interface name> <ip address of device running EK>

Known bugs:
Sometimes the terminal rceives what appear to be control characters.
TODO: Investigate if better sanitization of bytes from the wire is needed.
'''
#! /usr/bin/env python
import npyscreen
from datetime import datetime
from Player import Player, Players
import logging
logging.basicConfig(level=logging.ERROR)

from getmac import get_mac_address
import time
import os
import sys
import platform
from threading import Thread
import netifaces
from yaspin import yaspin
import threading
import pprint
import inspect
from EkGameCheat import EkGameCheat
from curses import wrapper


VICTIM_IP = ''
GATEWAY_IP = ''
SNIFF_INF = ''

spinner = yaspin()
console = ''

class BoxScroll(npyscreen.TitleBufferPager):
    _contained_widget = npyscreen.BufferPager


class ExitButton(npyscreen.ButtonPress):
    def whenPressed(self):
        self.parent.parentApp.setNextForm(None)
        raise KeyboardInterrupt


class MainForm(npyscreen.ActionForm):
    def while_waiting(self):
        #self.display()
        pass

    def create(self):
        y, x = self.useable_space()
        num_of_rows = 3
        num_of_cols = 2
        self.OK_BUTTON_TEXT = 'Exit'
        self.CANCEL_BUTTON_TEXT = ""
        row_height = y // num_of_rows

        row_pos = 0
        self.box1 = self.add(
                npyscreen.BufferPager, 
                name = "Player1",
                max_width = x // num_of_cols,
                max_height = row_height,
                relx = 1, 
                rely = (row_height * row_pos) + 1, 
                autowrap = True,
                editable = False)
        self.box2 = self.add(
                npyscreen.BufferPager, 
                name = "Player2", 
                relx = x // num_of_cols + 1, 
                rely = (row_height * row_pos) + 1, 
                max_height = row_height,
                autowrap = True,
                editable = False)

        row_pos += 1
        self.box3 = self.add(
                npyscreen.BufferPager, 
                name = "Player3",
                max_width = x // num_of_cols, 
                relx = 1,
                rely = (row_height * row_pos) + 1,
                autowrap = True,
                max_height = row_height,
                editable = False)
        self.box4 = self.add(
                npyscreen.BufferPager, 
                name = "Player4",
                relx = x // num_of_cols + 1,
                rely = (row_height * row_pos) + 1,
                max_height = row_height,
                autowrap = True,
                editable = False)

        row_pos += 1
        self.box5 = self.add(
                npyscreen.BufferPager, 
                name = "Player5",
                relx = 1,
                rely = (row_height * row_pos) + 1,
                max_height = row_height - row_pos,
                max_width = x // num_of_cols, 
                autowrap = True,
                editable = False)

        # console and status boxes will occupy space of 1 box
        status_height = 2
        console_height = row_height - status_height - row_pos

        self.console = self.add(
                npyscreen.BufferPager, 
                name = "Console",
                relx = x // num_of_cols + 1,
                rely = (row_height * row_pos) + 1,
                max_height = console_height,
                autowrap = True,
                editable = False)
                
        self.status = self.add(
                npyscreen.BufferPager, 
                name = "Status",
                relx = x // num_of_cols + 1,
                rely = (row_height * row_pos) + 1 + console_height,
                max_height = status_height,
                autowrap = True,
                editable = False)

    def on_ok(self):
        # TODO: Doesn't seem to work.
        # Exit the application if the OK button is pressed.
        self.parentApp.switchForm(None)

        self.parentApp.stop()


class MyApp(npyscreen.NPSAppManaged):
    def while_waiting(self):
        # Continues arp spoofing required
        try:
            self.game_cheat.spoofer(VICTIM_IP, self.gateway_ip) # Trick victim
            self.game_cheat.spoofer(self.gateway_ip, VICTIM_IP) # Trick gateway
            update_status(f'Spoofing {self.gateway_ip} {VICTIM_IP}')
        except KeyboardInterrupt:
            self.stop()


    def stop(self):
        os.system('reset;clear;stty sane')
        print("\nInterrupted. Restoring to normal state..")
        ip_forwarding(False)
        self.game_cheat.restore(VICTIM_IP,self.gateway_ip)
        self.game_cheat.restore(self.gateway_ip,VICTIM_IP)

        print('Closing down gracefully can take a while if there are many packets captured.')
       
        # Try to restore terminal to working order.
        os._exit(os.EX_OK)

    def onStart(self):
        # This is the refresh rate for when while_waiting() gets invoked on forms 
        self.keypress_timeout_default = 1

        self.main_form = self.addForm("MAIN", MainForm, name="Form")

        self.game_cheat = EkGameCheat(victim_ip=VICTIM_IP, 
                sniff_inf=SNIFF_INF, 
                console_cb=display_console, 
                status_cb=display_status, 
                player_cb=display_player_cb)
        #sniff_thread = AsyncSniffer(filter=f'udp port 5056', prn=send_cb, iface=SNIFF_INF)
        self.gateway_ip = self.game_cheat.GATEWAY_IP

        sniff_thread = threading.Thread(target=self.game_cheat.doSniff, args=())
        sniff_thread.start()

    def onCleanExit(self):
        npyscreen.notify_wait("Goodbye!")


def is_interface_up(interface):
    addr = netifaces.ifaddresses(interface)
    return netifaces.AF_INET in addr


def ip_forwarding(enable:bool=False):
    my_os = platform.system()

    if enable:
        if my_os == 'Linux':
            os.system(f'sudo net.ipv4.ip_forward = 1')
        elif my_os == 'Darwin':
            os.system(f'sudo sysctl -w net.inet.ip.forwarding=1')
        elif my_os == 'Windows':
            raise('O/S not supported')
    else:
        if my_os == 'Linux':
            os.system(f'sudo net.ipv4.ip_forward = 1')
        elif my_os == 'Darwin':
            os.system(f'sudo sysctl -w net.inet.ip.forwarding=0')
        elif my_os == 'Windows':
            raise('O/S not supported')


def init_config():
    global SNIFF_INF
    global VICTIM_IP
    # Prevent escape sequance output messing up screen. Meta mode ON
    os.environ['TERM'] = 'linux'

    if not (SNIFF_INF:= sys.argv[1]):
        raise Exception('Please specify an interface to launch attack from.')

    if not (VICTIM_IP:= sys.argv[2]):
        print('Please specify device running Exploding Kittens app.')
        raise KeyboardInterrupt

    # Initialize app configuration
    if not is_interface_up(SNIFF_INF):
        print('MitM interface is down.')
        raise KeyboardInterrupt

    ip_forwarding(True)

    configuration_message = f'SNIFF_INF {SNIFF_INF}\n'
    configuration_message += f'VICTIM_IP {VICTIM_IP}\n'
    input(f"{configuration_message}\nReady to start.\nOpen EK app and press enter to continue\n")
        

def display_console(**kwargs):
    global app

    data = kwargs.get('data', None)

    if data:
        app.main_form.console.buffer([repr(f'{data}')], True, True)
    
    # Display is auto invoked, but race condition means we might miss some messages.
    app.main_form.console.display()


def display_status(**kwargs):
    global app

    data = kwargs.get('data', None)

    if data:
        app.main_form.status.buffer([repr(f'{data}')], True, True)
    
    # Display is auto invoked, but race condition means we might miss some messages.
    app.main_form.status.display()


def update_console(message, call_back=display_console):
    if callable(call_back):
        call_back(data = message)


def update_status(message, call_back=display_status):
    if callable(call_back):
        call_back(data = message)


def display_player_cb(**kwargs):
    '''Can be used as a callback with no params.

    Params:
    Player object
    idx int index for reference to gui form
    '''
    global app

    player_obj = kwargs.get('player', None)
    idx = kwargs.get('idx', None) # Used for gui form ref

    # Can't display any forms if we don't have a player's index to represent which form to draw.
    # Should always exist
    if player_obj != None and idx != None:
        player_name = player_obj.names

        # No form, end
        if not (form:= getattr(app.main_form, f'box{idx+1}', None)):
            update_console(f'ERROR: display_player_cb {player_name} {idx}')
            return
        
        if not callable(form.display):
            return
            
        logging.debug(f'TRY TO display_player {player_obj.player_id} {player_name} {idx}', display_console)      

        # Function purpose is to display a player's hand
        if cards := player_obj.hand:
            # update_console(f'WORKED display_player {player_name} {idx} {cards}', display_console)

            if form and callable(form.buffer):
                form.buffer([repr(f'{player_name} {cards}')], True, True)
            else:
                #update_console(f'NOT CALLABLE display_player {player_obj.player_id} {player_name} {idx}', display_console)
                pass
        else:
            #update_console(f'FAILED cards display_player {player_name}', display_console)    

            if form and callable(form.buffer):
                form.buffer([repr(f'{player_name} {cards}')], True, True)
            else:
                # update_console(f'NOT CALLABLE display_player {player_obj.player_id} {player_name} {idx}', display_console)
                pass

        # Display is auto invoked, but race condition means we might miss some messages.
        form.display()
    else:
        update_console(f'ERROR: display_player failed. Missing player param', display_console)      


if __name__ == '__main__':
    # Set all variables needed to run
    init_config()

    app = MyApp()
    app.run()