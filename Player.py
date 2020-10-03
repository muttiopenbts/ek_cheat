import logging
logging.basicConfig(level=logging.ERROR)


class Player:
    def __init__(self, player_id=None, names=[], device_id=None, avatar_id=None, hand={}, display_cb=None):
        self.player_id = player_id
        self.names = names
        self.device_id = device_id
        self.avatar_id = avatar_id
        self.hand = hand
        self.display_cb = display_cb
        self.index = None # TODO: Not used yet


class Players:
    def __init__(self, players=[]):
        self.players = players

    def get_player_name(self, player_id):
        '''Extract player name from list of players.
        player_obj =[
            {'player_id':,
            'device_id:,
            'player_names':[],
            },
        ]
        '''
        player_obj = self.players

        # prevent overwriting existing entry of user
        found = self.get_index(player_id)
        # We now have an index into the list of players or not found

        if found != None:
            return player_obj[found].names

    def get_player(self, player_id):
        player_obj = self.players

        # prevent overwriting existing entry of user
        found = self.get_index(player_id)
        # We now have an index into the list of players or not found

        if found != None:
            return player_obj[found]

    def get_index(self, player_id):
        found = next((idx for idx, sub in enumerate(self.players) if sub.player_id == player_id), None)
        return found

    def get_player_cards(self, idx):
        '''Extract player cards from using list index into players.
        '''
        if len(self.players) >= idx:
            return self.players[idx].hand

    def save_card(self, player_id, card):
        '''card = Type byte'''
        # Don't save Bomb card to player hand
        if 'Bomb' in card.decode():
            return

        # prevent overwriting existing entry of user
        found = self.get_index(player_id)
        # We now have an index into the list of players or not found

        if found != None:
            # Update
            player_record = self.players[found]

            if player_record.hand == None:
                # Create new card list
                self.players[found].hand = {card}
            else:
                # I believe each card name is unique.
                # Just add to list
                self.players[found].hand.add(card)
            
            # Display player hand
            if callable(self.players[found].display_cb):
                self.players[found].display_cb(idx=found, player=self.players[found])
            else:
                raise Exception(f'Player display not callable from save_card() {found}')

    def save_player(self, player:Player):
        '''Update player details into an obj.
        player_obj =[
            {'player_id':,
            'device_id:,
            'player_names':[],
            'display_cb': func_cb
            },
        ]
        '''
        player_names = player.names # List
        player_id = player.player_id
        device_id = player.device_id
        avatar_id = player.avatar_id
        display_cb = player.display_cb
        # Every player starts with 1 Defuser card
        cards = player.hand or {b'Defuse0.0'} 

        # prevent overwriting existing entry of user
        found = self.get_index(player_id)
        # We now have an index into the list of players or not found

        if found != None:
            # Merge lists then convert to set (remove dups), convert back to list
            self.players[found].names = list(set((
                    self.players[found].names + player_names
            )))
            self.players[found].avatar_id = avatar_id
                

        else: # New entry
            new_player = Player(
                    player_id = player_id,
                    names = player_names,
                    device_id = device_id,
                    avatar_id = avatar_id,
                    hand = cards,
                    display_cb = display_cb,
            )
            self.players.append(new_player)
            #logging.debug(f'player not found: {player_id}, found: {found}, playerobj: {pp.pprint(player_obj)}')
        
        # Fire off a callback if player obj has one
        if callable(display_cb):
            if found != None:
                display_cb(player=self.players[found], idx=found)
            else:
                found = self.get_index(player_id)

                if found != None and callable(display_cb):
                    display_cb(player=self.players[found], idx=found)
        else:
            logging.error('Callback not callable')

    def remove_card(self, player_id, card):
        # prevent overwriting existing entry of user
        found = self.get_index(player_id)
        # We now have an index into the list of players or not found

        if found != None:
            # Update
            player_record = self.players[found]

            try:
                if player_record.hand != None:
                    # When game starts, we don't know the exact name of starting defuser card.
                    if 'defuse' in str(card.lower()):
                        found_defuser = next((hand_card for hand_card in self.players[found].hand 
                                if 'defuse' in str(hand_card.lower())), None)
                        if found_defuser:
                            # We know the caller wants to remove a defuser and we have a defuser in hand.
                            card = found_defuser

                    self.players[found].hand.discard(card)
                else:
                    # Appears we are removing a card we don't have a record of. Do nothing
                    pass
            except ValueError:
                pass

            # Display player hand
            if callable(self.players[found].display_cb):
                self.players[found].display_cb(idx=found, player=player_record)