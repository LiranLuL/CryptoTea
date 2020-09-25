from kivy.app import App
from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.config import Config
import time

Config.set ('graphics', 'resizable', '1')
Config.set ('graphics', 'width', '360')
Config.set ('graphics', 'height', '640')
#Config.set('graphics', 'fullscreen', '1')


from kivy.core.window import Window

from kivy.properties import StringProperty

from kivy.animation import Animation

from kivy.uix.label import Label

from kivy.factory import Factory

from web3 import Web3
import etherscan  
from eth_account import Account 

import os.path
import hashlib
import rc4
import datetime

import qrcode
import pyzbar
from kivy_garden.zbarcam import ZBarCam




Builder.load_file("FirstInput.kv")
Builder.load_file("PickPassword.kv")
Builder.load_file("InputPassword.kv")
Builder.load_file("RegistrationOrSign.kv")
Builder.load_file("PickPasswordTwo.kv")
Builder.load_file("HomeScreen.kv")
Builder.load_file("MnemonicWords.kv")
Builder.load_file("MnemonicEnter.kv")
Builder.load_file("SettingMnemonicWords.kv")
Builder.load_file("PublicKeyList.kv")
Builder.load_file("PrivateOrMnemonic.kv")
Builder.load_file("Mnemonic.kv")
Builder.load_file("PrivateKey.kv")
Builder.load_file("SettingMnemonicWordsTwo.kv")
Builder.load_file("PickPasswordSign.kv")
Builder.load_file("PickPasswordSignTwo.kv")
Builder.load_file("GetETH.kv")
Builder.load_file("SendETH.kv")
Builder.load_file("Parameters.kv")
Builder.load_file("Security.kv")
Builder.load_file("PasswordConfirmation.kv")
Builder.load_file("Transaction.kv")
Builder.load_file("PasswordConfirmationTwo.kv")
Builder.load_file("ChangePassword.kv")
Builder.load_file("ChangePasswordTwo.kv")


#Builder.load_file(".kv")

class Registration:
    def add_account(self, *args):
        # Registration
        Account.enable_unaudited_hdwallet_features() 
        acct, mnemonic = Account.create_with_mnemonic()
        # Get private key
        private_class = Account.from_mnemonic(mnemonic) 
        private_dict = private_class.__dict__ 
        private_key = str(private_dict['_key_obj'])
        print (mnemonic)
        print(private_key)
        CteaPerceApp.mnemonic = mnemonic   
        CteaPerceApp.public = acct.address
        CteaPerceApp.private_key = private_key
        
    def load_cash(self, password):
        mnem = open('mnem.txt', 'r', encoding='utf-8').read()
        unhash_mnem = Hash.decode_rc4(Hash, mnem, password)

        public = open('public.txt', 'r', 1).read()

        private = open('private.txt', 'r', encoding='utf-8').read()
        unhash_private = Hash.decode_rc4(Hash, private, password)

        password = open('pass.txt', 'r', 1).read()

        CteaPerceApp.mnemonic = unhash_mnem
        CteaPerceApp.public = public
        CteaPerceApp.private_key = unhash_private
        CteaPerceApp.password = password
        print(CteaPerceApp.mnemonic)

    def preload(self):
        if os.path.isfile('pass.txt') and \
        os.path.isfile('public.txt') and \
        os.path.isfile('private.txt') and \
        os.path.isfile('mnem.txt'):
            return True
        else:
            return False

class CteaPerceApp(App):
    password = ''
    mnemonic = ''
    private_key = ''
    public = ''
    def build(self):
        self.sm = ScreenManager()
        self.sm.add_widget(FirstInput(name = "FirstInput"))
        self.sm.add_widget(RegistrationOrSign(name = "RegistrationOrSign"))
        self.sm.add_widget(InputPassword(name = "InputPassword"))
        self.sm.add_widget(PickPassword(name = "PickPassword"))
        self.sm.add_widget(PickPasswordTwo(name = "PickPasswordTwo"))
        self.sm.add_widget(PrivateOrMnemonic(name = "PrivateOrMnemonic"))
        self.sm.add_widget(HomeScreen(name = "HomeScreen"))
        self.sm.add_widget(MnemonicWords(name = "MnemonicWords"))
        self.sm.add_widget(MnemonicEnter(name = "MnemonicEnter"))
        self.sm.add_widget(SettingMnemonicWords(name = "SettingMnemonicWords"))
        self.sm.add_widget(PublicKeyList(name = "PublicKeyList"))
        self.sm.add_widget(Mnemonic(name = "Mnemonic"))
        self.sm.add_widget(PrivateKey(name = "PrivateKey"))
        self.sm.add_widget(SettingMnemonicWordsTwo(name = "SettingMnemonicWordsTwo"))
        self.sm.add_widget(PickPasswordSign(name = "PickPasswordSign"))
        self.sm.add_widget(PickPasswordSignTwo(name = "PickPasswordSignTwo"))
        self.sm.add_widget(GetETH(name = "GetETH"))
        self.sm.add_widget(SendETH(name = "SendETH"))
        self.sm.add_widget(Parameters(name = "Parameters"))
        self.sm.add_widget(Security(name = "Security"))
        self.sm.add_widget(PasswordConfirmation(name = "PasswordConfirmation"))
        self.sm.add_widget(Transaction(name = "Transaction"))
        self.sm.add_widget(PasswordConfirmationTwo(name = "PasswordConfirmationTwo"))
        self.sm.add_widget(ChangePassword(name = "ChangePassword"))
        self.sm.add_widget(ChangePasswordTwo(name = "ChangePasswordTwo"))





        screen = Screen(name="SettingMnemonicWords")
        self.sm.switch_to(screen, direction='right')
        #       self.sm.add_widget((name = ""))
        self.auth()
        return self.sm
    def auth(self):    
        self.sm.current = 'FirstInput'
        if Registration.preload(self):
            self.sm.current = 'InputPassword'
        else:
            self.sm.current = 'RegistrationOrSign'
    
    def ss(self):
        print('Hello')
# АДРЕС - НЕ ШИФРОВАТЬ, ПРИВАТНЫЙ КЛЮЧ - СИНХРОННО, МНЕМОФРАЗА - СИНХРОННО, ПАРОЛЬ - АСИНХРОННО
class Hash:
    def creat_hash(self, password):
        hash_pass = password
      
        for i in range (10):
            hs = hashlib.md5()
            hs.update(hash_pass.encode())
            hash_pass = hs.hexdigest()
            hs = hashlib.sha1()
            hs.update(hash_pass.encode())
            hash_pass = hs.hexdigest()
            hs = hashlib.sha256()
            hs.update(hash_pass.encode())
            hash_pass = hs.hexdigest()
            hs = hashlib.sha512()
            hs.update(hash_pass.encode())
            hash_pass = hs.hexdigest()
            
        return hash_pass

    def create_rc4(self, text, password):
        self.creat_hash(Hash, password = password)
        hashh = rc4.rc4(text, password)
        return hashh

    def decode_rc4(self, rc, password):
        self.creat_hash(Hash, password = password)
        hashh = rc4.rc4(rc, password)
        return hashh

class InfuraChain:
    url = 'https://mainnet.infura.io/v3/8da0044cc2304474b465e117df2febbf' 
    #url = 'HTTP://127.0.0.1:7545'
    web3 = Web3(Web3.HTTPProvider(url))
    def get_balance(self, sender):
        balance = self.web3.eth.getBalance(sender)
        balance = self.web3.fromWei(balance, "ether")
        return balance

    def send_transaction(self, sender, getter, value, gas, private_key):
        # USING BLOCKCHAIN
        nonce = self.web3.eth.getTransactionCount(sender)
        value = Web3.toWei(float(value), 'ether')
        print(sender, type(sender), getter, type(getter), value, type(value), gas, type(gas), private_key, type(private_key))
        # BUILD A TRANSACTION

        tx = {
            'nonce': nonce,
            'to': getter,
            'value': value,
            'gas': int(gas),
            'gasPrice': Web3.toWei(102, 'gwei')
        }
        # SIGN A TRANSACTION
        signed_tx = self.web3.eth.account.signTransaction(tx, private_key)
        print('signed')
        # SEND A TRANSACTION
        tx_hash = self.web3.eth.sendRawTransaction(signed_tx.rawTransaction)
        print('hash')
        # GET A HASH OF TRANSACTION
        tx_hash = self.web3.toHex(tx_hash)
        print(tx_hash)


class EtherScan:
    es = etherscan.Client(api_key='AFJ976ENEMDXAFPQH237I3KPYJSB164Y45' )
    def get_balance(self, sender):
        balance = self.es.get_eth_balance(sender)
        return balance
    
    def get_price(self, balance):
        get_price = self.es.get_eth_price() 
        price = get_price['ethusd'] 
        USD = price * float (balance)
        USD = '%.2f USD' % USD      # Delete everything after 2 num
        return USD

class FirstInput(Screen):
    pass
        
class HomeScreen(Screen):
    sender = ''
    def on_enter(self, *args):
        self.sender = CteaPerceApp.public
        balance = EtherScan.get_balance(EtherScan, self.sender) # Get balance Etherscan
        balance =  Web3.fromWei(balance, 'ether')
        #balance = InfuraChain.get_balance(InfuraChain, self.sender) # Get balance Infura
        self.ids["ETH"].text = str(f"{balance} ETH")

        public = CteaPerceApp.public
        public = public[:14] + '...' + public[-6:]
        self.ids["public"].text = public

        eth_price = EtherScan.get_price(EtherScan, balance)
        self.ids["USD"].text =  eth_price
        
        

    
    initial = -1
    homeScreen_activity = 0
    homeScreenWidget_pos_y = Window.height * -0.7

    def down_history(self, instance):
        self.homeScreen_activity = 0
        self.homeScreenWidget_pos_y = -self.parent.height
        anim = Animation(x=0, y=self.homeScreenWidget_pos_y, duration=.3)
        anim.start(self.ids.HomeScreenWidget)
    
    def up_history(self, instance):
        self.homeScreen_activity = 1
        self.homeScreenWidget_pos_y = 0
        anim = Animation(x=0, y=self.homeScreenWidget_pos_y, duration=.3)
        anim.start(self.ids.HomeScreenWidget)

    
    def on_touch_down(self, touch):
        if (self.homeScreen_activity == 0):
            if touch.y < (self.parent.height - 25) * .4:
                self.initial = touch.y
                self.ids['history'].clear_widgets()
        else:
            if touch.y > self.parent.height * .7:
                self.initial = touch.y
        return super().on_touch_down(touch)

    def on_touch_up(self, touch):
        if self.initial >= 0:
            if touch.y - self.initial > 60:
                self.initial = -1
                self.up_history(self)
            elif touch.y - self.initial < -60:
                self.initial = -1
                self.down_history(self)
            else:
                self.initial = -1
                self.load_history()
        return super().on_touch_up(touch)

    def load_history(self):
        es = etherscan.Client(api_key='AFJ976ENEMDXAFPQH237I3KPYJSB164Y45')
        transactions = es.get_transactions_by_address(self.sender)
        print(transactions)
        print('\n:::::',len(transactions))
        if not transactions:
            self.ids['history'].add_widget(Label(text = 'История транзакций пуста'))
        else:
            id_trn = 1
            for transaction in transactions:
                
                self.ids['history'].add_widget(Factory.ItemTranz(text = f'{id_trn}. Дата: {datetime.datetime.utcfromtimestamp(transaction["timestamp"])}', on_release = self.changer ))
                id_trn += 1
                print(\
                    f'От:{transaction["from"]}', \
                    f'К: {transaction["to"]}', \
                    f'Сколько: {transaction["value"]}', \
                    f'Дата: {datetime.datetime.utcfromtimestamp(transaction["timestamp"])}'\
                    )


    def changer(self,instance,*args):
        text = instance.text
        print(text[0])
        es = etherscan.Client(api_key='AFJ976ENEMDXAFPQH237I3KPYJSB164Y45')
        transactions = es.get_transactions_by_address(self.sender)
        print(transactions[int(text[0])-1])
        transaction = transactions[int(text[0])-1]
        Transaction.sender = transaction["from"]
        Transaction.getter = transaction["to"]
        Transaction.how_many = transaction["value"]
        Transaction.comission = transaction["gas_used"]
        self.manager.current = 'Transaction'

class PrivateOrMnemonic(Screen):
    pass

class Mnemonic(Screen):
    def reg(self):
        try:
            Account.enable_unaudited_hdwallet_features()
            mnem = self.ids['mnemonictext'].text
            acct = Account.from_mnemonic(mnem)
            public = acct._address
            private_key = Web3.toHex(acct._key_obj.__dict__['_raw_key'])
            CteaPerceApp.private_key = private_key
            CteaPerceApp.mnemonic = mnem
            CteaPerceApp.public = public
            self.manager.current = 'PickPasswordSign'
        except:
            self.ids['stat'].text = 'Фраза введена неверно'

class PrivateKey(Screen):
    def reg(self):
        try:
            Account.enable_unaudited_hdwallet_features()
            privatekey = self.ids['privatetext'].text
            acct = Account.from_key(privatekey)
            public = acct._address
            private_key = Web3.toHex(acct._key_obj.__dict__['_raw_key'])
            CteaPerceApp.private_key = private_key
            CteaPerceApp.public = public
            self.manager.current = 'PickPasswordSign'
        except:
            self.ids['stat'].text = 'Ключ введён неверно'

class PickPassword(Screen):
    password = ''
    def add_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl_pass = lbl_pass + '•'
        lbl.text = lbl_pass
        CteaPerceApp.password = CteaPerceApp.password + instance.text
        if len(CteaPerceApp.password) == 6:
            self.changer()

    def del_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl.text = lbl_pass[:-1]
        self.password = self.password[:-1]

    def changer(self,*args):
        self.manager.current = 'PickPasswordTwo'

class PickPasswordTwo(Screen):
    password = ''
    def add_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl_pass = lbl_pass + '•'
        lbl.text = lbl_pass
        self.password = self.password + instance.text


        if len(self.password) == 6:
            if self.password == CteaPerceApp.password:
                self.changer()
            else:
                self.ids['status'].text = 'пароли не совпадают'

    def del_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl.text = lbl_pass[:-1]
        self.password = self.password[:-1]

        if len(self.password) < 6:
            status = self.ids['status']
            status.text = 'подтвердите пароль'

    def changer(self,*args):
        public = CteaPerceApp.public
        mnem = CteaPerceApp.mnemonic
        private_key = CteaPerceApp.private_key
        password = self.password

        hash_mnem = Hash.create_rc4(Hash, mnem, password)
        hash_private = Hash.create_rc4(Hash, private_key, password)
        hash_pass = Hash.creat_hash(Hash, password)
        CteaPerceApp.password = hash_pass
        open('public.txt', 'w', 1).write(public)
        open('mnem.txt', 'w', encoding='utf-8').write(hash_mnem)
        open('private.txt', 'w', encoding='utf-8').write(hash_private)
        open('pass.txt', 'w', 1).write(hash_pass)

        # Make QrCode
        qr = qrcode.make(public)
        qr.save('qr.jpg')
        
        self.manager.current = 'HomeScreen'
 
class RegistrationOrSign(Screen):
    pass

class InputPassword(Screen):
    password = ''

    def add_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        status = self.ids['status']
        self.password += instance.text
        lbl_pass = lbl_pass + '•'
        lbl.text = lbl_pass
        if len(self.password) == 6:
            if self.compare():
                self.changer()
            else:
                status.text = 'пароль неверный'
    
        
    def del_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl.text = lbl_pass[:-1]
        self.password = self.password[:-1]
        if len(self.password) < 6:
            status = self.ids['status']
            status.text = 'введите пароль'

    def compare(self):
        main_pass = open('pass.txt', 'r', 1).read()
        hash_of_password = Hash.creat_hash(Hash, self.password)
        if main_pass == hash_of_password:
            return True
        else:
            return False

    def changer(self,*args):
        Registration.load_cash(Registration, self.password)
        self.manager.current = 'HomeScreen'

class MnemonicWords(Screen):
    def on_enter(self, *args):
        Registration.add_account(self)
        mnemonic = CteaPerceApp.mnemonic 
        mnem = mnemonic.split() 
        it = iter(mnem) 
        abc = 'abcdefghijkl' 
        for i in abc:  
            self.ids[i].text = next(it)

class MnemonicEnter(Screen):
    def verification(self, *args):
        mnemonic = CteaPerceApp.mnemonic
        entered_mnem = self.ids['text'].text
        if entered_mnem == mnemonic:
            self.changer()
        else:
            self.ids["stat"].text= "Мнемофразы не совпадают"
    def changer(self,*args):
        self.manager.current = 'PickPassword'

class SettingMnemonicWords(Screen):
    def on_enter(self, *args):
        mnemonic = CteaPerceApp.mnemonic
        mnem = mnemonic.split() 
        it = iter(mnem)
        abc = 'abcdefghijkl' 
        for i in abc:  
            self.ids[i].text = next(it)

class PublicKeyList(Screen):
    pass

class SettingMnemonicWordsTwo(Screen):
    pass

class PickPasswordSign(Screen):
    password = ''
    def add_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl_pass = lbl_pass + '•'
        lbl.text = lbl_pass
        self.password += instance.text
        if len(self.password) == 6:
            self.changer()

    def del_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl.text = lbl_pass[:-1]
        self.password = self.password[:-1]

    def changer(self,*args):
        CteaPerceApp.password = self.password
        self.manager.current = 'PickPasswordSignTwo'

class PickPasswordSignTwo(Screen):
    password = ''
    def add_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl_pass = lbl_pass + '•'
        lbl.text = lbl_pass
        self.password += instance.text

        if len(self.password) == 6:
            if self.password == CteaPerceApp.password:
                self.changer()
            else:
                self.ids['status'].text = 'пароли не совпадают'



    def del_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl.text = lbl_pass[:-1]
        self.password = self.password[:-1]

        if len(self.password) < 6:
            status = self.ids['status']
            status.text = 'подтвердите пароль'

    def changer(self,*args):
        public = CteaPerceApp.public
        mnem = CteaPerceApp.mnemonic
        private_key = CteaPerceApp.private_key
        password = self.password

        hash_mnem = Hash.create_rc4(Hash, mnem, password)
        hash_private = Hash.create_rc4(Hash, private_key, password)
        hash_pass = Hash.creat_hash(Hash, password)
        open('public.txt', 'w', 1).write(public)
        open('mnem.txt', 'w', encoding='utf-8').write(hash_mnem)
        open('private.txt', 'w', encoding='utf-8').write(hash_private)
        open('pass.txt', 'w', 1).write(hash_pass)
        self.manager.current = 'HomeScreen'

        # Make QrCode
        qr = qrcode.make(public)
        qr.save('qr.jpg')
        self.manager.current = 'HomeScreen'

class GetETH(Screen):
    def on_enter(self):
        self.ids['publicget'].text = CteaPerceApp.public

class SendETH(Screen):
    sender = ''
    getter = ''
    value = 0
    gas = 21000
    private_key = ''
    def send(self):
        self.getter = self.ids.getter.text
        self.value = self.ids.much.text
        self.sender = CteaPerceApp.public
        self.private_key = CteaPerceApp.private_key
        InfuraChain.send_transaction(\
                InfuraChain,\
                sender = self.sender, \
                getter = self.getter, \
                value = self.value, \
                gas = self.gas, \
                private_key = self.private_key
                )
        
"""    data = ''
    def  not_pass(self, detector, data):
        data = data.replace('b', '')
        data = data.replace('\'', '')
        self.data = data
        detector.stop()
        return self.data
    def pas(self):
        return self.data

    def activate(self, detector):
        detector.start()
"""
    

class Parameters(Screen):
    pass

class Security(Screen):
    SecurityWidget_pos_x = Window.width*5000
    SecurityScreen_activity = 0
    def anim_security(self, instance):
        self.SecurityScreen_activity = 1
        anim = Animation(x = 0, duration=.001)
        anim.start(self.ids.SecurityWidget)

    def on_touch_down(self, touch):
        if (self.SecurityScreen_activity == 1):
            if (touch.y < self.parent.height*.44) | (touch.y > self.parent.height*.55):
                self.SecurityScreen_activity = 0
                anim = Animation(x = Window.width*5000, duration=.001)
                anim.start(self.ids.SecurityWidget)
        else:
            return super().on_touch_down(touch)


class Transaction(Screen):
    sender = ''
    getter = ''
    how_many = ''
    comission = ''
    def on_enter(self):
        self.ids['sender'].text = self.sender
        self.ids['getter'].text = self.getter
        self.ids['how_many'].text = str(self.how_many)
        self.ids['comission'].text = str(self.comission)

class PasswordConfirmation(Screen):
    password = ''
    def add_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl_pass = lbl_pass + '•'
        lbl.text = lbl_pass
        self.password = self.password + instance.text


        if len(self.password) == 6:
            hash_pass = Hash.creat_hash(Hash, self.password)
            if hash_pass == CteaPerceApp.password:
                self.checking()
            else:
                self.ids['status'].text = 'пароли не совпадают'

    def del_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl.text = lbl_pass[:-1]
        self.password = self.password[:-1]

        if len(self.password) < 6:
            status = self.ids['status']
            status.text = 'подтвердите пароль'

    def checking(self):
        if CteaPerceApp.mnemonic == '':
            self.manager.current = 'SettingMnemonicWordsTwo'
        else:
            self.manager.current = 'SettingMnemonicWords' 

class PasswordConfirmationTwo(Screen):
    password = ''
    def add_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl_pass = lbl_pass + '•'
        lbl.text = lbl_pass
        self.password = self.password + instance.text


        if len(self.password) == 6:
            hash_pass = Hash.creat_hash(Hash, self.password)
            if hash_pass == CteaPerceApp.password:
                self.manager.current = 'ChangePassword'
            else:
                self.ids['status'].text = 'пароли не совпадают'

    def del_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl.text = lbl_pass[:-1]
        self.password = self.password[:-1]

        if len(self.password) < 6:
            status = self.ids['status']
            status.text = 'введите пароль'


class ChangePassword(Screen):
    password = ''
    def add_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl_pass = lbl_pass + '•'
        lbl.text = lbl_pass
        self.password = self.password + instance.text
        if len(self.password) == 6:
            self.changer()

    def del_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl.text = lbl_pass[:-1]
        self.password = self.password[:-1]

    def changer(self,*args):
        CteaPerceApp.password = self.password
        self.manager.current = 'ChangePasswordTwo'

class ChangePasswordTwo(Screen):
    password = ''
    def add_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl_pass = lbl_pass + '•'
        lbl.text = lbl_pass
        self.password = self.password + instance.text


        if len(self.password) == 6:
            if self.password == CteaPerceApp.password:
                self.changer()
            else:
                self.ids['status'].text = 'пароли не совпадают'
                print(CteaPerceApp.password)

    def del_point(self, instance):
        lbl = self.ids['lbl']
        lbl_pass = lbl.text
        lbl.text = lbl_pass[:-1]
        self.password = self.password[:-1]

        if len(self.password) < 6:
            status = self.ids['status']
            status.text = 'подтвердите пароль'

    def changer(self,*args):
        public = CteaPerceApp.public
        mnem = CteaPerceApp.mnemonic
        private_key = CteaPerceApp.private_key
        password = self.password

        hash_mnem = Hash.create_rc4(Hash, mnem, password)
        hash_private = Hash.create_rc4(Hash, private_key, password)
        hash_pass = Hash.creat_hash(Hash, password)
        open('public.txt', 'w', 1).write(public)
        open('mnem.txt', 'w', encoding='utf-8').write(hash_mnem)
        open('private.txt', 'w', encoding='utf-8').write(hash_private)
        open('pass.txt', 'w', 1).write(hash_pass)
        CteaPerceApp.password = hash_pass

        # Make QrCode
        qr = qrcode.make(public)
        qr.save('qr.jpg')
        self.manager.current = 'HomeScreen'


if __name__ == "__main__":
    CteaPerceApp().run()
    