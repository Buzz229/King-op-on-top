import os
import time
import httpx
import base64
import json
import threading
import tls_client
import string
import sys
import psutil
import subprocess
import binascii
import requests
import platform
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from uuid import uuid4
from base64 import b64encode as enc
from colorama import *
from typing import Optional, Any
import random
from itertools import cycle
import json as jsond
import gratient

try:
    
    class AntiDebug:
        inVM = False
        
        def __init__(self):
            self.processes = list()
            self.blackListedPrograms = [
                'httpdebuggerui',
                'wireshark',
                'fiddler',
                'regedit',
                'cmd',
                'taskmgr',
                'vboxservice',
                'df5serv',
                'processhacker',
                'vboxtray',
                'vmtoolsd',
                'vmwaretray',
                'ida64',
                'ollydbg',
                'pestudio',
                'vmwareuser',
                'vgauthservice',
                'vmacthlp',
                'x96dbg',
                'vmsrvc',
                'x32dbg',
                'vmusrvc',
                'prl_cc',
                'prl_tools',
                'xenservice',
                'qemu-ga',
                'joeboxcontrol',
                'ksdumperclient',
                'ksdumper',
                'joeboxserver',
                'x64dbg']
            self.blackListedUsers = []
            self.blackListedPCNames = []
            self.blackListedHWIDS = []
            self.blackListedIPS = []
            self.blackListedGPU = []
            threading.Thread(self.blockDebuggers, **('target',)).start()
            for func in (self.listCheck,):
                process = threading.Thread(func, True, **('target', 'daemon'))
                self.processes.append(process)
                process.start()
            for t in self.processes:
                
                try:
                    t.join()
                finally:
                    continue
                    continue
                    return None


        
        def programExit(self):
            time.sleep(2)
            self.__class__.inVM = True

        
        def blockDebuggers(self):
            for None in psutil.process_iter():
                proc = None
                if None((lambda .0 = None: for procstr in .0:
procstr in proc.name().lower())(self.blackListedPrograms)):
                    
                    try:
                        proc.kill()
                    finally:
                        pass
                    self.programExit()
                    continue
                    return None


        
        def listCheck(self):
            for path in ('D:\\Tools', 'D:\\OS2', 'D:\\NT3X'):
                if os.path.exists(path):
                    self.programExit()
            myName = os.getlogin()
            for user in self.blackListedUsers:
                if myName == user:
                    self.programExit()
            myPCName = os.getenv('COMPUTERNAME')
            for pcName in self.blackListedPCNames:
                if myPCName == pcName:
                    self.programExit()
            
            try:
                myHWID = subprocess.check_output('wmic csproduct get uuid', 134217728, **('creationflags',)).decode().split('\n')[1].strip()
            finally:
                pass
            myHWID = ''
            for hwid in self.blackListedHWIDS:
                if myHWID == hwid:
                    self.programExit()
            
            try:
                myIP = httpx.get('https://api64.ipify.org/').text.strip()
            finally:
                pass
            for ip in self.blackListedIPS:
                if myIP == ip:
                    self.programExit()
            
            try:
                myGPU = subprocess.check_output('wmic path win32_VideoController get name', 134217728, **('creationflags',)).decode().strip('Name\n').strip()
            finally:
                pass
            myGPU = ''
            for gpu in self.blackListedGPU:
                if gpu in myGPU.split('\n'):
                    self.programExit()
            return None





    
    class api:
        name = ownerid = secret = version = ''
        
        def __init__(self, name, ownerid, secret, version):
            self.name = name
            self.ownerid = ownerid
            self.secret = secret
            self.version = version

        sessionid = enckey = ''
        
        def init(self):
            init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
            self.enckey = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
            post_data = {
                'type': binascii.hexlify('init'.encode()),
                'ver': encryption.encrypt(self.version, self.secret, init_iv),
                'enckey': encryption.encrypt(self.enckey, self.secret, init_iv),
                'name': binascii.hexlify(self.name.encode()),
                'ownerid': binascii.hexlify(self.ownerid.encode()),
                'init_iv': init_iv }
            response = self.__do_request(post_data)
            if response == 'KeyAuth_Invalid':
                print("The application doesn't exist")
                sys.exit()
            response = encryption.decrypt(response, self.secret, init_iv)
            json = jsond.loads(response)
            if not json['success']:
                print(json['message'])
                sys.exit()
            self.initialized = False
            self.sessionid = json['sessionid']

        
        def license(self, key, hwid = (None,)):
            if hwid is None:
                hwid = others.get_hwid()
            init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
            post_data = {
                'type': binascii.hexlify('license'.encode()),
                'key': encryption.encrypt(key, self.enckey, init_iv),
                'hwid': encryption.encrypt(hwid, self.enckey, init_iv),
                'sessionid': binascii.hexlify(self.sessionid.encode()),
                'name': binascii.hexlify(self.name.encode()),
                'ownerid': binascii.hexlify(self.ownerid.encode()),
                'init_iv': init_iv }
            response = self.__do_request(post_data)
            response = encryption.decrypt(response, self.enckey, init_iv)
            json = jsond.loads(response)
            if json['success']:
                self.__load_user_data(json['info'])
                return None
            None(json['message'])
            time.sleep(5)
            sys.exit(1)

        
        def __do_request(self, post_data):
            rq_out = requests.post('https://keyauth.win/api/1.0/', post_data, **('data',))
            return rq_out.text

        
        class user_data_class:
            __qualname__ = 'api.user_data_class'
            username = ip = hwid = expires = createdate = lastlogin = ''

        user_data = user_data_class()
        
        def __load_user_data(self, data):
            global expires
            self.user_data.username = data['username']
            self.user_data.ip = data['ip']
            self.user_data.hwid = data['hwid']
            self.user_data.expires = data['subscriptions'][0]['expiry']
            self.user_data.createdate = data['createdate']
            self.user_data.lastlogin = data['lastlogin']
            expires = int(self.user_data.expires)


    
    class others:
        
        def get_hwid():
            if platform.system() != 'Windows':
                return subprocess.Popen('hal-get-property --udi /org/freedesktop/Hal/devices/computer --key system.hardware.uuid'.split())
            cmd = None.Popen("wmic useraccount where name='%username%' get sid", subprocess.PIPE, True, **('stdout', 'shell'))
            (suppost_sid, error) = cmd.communicate()
            suppost_sid = suppost_sid.split(b'\n')[1].strip()
            return suppost_sid.decode()

        get_hwid = staticmethod(get_hwid)

    
    class encryption:
        
        def encrypt_string(plain_text, key, iv):
            plain_text = pad(plain_text, 16)
            aes_instance = AES.new(key, AES.MODE_CBC, iv)
            raw_out = aes_instance.encrypt(plain_text)
            return binascii.hexlify(raw_out)

        encrypt_string = staticmethod(encrypt_string)
        
        def decrypt_string(cipher_text, key, iv):
            cipher_text = binascii.unhexlify(cipher_text)
            aes_instance = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = aes_instance.decrypt(cipher_text)
            return unpad(cipher_text, 16)

        decrypt_string = staticmethod(decrypt_string)
        
        def encrypt(message, enc_key, iv):
            
            try:
                _key = SHA256.new(enc_key.encode()).hexdigest()[:32]
                _iv = SHA256.new(iv.encode()).hexdigest()[:16]
            finally:
                return None
                print('Invalid Application Information')
                time.sleep(5)
                sys.exit()
                return None


        encrypt = staticmethod(encrypt)
        
        def decrypt(message, enc_key, iv):
            
            try:
                _key = SHA256.new(enc_key.encode()).hexdigest()[:32]
                _iv = SHA256.new(iv.encode()).hexdigest()[:16]
            finally:
                return None
                print('Invalid Application Information')
                time.sleep(5)
                sys.exit()
                return None


        decrypt = staticmethod(decrypt)

    if AntiDebug().inVM:
        os._exit(1)
        keyauthapp = api('Redeemer Request', '64BxyBjJq3', '6c9a8f375ee81f95420abbe6dba377e96da50c6a7fcdf91835bc2ccf6ea58d53', '1.0')
finally:
    pass
sys.exit(1)
lock = threading.Lock()
activated_accounts = 0
with open('config/settings.json', 'r') as config:
    config = json.load(config)
    user_agent = config['fingerprint']['user_agent']
    browser_version = config['fingerprint']['browser_version']
    None(None, None, None)
if not None:
    
    class Client:
        
        def time_logged():
            return time.strftime('%H:%M', time.gmtime())

        time_logged = staticmethod(time_logged)
        
        def logs(log = None, msg = None, dic = staticmethod):
            msg_dic = ''
            if dic:
                msg_dic = ''.join((lambda .0: for key, value in .0:
'   {}{}: {}{}'.format(Fore.LIGHTBLACK_EX, key, Fore.WHITE, value))(dic.items()))
            if log == 'INF':
                print(f'''{Fore.LIGHTBLACK_EX}{Client().time_logged()} {Fore.WHITE}[{Fore.LIGHTBLUE_EX}{log}{Fore.WHITE}]{Fore.LIGHTBLACK_EX}  >  {Fore.WHITE}{msg}{msg_dic}{Style.RESET_ALL}''')
                return None
            if None == 'ERR':
                print(f'''{Fore.LIGHTBLACK_EX}{Client().time_logged()} {Fore.WHITE}[{Fore.RED}{log}{Fore.WHITE}]{Fore.LIGHTBLACK_EX}  >  {Fore.WHITE}{msg}{msg_dic}{Style.RESET_ALL}''')
                return None
            if None == 'SUC':
                print(f'''{Fore.LIGHTBLACK_EX}{Client().time_logged()} {Fore.WHITE}[{Fore.LIGHTGREEN_EX}{log}{Fore.WHITE}]{Fore.LIGHTBLACK_EX}  >  {Fore.WHITE}{msg}{msg_dic}{Style.RESET_ALL}''')
                return None

        logs = None(logs)

    
    def generate_x_super_properties():
        x_super_properties = '{"os":"Windows","browser":"Chrome","device":"","system_locale":"en-GB","browser_user_agent":"%s","browser_version":"%s","os_version":"10","referrer":"","referring_domain":"","referrer_current":"","referring_domain_current":"","release_channel":"stable","client_build_number":102113,"client_event_source":null}' % (user_agent, browser_version)
        return base64.b64encode(x_super_properties.encode()).decode()

    
    def remove_content(filename = None, delete_line = None):
        
        try:
            lock.acquire()
            with open(filename, 'r+') as io:
                content = io.readlines()
                io.seek(0)
                for line in content:
                    if delete_line not in line:
                        io.write(line)
                io.truncate()
                None(None, None, None)
            if not None:
                pass
            lock.release()
        finally:
            return None
            e = None
            
            try:
                print(e)
            finally:
                e = None
                del e
                return None
                e = None
                del e
                return None



    remove_content = None(remove_content)
    
    def add_content(filename = None, content = None):
        
        try:
            lock.acquire()
            with open(filename, 'a+') as io:
                io.write(f'''\n{content}''')
                None(None, None, None)
            if not None:
                pass
            lock.release()
        finally:
            return None
            e = None
            
            try:
                print(f'''add {e}''')
            finally:
                e = None
                del e
                return None
                e = None
                del e
                return None



    add_content = None(add_content)
    
    def generate_stripe_id():
        elements = string.ascii_lowercase[:6] + string.digits
        return ''.join(random.choices(elements, 8, **('k',))) + '-' + ''.join(random.choices(elements, 4, **('k',))) + '-' + ''.join(random.choices(elements, 4, **('k',))) + '-' + ''.join(random.choices(elements, 4, **('k',))) + '-' + ''.join(random.choices(elements, 18, **('k',)))

    generate_stripe_id = None(generate_stripe_id)
    client_identifiers = [
        'safari_ios_16_0',
        'safari_ios_15_6',
        'safari_ios_15_5',
        'safari_16_0',
        'safari_15_6_1',
        'safari_15_3',
        'opera_90',
        'opera_89',
        'firefox_104',
        'firefox_102']
    
    class Redeem:
        
        def __init__(self = None, token = None, promo = None, vcc = (None,), proxy = ('token', str, 'promo', str, 'vcc', str, 'proxy', Optional[Any], 'return', None)):
            self.token = token
            self.promo = promo
            self.vcc = vcc
            (self.vcc_num, self.vcc_exp, self.vcc_ccv) = vcc.split(':')
            self.proxy = proxy
            self.token_name = ''
            self.country_code = ''
            
            try:
                self.client = httpx.Client({
                    'Connection': 'close' }, self.proxy, 90, **('headers', 'proxies', 'timeout'))
                self.stripe_client = httpx.Client({
                    'Connection': 'close' }, self.proxy, 90, **('headers', 'proxies', 'timeout'))
                self.redeem_client = tls_client.Session('771,4866-4867-4865-49196-49200-49195-49199-52393-52392-159-158-52394-49327-49325-49326-49324-49188-49192-49187-49191-49162-49172-49161-49171-49315-49311-49314-49310-107-103-57-51-157-156-49313-49309-49312-49308-61-60-53-47-255,0-11-10-35-16-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2', random.choice(client_identifiers), **('ja3_string', 'client_identifier'))
            finally:
                pass
            return None
            self.redeem_code = 0
            if 'promos.discord.gg' in self.promo:
                self.promo_code = self.promo.split('promos.discord.gg/')[1]
                self.link = f'''https://discord.com/billing/promotions/{self.promo.split('promos.discord.gg/')[1]}'''
            else:
                self.promo_code = self.promo.split('discord.com/billing/promotions/')[1]
                self.link = self.promo

            self.city = 'State College'
            self.country = 'US'
            self.email = self.token.split(':')[0]
            self.line_1 = '243 Johnson Ter'
            self.line_2 = ''
            self.name = 'Jack Nuts'
            self.postal_code = '16803'
            self.state = 'PA'
            self.full_token = self.token
            self.token = self.token.split(':')[-1] if ':' in self.token else self.token
            self.set_random_stripe_ids()
            if self.__main():
                return None

        
        def set_random_stripe_ids(self = None):
            self.guid = generate_stripe_id()
            self.muid = generate_stripe_id()
            self.sid = generate_stripe_id()

        
        def get_message(self = None, message = None):
            self.client.close()
            self.stripe_client.close()
            if message == False:
                Client().logs('ERR', 'Could not redeem nitro', {
                    'token': self.token[:-25] + '******' }, **('msg', 'dic'))
                return None

        
        def __main(self = None):
            global activated_accounts
            self.message = False
            
            try:
                start = time.time()
                if not self.__session_start__():
                    self.message = True
                    Client().logs('ERR', 'Session couldnt be started.', **('msg',))
                    self.get_message(self.message)
            finally:
                return False
                if not self.tokencheck():
                    self.message = True
                    Client().logs('ERR', 'Invalid', {
                        'token': self.token[:-25] + '******' }, **('msg', 'dic'))
                    remove_content('config/tokens.txt', self.full_token)
                    self.get_message(self.message)
                return False
                if not self.promo_check():
                    self.get_message(self.message)
                return False
                if not self.stripe_token():
                    self.get_message(self.message)
                return False
                if not self.setup_intents():
                    self.get_message(self.message)
                return False
                if not self.validate_billing():
                    self.get_message(self.message)
                return None
                if not self.payment_source():
                    self.get_message(self.message)
                return None
                if self.redeem() and self.redeem_code == 0:
                    self.get_message(self.message)
                return None
                if self.redeem_code == 1:
                    if not self.discord_payment_intent():
                        self.get_message(self.message)
                    return None
                if not None.stripe_payment_intent():
                    self.get_message(self.message)
                return None
                if not self.stripe_confirm():
                    self.get_message(self.message)
                return None
                if not self.stripe_fingerprint():
                    self.get_message(self.message)
                return None
                if not self.stripe_authenticate():
                    self.get_message(self.message)
                return None
                if not self.billing():
                    self.get_message(self.message)
                return None
                if self.redeem_code == 3:
                    if not self.stripe_payment_intent():
                        self.get_message(self.message)
                    return None
                if not None.discord_payment_intent():
                    self.get_message(self.message)
                return None
                if self.redeem() and self.redeem_code == 0:
                    self.get_message(self.message)
                return None
                if self.redeem_code == 4:
                    end = time.time()
                    elasped = round(end - start, 2)
                    self.message = True
                    Client().logs('SUC', f'''Redeemed Nitro in {elasped}s''', {
                        'token': self.token[:-25] + '******' }, **('msg', 'dic'))
                    add_content('config/success.txt', self.full_token)
                    remove_content('config/tokens.txt', self.full_token)
                remove_content('config/promos.txt', self.promo)
                activated_accounts += 1
                self.client.close()
                self.stripe_client.close()
                return None
                self.get_message(self.message)
                return None
                return None


        
        def __session_start__(self):
            
            try:
                self.client.headers.update({
                    'accept': '*/*',
                    'accept-encoding': 'gzip, deflate',
                    'accept-language': 'en-US',
                    'origin': 'https://discord.com',
                    'sec-ch-ua': '"Google Chrome";v="95", "Chromium";v="95", ";Not A Brand";v="99"',
                    'sec-fetch-dest': 'document',
                    'sec-fetch-mode': 'navigate',
                    'sec-fetch-Site': 'none',
                    'sec-fetch-user': '?1',
                    'sec-ch-ua-platform': '"Windows"',
                    'user-agent': user_agent })
                get_site = self.client.get('https://discord.com/login')
                if get_site.status_code not in (200, 201, 204):
                    pass
            finally:
                return False
                self._Redeem__dcfduid = get_site.headers['set-cookie'].split('__dcfduid=')[1].split(';')[0]
                self._Redeem__sdcfduid = get_site.headers['set-cookie'].split('__sdcfduid=')[1].split(';')[0]
                self.super_properties = generate_x_super_properties()
                self.fingerprint = self.client.get('https://discord.com/api/v9/experiments')
                if self.fingerprint.status_code not in (200, 201, 204):
                    pass
                return False
                self.fingerprint = self.fingerprint.json()['fingerprint']
                if get_site.status_code not in (200, 201, 204):
                    pass
                return False
                return True
                return None


        
        def tokencheck(self):
            
            try:
                self.x_properties = generate_x_super_properties()
                'sec-fetch-site'('user-agent')
                self.client.cookies.update({
                    '__dcfduid': self._Redeem__dcfduid,
                    '__sdcfduid': self._Redeem__sdcfduid,
                    'locale': 'en-US' })
                user = self.client.get('https://discord.com/api/v9/users/@me')
                if user.status_code not in (200, 201, 204):
                    pass
            finally:
                return False
                self.token_name = f'''{user.json()['username']}#{user.json()['discriminator']}'''
                if not user.json()['verified']:
                    pass
                return False
                
                try:
                    self.country_code = self.client.get('https://discord.com/api/v9/users/@me/billing/country-code').json()['country_code']
                finally:
                    pass
                return False
                Client().logs('INF', 'Starting', {
                    'user': self.token_name,
                    'token': self.token[:-25] + '******' }, **('msg', 'dic'))
                return True
                return None



        
        def promo_check(self = None):
            
            try:
                promo = self.client.get(f'''https://discord.com/api/v9/entitlements/gift-codes/{self.promo_code}?country_code={self.country_code}&with_application=false&with_subscription_plan=true''')
                if promo.status_code not in (200, 201, 204):
                    self.message = True
                    Client().logs('ERR', 'Invalid', {
                        'promo': self.promo }, **('msg', 'dic'))
                    remove_content('config/promos.txt', self.promo)
            finally:
                return False
                if promo.json()['max_uses'] - promo.json()['uses'] == 0:
                    self.message = True
                    Client().logs('ERR', 'Promo already redeemed', {
                        'promo': self.promo }, **('msg', 'dic'))
                    remove_content('config/promos.txt', self.promo)
                return False
                promo_check_2 = self.client.get(self.link)
                
                try:
                    self.stripe_key = promo_check_2.text.split("STRIPE_KEY: '")[1].split("',")[0]
                finally:
                    return True
                    Client().logs('ERR', 'Invalid', {
                        'promo': self.promo }, **('msg', 'dic'))
                    remove_content('config/promos.txt', self.promo)
                    return False
                    return None



        
        def stripe_token(self = None):
            
            try:
                self.client.headers.update({
                    'cookie': f'''__dcfduid={self._Redeem__dcfduid}; __sdcfduid={self._Redeem__sdcfduid}; __stripe_mid={self.muid}; __stripe_sid={self.sid}''' })
                self.stripe_client.headers['Authorization'] = 'Bearer ' + self.stripe_key
                data = {
                    'card[number]': self.vcc_num,
                    'card[cvc]': self.vcc_ccv,
                    'card[exp_month]': self.vcc_exp[:2],
                    'card[exp_year]': self.vcc_exp[-2:],
                    'guid': self.guid,
                    'muid': self.muid,
                    'sid': self.sid,
                    'payment_user_agent': 'stripe.js/5b44f0773; stripe-js-v3/5b44f0773',
                    'time_on_page': random.randint(1000000, 5000000),
                    'key': self.stripe_key,
                    'pasted_fields': 'number,exp,cvc' }
                stripe = self.stripe_client.post('https://api.stripe.com/v1/tokens', data, **('data',))
                if stripe.status_code not in (200, 201, 204):
                    error = stripe.json()['error']['message']
                    if error == 'The card number is not a valid credit card number.':
                        self.message = True
                        Client().logs('ERR', {
                            'Invalid card': f'''{self.vcc_num}:{self.vcc_exp}:{self.vcc_ccv}''' }, **('dic',))
                        remove_content('config/vccs.txt', self.vcc)
                    return False
                self.stripe_token_id = None.json()['id']
            finally:
                return True
                return None


        
        def setup_intents(self):
            
            try:
                setup = self.client.post('https://discord.com/api/v9/users/@me/billing/stripe/setup-intents')
                if setup.status_code == 200:
                    self.client_secret = setup.json()['client_secret']
            finally:
                return True
                messge = setup.json()['message']
                
                try:
                    if messge == 'The resource is being rate limited.':
                        self.message = True
                        Client().logs('ERR', 'Token ratelimited', {
                            'token': self.token[:-25] + '******',
                            'retry after': f'''{setup.json()['retry_after']}s''' }, **('msg', 'dic'))
                finally:
                    return False
                    raise IndexError
                    self.message = True
                    Client().logs('ERR', 'Failed to redeem [i]', {
                        'token': self.token[:-25] + '******' }, **('msg', 'dic'))
                    return False
                    return None



        
        def validate_billing(self):
            
            try:
                billing = self.client.post('https://discord.com/api/v9/users/@me/billing/payment-sources/validate-billing-address', {
                    'billing_address': {
                        'city': self.city,
                        'country': self.country,
                        'email': self.email,
                        'line_1': self.line_1,
                        'line_2': self.line_2,
                        'name': self.name,
                        'postal_code': self.postal_code,
                        'state': self.state } }, **('json',))
                if not billing.status_code == 200:
                    error = billing.json()
            finally:
                return False
                self.billing_token = billing.json()['token']
                data = 'key'
                confirm = self.stripe_client.post(f'''https://api.stripe.com/v1/setup_intents/{self.client_secret.split('_secret_')[0]}/confirm''', data, **('data',))
                if confirm.status_code == 200:
                    self.payment_method = confirm.json()['payment_method']
                return True
                error = confirm.json()['error']['message']
                if error == 'Your card has expired.':
                    self.message = True
                    Client().logs('ERR', f'''Expired card: {self.vcc_num}:{self.vcc_exp}:{self.vcc_ccv}''', **('msg',))
                    remove_content('config/vccs.txt', self.vcc)
                return None
                return None
                'use_stripe_sdk'
                'use_stripe_sdk'
                'use_stripe_sdk'
                return None


        
        def payment_source(self):
            
            try:
                data = {
                    'payment_gateway': 1,
                    'token': self.payment_method,
                    'billing_address': {
                        'name': self.name,
                        'line_1': self.line_1,
                        'line_2': self.line_2,
                        'city': self.city,
                        'state': self.state,
                        'postal_code': self.postal_code,
                        'country': self.country,
                        'email': self.email },
                    'billing_address_token': self.billing_token }
                source = self.client.post('https://discord.com/api/v9/users/@me/billing/payment-sources', data, **('json',))
                if source.status_code not in (200, 201, 204):
                    print(source.json())
                    if source.json()['errors']['_errors'][0]['code'] == 'BILLING_DUPLICATE_PAYMENT_SOURCE':
                        self.message = True
                        Client().logs('ERR', 'Duplicate payment', {
                            'vcc': f'''{self.vcc_num}:{self.vcc_exp}:{self.vcc_ccv}''',
                            'token': self.token[:-25] + '******' }, **('msg', 'dic'))
                    return False
                self.payment_source_id = None.json()['id']
            finally:
                return True
                return None


        
        def redeem(self):
            
            try:
                headers = 'sec-fetch-mode'
                json = {
                    'channel_id': None,
                    'payment_source_id': self.payment_source_id }
                redeem = self.redeem_client.post(f'''https://discord.com/api/v9/entitlements/gift-codes/{self.promo_code}/redeem''', json, headers, self.proxy, **('json', 'headers', 'proxy'))
                if redeem.status_code not in (200, 201, 204):
                    message = redeem.json()['message']
                    if message == 'Authentication required':
                        self.payment_id = redeem.json()['payment_id']
                        self.redeem_code = 1
                    return False
                if 'sec-fetch-dest' == 'Already purchased':
                    self.message = True
                    Client().logs('ERR', 'Nitro purchased before', {
                        'token': self.token[:-25] + '******' }, **('msg', 'dic'))
                    remove_content('config/tokens.txt', self.full_token)
            finally:
                return False
                if message == 'This payment method cannot be used':
                    self.message = True
                    Client().logs('ERR', 'Vcc cannot be used', {
                        'vcc': f'''{self.vcc_num}:{self.vcc_exp}:{self.vcc_ccv}''',
                        'token': self.token[:-25] + '******' }, **('msg', 'dic'))
                    remove_content('config/vccs.txt', self.vcc)
                return False
                if message == 'New subscription required to redeem gift.':
                    self.message = True
                    Client().logs('ERR', 'Already redeemed token', {
                        'token': self.token[:-25] + '******' }, **('msg', 'dic'))
                    add_content('config/already_redeemed.txt', self.full_token)
                    remove_content('config/tokens.txt', self.full_token)
                return False
                if message == 'The resource is being rate limited.':
                    self.message = True
                    self.message = True
                    Client().logs('ERR', 'Token ratelimited', {
                        'token': self.token[:-25] + '******' }, **('msg', 'dic'))
                return False
                if message == 'This gift has been redeemed already.':
                    self.message = True
                    Client().logs('ERR', 'Promo already redeemed', {
                        'token': self.token[:-25] + '******',
                        'promo': self.promo }, **('msg', 'dic'))
                    remove_content('config/promos.txt', self.promo)
                return False
                if message == 'Invalid Payment Source':
                    self.message = True
                    Client().logs('ERR', 'Invalid vcc', {
                        'vcc': f'''{self.vcc_num}:{self.vcc_exp}:{self.vcc_ccv}''',
                        'token': self.token[:-25] + '******' }, **('msg', 'dic'))
                    remove_content('config/vccs.txt', self.vcc)
                return False
                return False
                self.redeem_code = 4
                return True
                return None
                return None


        
        def discord_payment_intent(self):
            
            try:
                intent = self.client.get(f'''https://discord.com/api/v9/users/@me/billing/stripe/payment-intents/payments/{self.payment_id}''')
                if intent.status_code not in (200, 201, 204):
                    pass
            finally:
                return False
                self.stripe_payment_intent_client_secret = intent.json()['stripe_payment_intent_client_secret']
                self.stripe_payment_intent_payment_method_id = intent.json()['stripe_payment_intent_payment_method_id']
                return True
                return None
                return None


        
        def stripe_payment_intent(self):
            
            try:
                self.stripe_headers = 'sec-fetch-mode'
                intent = self.redeem_client.get(f'''https://api.stripe.com/v1/payment_intents/{self.stripe_payment_intent_client_secret.split('_secret_')[0]}?key={self.stripe_key}&is_stripe_sdk={False}&client_secret={self.stripe_payment_intent_client_secret}''', self.stripe_headers, self.proxy, **('headers', 'proxy'))
                if intent.status_code not in (200, 201, 204):
                    pass
            finally:
                return False
                return True
                return None


        
        def stripe_confirm(self):
            
            try:
                data = {
                    'expected_payment_method_type': 'card',
                    'use_stripe_sdk': True,
                    'key': self.stripe_key,
                    'client_secret': self.stripe_payment_intent_client_secret }
                confirm = self.redeem_client.post(f'''https://api.stripe.com/v1/payment_intents/{self.stripe_payment_intent_client_secret.split('_secret_')[0]}/confirm''', data, self.stripe_headers, self.proxy, **('data', 'headers', 'proxy'))
                if confirm.status_code not in (200, 201, 204):
                    pass
            finally:
                return False
                self.server_transaction_id = confirm.json()['next_action']['use_stripe_sdk']['server_transaction_id']
                self.three_d_secure_2_source = confirm.json()['next_action']['use_stripe_sdk']['three_d_secure_2_source']
                self.merchant = confirm.json()['next_action']['use_stripe_sdk']['merchant']
                return True
                return None
                return None


        
        def stripe_fingerprint(self = None):
            
            try:
                self.threeDSMethodNotificationURL = f'''https://hooks.stripe.com/3d_secure_2/fingerprint/{self.merchant}/{self.three_d_secure_2_source}'''
                data = {
                    'threeDSMethodData': enc(json.dumps({
                        'threeDSServerTransID': self.server_transaction_id }, (',', ':'), **('separators',)).encode()).decode('utf-8') }
                response = self.redeem_client.post(self.threeDSMethodNotificationURL, data, self.stripe_headers, self.proxy, **('data', 'headers', 'proxy'))
                if response.status_code == 200:
                    pass
            finally:
                return True
                return False
                return None
                return None


        
        def stripe_authenticate(self):
            
            try:
                headers = 'sec-fetch-site'
                data = {
                    'source': self.three_d_secure_2_source,
                    'browser': '{"fingerprintAttempted":true,"fingerprintData":"eyJ0aHJlZURTU2VydmVyVHJhbnNJRCI6ImYwYTQ4ZjdhLWNjYTktNDVmMS1iN2JiLWM4MTE2ZDMyOTdmYiJ9","challengeWindowSize":null,"threeDSCompInd":"Y","browserJavaEnabled":false,"browserJavascriptEnabled":true,"browserLanguage":"en","browserColorDepth":"24","browserScreenHeight":"1080","browserScreenWidth":"1920","browserTZ":"-120","browserUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"}',
                    'one_click_authn_device_support[hosted]': False,
                    'one_click_authn_device_support[same_origin_frame]': False,
                    'one_click_authn_device_support[spc_eligible]': False,
                    'one_click_authn_device_support[webauthn_eligible]': False,
                    'one_click_authn_device_support[publickey_credentials_get_allowed]': True,
                    'key': self.stripe_key }
                auth = self.stripe_client.post('https://api.stripe.com/v1/3ds2/authenticate', data, headers, **('data', 'headers'))
                if auth.status_code not in (200, 201, 204):
                    pass
            finally:
                return False
                if auth.json()['state'] == 'succeeded':
                    self.redeem_code = 3
                return True
                return None
                return None


        
        def billing(self = None):
            
            try:
                response = self.client.get(f'''https://discord.com/api/v9/users/@me/billing/payments/{self.payment_id}''')
                if response.status_code == 200:
                    pass
            finally:
                return True
                return False
                return None
                return None



    
    def protect_pytransform():
        pass

    protect_pytransform()
    if __name__ == '__main__':
        
        try:
            with open('config/settings.json', 'r') as config:
                config = json.load(config)
                None(None, None, None)
            if not None:
                key = config['key']
                keyauthapp.init()
                keyauthapp.license(key)
                proxies = cycle(open('config/proxies.txt', 'r').read().splitlines())
                vccs = open('config/vccs.txt', 'r').read().splitlines()
                tokens = open('config/tokens.txt', 'r').read().splitlines()
                promos = open('config/promos.txt', 'r').read().splitlines()
                vcc_use = config['vcc_uses']
                thread_count = config['threads']
                duplicate_vccs = []
                input(f'''{Fore.LIGHTBLACK_EX}{Client().time_logged()} {Fore.WHITE}[{Fore.LIGHTYELLOW_EX}DBG{Fore.WHITE}]{Fore.LIGHTBLACK_EX}  >  {Fore.WHITE}Press enter to start{Style.RESET_ALL}''')
                os.system('cls')
                print(Fore.MAGENTA + '  \n                                    ╔═══╗─────╔╗╔══╗─────────╔╗\n                                    ║╔══╝────╔╝╚╣╔╗║────────╔╝╚╗\n                                    ║╚══╦══╦═╩╗╔╣╚╝╚╦══╦══╦═╩╗╔╬══╗\n                                    ║╔══╣╔╗║══╣║║╔═╗║╔╗║╔╗║══╣║║══╣\n                                    ║║──║╔╗╠══║╚╣╚═╝║╚╝║╚╝╠══║╚╬══║\n                                    ╚╝──╚╝╚╩══╩═╩═══╩══╩══╩══╩═╩══╝')
                time.sleep(50)
                for x in vccs:
                    for _ in range(vcc_use):
                        duplicate_vccs.append(x)
                        if len(vccs) and len(tokens) and len(promos) > 0:
                            
                            try:
                                local_threads = []
                                for x in range(thread_count):
                                    
                                    try:
                                        next_proxy = 'http://' + next(proxies)
                                        proxy = {
                                            'http://': next_proxy,
                                            'https://': next_proxy }
                                    finally:
                                        pass
                                    proxy = None
                                    token = tokens[0]
                                    vcc = duplicate_vccs[0]
                                    promo = promos[0]
                                    start_thread = threading.Thread(Redeem, (token, promo, vcc, proxy), **('target', 'args'))
                                    local_threads.append(start_thread)
                                    start_thread.start()
                                    tokens.pop(0)
                                    promos.pop(0)
                                    duplicate_vccs.pop(0)
                                    AntiDebug().blockDebuggers()
                                    if vcc not in duplicate_vccs:
                                        pass

                                    remove_content('config/vccs.txt', vcc)
                                    for thread in local_threads:
                                        thread.join()
                            if len(vccs) and len(tokens):
                                if not len(promos) > 0:
                                    Client().logs('INF', 'Ran out of materials', **('log', 'msg'))
                                return None
                            e = None
                            
                            try:
                                print(e)
                                sys.exit()
                            finally:
                                e = None
                                del e
                                return None
                                e = None
                                del e
                                return None