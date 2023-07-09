# EDUCATIONAL PURPOSES
# Fat big cock generator for Spotify
# By H4cK3dR4Du#0001 & yx#7510
import os
import time
import json
import ctypes
try:
    import requests
    import colored
    import pystyle
    import random
    import string
    import httpx
    import uuid
    import threading
    import datetime
except ModuleNotFoundError:
    os.system('pip install requests')
    os.system('pip install colored')
    os.system('pip install pystyle')
    os.system("pip install random")
    os.system("pip install string")
    os.system("pip install httpx")
    os.system("pip install uuid")
    os.system("pip install threading")
    os.system("pip install datetime")

from threading import Thread, active_count
from colored import fg
from pystyle import Write, System, Colors, Colorate
from json import dumps
from uuid import uuid4
from random import choice, choices, randint
from datetime import datetime
from colorama import Fore
red = Fore.RED
purple = Fore.MAGENTA
yellow = Fore.YELLOW
green = Fore.GREEN
nothing = Fore.RESET
dark_blue = Fore.BLUE
gray = Fore.LIGHTBLACK_EX
blue = Fore.BLUE
pink = Fore.LIGHTMAGENTA_EX

madeAccounts = 0
failed_accs = 0
proxy_error = 0
    
def run_account_creation(session):
    while True:
        try:
            token = client_token(session)
            csrf = get_csrf(session)
            generate_account(session, token, csrf)
        except Exception as e:
            pass

def get_current_time():
    current_time = datetime.now().strftime("%H:%M:%S")
    return current_time

def getBirthday():
        day = str(randint(1, 28))
        month = str(randint(1, 12))

        if int(month) < 10: month = "0" + month
        if int(day) < 10: day = "0" + day

        birthday = "-".join([str(randint(1910, 2004)), month, day])
        return birthday

def generate_email():
    with open("data/config.json") as file:
        data = json.load(file)
        gen = data['Email_Names']
        if gen == "" or gen == " ":
            gen = ''.join(random.choices(string.ascii_lowercase + string.digits, k=17))
            domain = "gmail.com"
            email = f"{gen}@{domain}"
            return email
        else:
            domain = "gmail.com"
            email = f"{gen}@{domain}"
            return email

def generate_username():
    with open("data/config.json") as file:
        data = json.load(file)
        usernames = data['Username']
        if usernames == "" or usernames == " ":
            username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            names = ["Radu loves Spotify", "yx1337 is cool", "radutool", "PussyKill", "Big fat cock", "h4ck3dr4du", "yx1337", "imagine genned", "spotifai", "cool gen - radu / yx", "yx is cool", "radu is cool", "very big cock", "fat cock", "penis", "pizda cu chapa"]
            name = choice(names)
            user = username + " | " + name
            username = user
            return username
        else:
            username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            user = usernames + " | " + username
            username = user
            return username

def generate_password():
    with open("data/config.json") as file:
        data = json.load(file)
        check_pass = data['Password']
        if check_pass == "" or check_pass == " ":
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            return password
        else:
            password = check_pass
            return password

def getAvatar():
    avatars = ["images-75.jpg", "images-76.jpg", "images-77.jpg", "images-78.jpg", "images-79.jpg", "images-80.jpg", "images-81.jpg", "images-82.jpg", "images-83.jpg", "images-84.jpg", "images-85.jpg", "images-86.jpg", "images-87.jpg", "images-88.jpg", "images-89.jpg", "images-90.jpg", "images-91.jpg"]
    image = open('data/avatars/' + choice(avatars), 'rb').read()
    return image
def set_console_title(title):
    ctypes.windll.kernel32.SetConsoleTitleW(title)

set_console_title(f"Spotify Account Creator | By H4cK3dR4Du & yx1337 | github.com/H4cK3dR4Du ~ github.com/yxsyn")

def check_if_proxy():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0"
    }
    with open("data/config.json") as checkproxy:
        data = json.load(checkproxy)
    want_proxy = data['Use_Proxy']
    if want_proxy == "y":
        with open("data/proxies.txt", "r") as proxy_select:
            proxies = proxy_select.readlines()
        
        random_proxy = random.choice(proxies).strip()
        proxies = {"http://": f"http://{random_proxy}", "https://": f"http://{random_proxy}"}
        session = httpx.Client(headers=headers, proxies=proxies, timeout=30)
    if want_proxy == "n":
        session = httpx.Client(headers=headers, timeout=30)

    return session

def client_token(session):
    session = check_if_proxy()
    try:
            payload = {
                "client_data": {
                    "client_id": "d8a5ed958d274c2e8ee717e6a4b0971d",
                    "client_version": "1.2.10.278.g261ea664",
                    "js_sdk_data": {
                        "device_brand": "unknown",
                        "device_model": "desktop",
                        "os": "Windows",
                        "os_version": "NT 10.0",
                    }
                }
            }

            headers = {
                "Host": "clienttoken.spotify.com",
                "Accept": "application/json",
                "Accept-Language": "tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3",
                "Accept-Encoding": "gzip, deflate, br",
                "Content-Type": "application/json",
                "Content-Length": str(len(json.dumps(payload))),
                "Origin": "https://open.spotify.com",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-site",
                "Referer": "https://open.spotify.com/",
                "Connection": "keep-alive",
                "TE": "trailers"
            }

            response = session.post(url='https://clienttoken.spotify.com/v1/clienttoken', headers=headers, json=payload)
            if response.status_code == 200:
                current_time = get_current_time()
                return response.json()['granted_token']['token']
            else:
                pass
    except requests.exceptions.RequestException as e:
            pass
def get_csrf(session):
    session = check_if_proxy()
    headers = {
            "Host": "www.spotify.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "TE": "trailers"
    }
    current_time = get_current_time()
    response = session.get(url='https://www.spotify.com/us/signup', headers=headers)
    if response.status_code == 200:
        return response.text.split('csrfToken')[1].split('"')[2]
    else:
        pass

def get_token(login_token):
    session = check_if_proxy()
    headers = {
            "Host": "www.spotify.com",
            "Accept": "*/*",
            "Accept-Language": "tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": "https://www.spotify.com/us/signup?forward_url=https%3A%2F%2Fopen.spotify.com%2F",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRF-Token": get_csrf(session),
            "X-KL-Ajax-Request": "Ajax_Request",
            "Content-Length": "28",
            "Origin": "https://www.spotify.com",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "TE": "trailers"
    }
    response = session.post(url='https://www.spotify.com/api/signup/authenticate', headers=headers, data=f'splot={login_token}')
    if response.status_code == 200:
            headers = {
                "Accept": "application/json",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "spotify-app-version": "1.2.10.278.g261ea664",
                "app-platform": "WebPlayer",
                "Host": "open.spotify.com",
                "Referer": "https://open.spotify.com/",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "TE": "trailers"
            }
            response2 = session.get(url='https://open.spotify.com/get_access_token?reason=transport&productType=web_player', headers=headers)
            if response2.status_code == 200:
                current_time = get_current_time()
                print(f"{current_time}{green} Generator{nothing} > {blue}Successfully Got {yellow}Spotify{blue} Token{nothing}")
                return response2.json()['accessToken']
            else:
                current_time = get_current_time()
                print(f"{current_time}{red} Failed{nothing} > {blue}Error Getting {yellow}Spotify{blue} Token{nothing}")
                pass
    else:
        pass

def generate_account(session, token, csrf):
    global madeAccounts
    global failed_accs
    global proxy_error
    session = check_if_proxy()
    birthday = getBirthday()
    username = generate_username()
    password = generate_password()
    gmail = generate_email()
    c_token = client_token(session)
    current_time = get_current_time()
    payload = { 
        "account_details": {
            "birthdate": birthday,
            "consent_flags": {
                "eula_agreed": True,
                "send_email": True,
                "third_party_email": True
            },
            "display_name": username,
            "email_and_password_identifier": {
                "email": gmail,
                "password": password
            },
            "gender": randint(1, 2)
        },
        "callback_uri": "https://auth-callback.spotify.com/r/android/music/signup",
        "client_info": {
            "api_key": "142b583129b2df829de3656f9eb484e6",
            "app_version": "v2",
            "capabilities": [1],
            "installation_id": str(uuid4()),
            "platform": "Android-ARM"
        },
        "tracking": {
            "creation_flow": "",
            "creation_point": "client_mobile",
            "referrer": ""
        }
    }

    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip',
        'accept-language': 'en-US;q=0.5',
        "app-platform": "Android",
        'client-token': c_token,
        'connection': 'Keep-Alive',
        'Origin': 'https://www.spotify.com',
        'content-length': str(len(json.dumps(payload))),
        'host': 'spclient.wg.spotify.com',
        'spotify-app-version': '8.8.0.347',
        'user-agent': 'Spotify/8.8.0.347 Android/25 (SM-G988N)',
        'x-client-id': str(uuid4()).replace('-', ''),
    }
    try:
        response = session.post(url='https://spclient.wg.spotify.com/signup/public/v2/account/create', headers=headers, json=payload)
    except requests.exceptions.RequestException as e:
        pass
    if response.status_code == 200 and 'success' in response.text:
        current_time = get_current_time()
        print(f"{current_time}{dark_blue} Generated{nothing} > {blue}Email : {yellow}{gmail}{nothing} | {blue}Pass : {yellow}{password[:10]}*{nothing} | {blue}User : {yellow}{username}{nothing}")
        print(f"{current_time}{yellow} Credentials{nothing} > {blue}Created Email {nothing}| {yellow}{gmail}{nothing}")
        print(f"{current_time}{yellow} Credentials{nothing} > {blue}Created Password {nothing}| {yellow}{password}{nothing}")
        print(f"{current_time}{yellow} Credentials{nothing} > {blue}Created Date-Of-Birth {nothing}| {yellow}{birthday}{nothing}")
        print(f"{current_time}{yellow} Credentials{nothing} > {blue}Created Username {nothing}| {yellow}{username}{nothing}")
        print(f"{current_time}{pink} Client Token{nothing} > {pink}{c_token[:60]}********{nothing}")
        with open("data/config.json") as carlos:
            data = json.load(carlos)
            interact = data.get("discordInteraction")
            if interact == "y":
                with open("data/config.json") as carlos:
                    data = json.load(carlos)
                    hook = data.get("discordWebhook")
                    msg = f"```Gmail : {gmail}\nPassword : {password}```"
                    ms_data = {
                        "content": msg
                    }
                    r = requests.post(hook, data=ms_data)
                    if r.status_code == 200 or r.status_code == 201 or r.status_code == 204:
                        current_time = get_current_time()
                        print(f"{nothing}{current_time}{dark_blue} Sent Account {nothing}> {blue}{hook[:60]}*******")
        with open('Results/accounts.txt', 'a', encoding='utf-8') as f:
            f.write(f"Gmail : {gmail} | Password : {password} | Generated By H4cK3dR4Du Spotify Account Generator\n")
            print(f"{current_time}{green} Account Saver{nothing} > {blue}Saved Account {green}Successfully{nothing}")
        madeAccounts += 1
        account_id = response.json()['success']['username']
        login_token = response.json()['success']['login_token']
        token = get_token(login_token)
    elif 'VPN' in response.text:
        try:
            current_time = get_current_time()
            print(f"{current_time}{red} Failed{nothing} > {blue}Ratelimit{nothing}")
        except UnboundLocalError:
            current_time = get_current_time()
            print(f"{current_time}{red} Failed{nothing} > {blue}Ratelimit{nothing}")
    else:
        pass
        failed_accs += 1
        if failed_accs >= 3:
            proxy_error += 1
            pass
    
session = check_if_proxy()

with open("data/config.json") as file:
    data = json.load(file)
    thread_count = data['Threads']

threads = []
for _ in range(thread_count):
    thread = threading.Thread(target=run_account_creation, args=(session,))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()
