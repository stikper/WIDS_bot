import asyncio
import os
import re
import pickle
import subprocess
from threading import Timer
import websocket
import json
import time
import asyncio

from pyrogram import Client, idle, filters
from pyrogram.types import (InlineQueryResultArticle, InputTextMessageContent, ReplyKeyboardMarkup, KeyboardButton,
                            InlineKeyboardMarkup,
                            InlineKeyboardButton, ReplyKeyboardRemove)


ABS_PATH = os.path.dirname(os.path.abspath(__file__))
from API_TOKEN import *

async def set_adapter_mode(adapter, mode):
    subprocess.run(f'sudo ifconfig {adapter} down && sudo iwconfig {adapter} mode {mode} && sudo ifconfig {adapter} up', shell=True, capture_output=True, text=True)
async def get_adapter_list():
    output = subprocess.run('iw dev', shell=True, capture_output=True, text=True).stdout
    return re.findall(r'(?<=Interface )\w+', output)

async def get_network_list(adapter):
    output = subprocess.run(f'sudo iw dev {adapter} scan', shell=True, capture_output=True, text=True).stdout
    network_list = re.split(r'BSS (?=[\da-f][\da-f])', output)
    network_list.pop(0)
    networks = []
    for network in network_list:
        bssid = re.findall(r'(?<!:)\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b(?!:)', network)[0]
        ssid = re.findall(r'(?<=SSID: )[\w\- ]+', network)
        if len(ssid) == 0:  continue
        ssid = ssid[0]
        channel = re.findall(r'(?<=channel )\d+', network)[0]
        networks.append([bssid, ssid, channel])
    return networks

async def monitor_start(user):
    await set_adapter_mode(user.adapter, "monitor")
    user.monitor = subprocess.Popen(f"python monitor.py {user.adapter} {user.network[0]} {user.network[2]}", shell=True,
                                    stdout=subprocess.DEVNULL)
    await monitor_get_pkt_cnt(user)

async def monitor_stop(user):
    await monitor_get_pkt_cnt(user)
    user.monitor.send_signal(2)
    user.monitor.kill()

async def monitor_get_pkt_cnt(user):
    if user.monitor.poll() is not None:
        return monitor_stop(user)
    def on_open(ws):
        ws.send("get_pkt_cnt")
        return

    def on_message(ws, message):
        user.packet_counter = json.loads(message)

    def on_close(ws, _, __):
        return

    ws = websocket.WebSocketApp("ws://localhost:8765",
                                on_open=on_open,
                                on_message=on_message,
                                on_close=on_close)
    ws.run_forever()
    await check_for_attack(user)
    await asyncio.sleep(1)
    if user.monitor_enabled: await monitor_get_pkt_cnt(user)

async def update_status(user):
    while user.status_update:
        await execute(user, "/status_update")
        await asyncio.sleep(20)
    await execute(user, "/status_update")

async def check_for_attack(user):
    if get_frame_cnt(user.packet_counter, '0x000c') > 10 and not user.under_attack:
        await execute(user, "/attack")
        user.under_attack = True
    elif get_frame_cnt(user.packet_counter, '0x000c') < 10:
        user.under_attack = False


async def get_status(user):
    markup = []
    if not user.status_update:
        markup.append([InlineKeyboardButton('🟡 Автообновление выключено', '/status_update_on')])
    else:
        markup.append([InlineKeyboardButton('🟢 Автообновление включено', '/status_update_off')])
    if not user.monitor_enabled:
        markup.append([InlineKeyboardButton('🔴 Монитор выключен', '/monitor_on')])
    else:
        markup.append([InlineKeyboardButton('🟢 Монитор включен', '/monitor_off')])
    named_tuple = time.localtime()  # получить struct_time
    time_string = time.strftime("%m/%d/%Y, %H:%M:%S", named_tuple)
    sum_frames = sum(i for i in user.packet_counter.values())
    text = (f"🕖 {time_string}\n📥 За последние 10 секунд: кадров: {sum_frames}\n"
            f"❌ Кадров деаутентификации: {get_frame_cnt(user.packet_counter, '0x000c')}\n"
            f"✅ Кадров ассоциации: {get_frame_cnt(user.packet_counter, '0x0000')}\n"
            f"🔑 Кадров аутентификации: {get_frame_cnt(user.packet_counter, '0x000b')}\n")
    return text, markup

def get_frame_cnt(counter, frame):
    if frame in counter.keys():
        return counter[frame]
    return 0


class User:
    def __init__(self, user):
        self.id = user.id
        self.is_configured = False
        self.adapter = ""
        self.network = []
        self.adapter_list = []
        self.network_list = []
        self.status_message = None
        self.status_update = False
        self.monitor_enabled = False
        self.monitor = None
        self.packet_counter: dict[str, int] = {}
        self.under_attack = False




class App:
    def __init__(self):
        self.users: dict[int, User] = {}  # id -> User
        self.whitelist: list[int] = []
        # Users loading
        # if os.path.isfile("users.pickle"):
        #     with open("users.pickle", "rb") as file:
        #         self.users = pickle.load(file)
        # else:
        #     self.users = {}
        #     self.dump()
        # Whitelist loading
        if os.path.isfile("whitelist.txt"):
            with open("whitelist.txt", "r") as file:
                f = file.read()
                a = re.findall('\d+', f)
                self.whitelist = list(map(int, a))

    def auth(self, user):
        if user.id not in self.users:
            self.users[user.id] = User(user)
        return self.users[user.id]

    def dump(self):
        with open("users.pickle", "wb") as file:
            pickle.dump(self.users, file)


app = App()
bot = Client('stikper', api_id=API_ID,
             api_hash=API_HASH,
             bot_token=BOT_TOKEN)


async def execute(user, text):
    user = app.auth(user)
    uid = user.id
    if uid not in app.whitelist:
        await bot.send_message(uid, "Доступ запрещён")
        return
    match text:
        case "/start":
            await bot.send_message(uid, "Привет!\n\n🔐 Это система безопасности Wi-Fi!\n\n🖥️ С помощью данного бота Вы можете отслеживать состояние Вашей беспроводной сети.\n\n🔔 Вы также можете подключить оповещения, тогда бот будет сообщать вам о подозрительном трафике на вашем канале.")
            if not user.is_configured:
                await bot.send_message(uid, "Необходимо выполнить настройку ⚙️")
                await execute(user, "/adapter")
            else:
                await execute(user, "/status")

        case "/adapter":
            user.adapter_list = await get_adapter_list()
            markup = [[InlineKeyboardButton(f'{user.adapter_list[i]}', f'/adapter {i}')] for i in
                      range(len(user.adapter_list))]
            await bot.send_message(uid, "Выберите адаптер:", reply_markup=InlineKeyboardMarkup(markup))

        case str(x) if "/adapter" in x:
            number = int(re.findall(r'\d+', x)[0])
            user.adapter = user.adapter_list[number]
            await bot.send_message(uid, f"Выбран адаптер {user.adapter}")
            await set_adapter_mode(user.adapter, "managed")
            await execute(user, "/network")

        case "/network":
            user.network_list = await get_network_list(user.adapter)
            markup = [[InlineKeyboardButton(f'🛜 {user.network_list[i][1]}', f'/network {i}')] for i in
                      range(len(user.network_list))]
            await bot.send_message(uid, "Выберите сеть:", reply_markup=InlineKeyboardMarkup(markup))

        case str(x) if "/network" in x:
            number = int(re.findall(r'\d+', x)[0])
            user.network = user.network_list[number]
            await bot.send_message(uid, f"Выбранa сеть {user.network[1]}")
            user.is_configured = True
            await execute(user, "/status")

        case "/status":
            text, markup = await get_status(user)
            user.status_message = await bot.send_message(uid, text, reply_markup=InlineKeyboardMarkup(markup))
        case "/status_update":
            text, markup = await get_status(user)
            await user.status_message.edit_text(text, reply_markup=InlineKeyboardMarkup(markup))

        case "/status_update_on":
            user.status_update = True
            await update_status(user)
        case "/status_update_off":
            user.status_update = False
            await update_status(user)
        case "/monitor_on":
            user.monitor_enabled = True
            await execute(user, "/status_update")
            await monitor_start(user)
        case "/monitor_off":
            user.monitor_enabled = False
            await execute(user, "/status_update")
            await monitor_stop(user)

        case "/attack":
            await bot.send_message(uid, f"‼️ **Обнаружена атака!** ‼️\n __{get_frame_cnt(user.packet_counter, '0x000c')}__"
                                        f" фреймов деаутентификации за 10 секунд")

        case "/kb":
            await bot.send_message(uid, "keyboard", reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton('Row1 btn1', '/cmd1'),
                    InlineKeyboardButton('Row1 btn2', '/cmd2'),
                ],
                [
                    InlineKeyboardButton('Row 2 btn1', '/cmd3')
                ]
            ]))

        case str(x) if "/cmd" in x:
            await bot.send_message(uid, f'received cmd with number {x[5:]}')

        case _:
            if "complex expressions":
                await bot.send_message(uid, 'not found')


@bot.on_message(~filters.me & filters.text)
async def message_received(b, message):
    return await execute(message.from_user, message.text)


@bot.on_callback_query()
async def callback_received(b, query):
    await execute(query.from_user, query.data)
    return await query.answer()


if __name__ == "__main__":
    bot.start()
    idle()
    app.dump()
    bot.stop()
