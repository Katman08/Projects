import discord
import random
import datetime
import string
import urllib
import time
from io import BytesIO
from bs4 import BeautifulSoup
import cfscrape

current = datetime.datetime.now()

scraper = cfscrape.create_scraper()

responses = open("responses.txt")
responses = responses.readlines()

Override = False
NickOn = False
length = 0

for line in responses:
    length += 1
    
def PRINTSCgetURL():
    url = "https://prnt.sc/"

    for x in range(6):
            url += random.choice(string.ascii_lowercase + string.digits)

    while True:
        print("G")
        site = scraper.get(url)
        soup = BeautifulSoup(site.content, "html.parser")
        ImageURL = soup.find(id="screenshot-image")["src"]
        if not list(ImageURL)[1:2] == "//":
            return ImageURL

def IMGURgetURL():
    url = "https://imgur.com/"
    while True:
        url = "https://imgur.com/"
        for x in range(5):
            url += random.choice(string.ascii_letters + string.digits)
        url += ".jpg"
        if not urllib.request.urlopen(url).geturl() == "https://i.imgur.com/removed.png":     
            return url

client = discord.Client()

@client.event
async def on_ready():
    print("ready to fuck")

@client.event
async def on_message(message):
    global vc
    global NickOn
    global MessageBU

    MessageBU = message
    
    if message.author == client.user:
        return
    elif message.channel.id == 697903857736351746:
        if not current.strftime("%H:%M") == "4:21" and not current.strftime("%H:%M") == "16:21":
            await message.delete()
    elif message.content.startswith("status"):
        if len(message.content) % 2 == 0:  
            await message.channel.send("NOT ready to fuck^^")
        else:
            await message.channel.send("ready to fuck^^")

    elif message.content == "join vc":
        await message.channel.send("joining")
        vc = await message.author.voice.channel.connect()

    elif message.content == "lmao":
        await vc.play(discord.FFmpegPCMAudio("rimshot.mp3"))

    elif message.content == "haha":
        haha = []
        HaHaLength = random.randint(1,90)

        for x in range(1,HaHaLength):
            haha.append(random.choice(["h", "a", "a"]))

        await message.channel.send("".join(haha), tts=True)
        
    elif message.content == "!nickon":
        NickOn = True
        await message.channel.send("Nick change activated")

    elif message.content == "!nickoff":
        NickOn = False
        await message.channel.send("Nick change deactivated")

    elif NickOn:
        if len(message.content) <= 32: 
            NickLength = len(message.content)
        else:
            NickLength = 32
        await message.author.edit(nick=message.content[:NickLength], reason="nick game")

    elif message.content.startswith("image"):
        messageList = message.content.split(" ")
        if len(messageList) == 2:
            pics = int(messageList[1])
        else:
            pics = 1
        for x in range(pics):
            pic = discord.Embed()
            pic.set_image(url=IMGURgetURL())
            await message.channel.send(embed=pic)
        
        
    elif random.randint(1,10) == 1:
        await message.channel.send(responses[random.randint(0,length-1)])

@client.event
async def on_voice_state_update(member, before, after):
    
    if str(before.channel) == "None":
        await vc.play(discord.FFmpegPCMAudio(random.choice(["R-Alert.mp3", "tasty.mp3", "idiot.mp3", "fellow.mp3"])))

@client.event
async def on_message_delete(message):
    global Override
    
    if Override:
        Override = False
    elif message.author == client.user:
        await message.channel.send(message.content)
    else:
        await message.channel.send(message.author.nick + " really did just delete their message. >>> " + str(message.content), tts=True)

@client.event
async def on_reaction_add(reaction, user):  
    global Override
    
    if str(reaction) == "❌":
        await MessageBU.delete()
        Override = True

client.run(TOKEN)
