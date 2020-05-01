from youtube_api import YouTubeDataAPI
from discord.ext import commands
from io import BytesIO
from bs4 import BeautifulSoup
from gtts import gTTS
from os import path
import discordfrom youtube_api import YouTubeDataAPI
from discord.ext import commands
from io import BytesIO
from bs4 import BeautifulSoup
from gtts import gTTS
from os import path
import discord
import random
import datetime
import string
import urllib
import time
import cfscrape
import asyncio
import os

#yt = YouTubeDataAPI("AIzaSyDB-9pBXBWuvvaCSUUuXLOALv9EapjuAXA")
#yt = YouTubeDataAPI("AIzaSyC8HN3GCu4-lXolqfHCBlWVS9xRkSikvfI")
#yt = YouTubeDataAPI("AIzaSyAqvs-adIF_2xFWr1Gv51K1cHrliStoB14")
#yt = YouTubeDataAPI("AIzaSyAE4fTCHuX4wcTpMb8HLAHUexgu10-M5k8")
#yt = YouTubeDataAPI("AIzaSyAPcvoCSXaEAEIuJGDNfK8z0Qv3iz3jiH8")

yt = YouTubeDataAPI(random.choice(["AIzaSyDB-9pBXBWuvvaCSUUuXLOALv9EapjuAXA","AIzaSyC8HN3GCu4-lXolqfHCBlWVS9xRkSikvfI","AIzaSyAqvs-adIF_2xFWr1Gv51K1cHrliStoB14","AIzaSyAE4fTCHuX4wcTpMb8HLAHUexgu10-M5k8","AIzaSyAPcvoCSXaEAEIuJGDNfK8z0Qv3iz3jiH8"]))
 
bot = commands.Bot(command_prefix='$')

current = datetime.datetime.now()

scraper = cfscrape.create_scraper()

queue = []
nextSong = asyncio.Event()
        
@bot.event
async def on_ready():
    for server in bot.guilds:
        if not path.exists(server.name.replace(" ", "")):
            os.mkdir(server.name.replace(" ", ""))
            os.mkdir(server.name.replace(" ", "") + "/Music")
            print("Created a folder for " + server.name)
    for item in os.listdir(server.name.replace(" ", "") + "/Music"):
        os.remove(server.name.replace(" ", "") + "/Music/" + item)
    print("ready to fuck")

def PRINTSCgetURL():    
    while True:
        url = "https://prnt.sc/"
        for x in range(6):
            url += random.choice(string.ascii_lowercase + string.digits)
    
            site = scraper.get(url)
            soup = BeautifulSoup(site.content, "html.parser")
            ImageURL = soup.find(id="screenshot-image")["src"]
            print(ImageURL)
            if not ImageURL[0] == "/":
                return ImageURL
                print(ImageURL)

def IMGURgetURL():
    url = "https://imgur.com/"
    while True:
        url = "https://imgur.com/"
        for x in range(5):
            url += random.choice(string.ascii_letters + string.digits)
        url += ".jpg"
        if not urllib.request.urlopen(url).geturl() == "https://i.imgur.com/removed.png":     
            return url
            print(url)

@bot.command()
async def connect(ctx):
    print("Attempting to connect to voice channel...")
    global vc
    if ctx.author.voice == None:
        await ctx.channel.send("You must be in a voice channel to use this command")

    else:
        vc = await ctx.author.voice.channel.connect(reconnect=True)
        await ctx.channel.send("Joining channel")
        print("Joining " + str(vc.channel))

    output = gTTS(random.choice(["katbot has joined the chat", "katbot is here", "sup boys katbot here"]))            
    output.save("tts.mp3")
    vc.play(discord.FFmpegPCMAudio("tts.mp3"))
    
@bot.command()
async def effect(ctx, *choice): #soundboard
    if choice == ():
        print("Displaying soundboard...")
        await ctx.channel.send("""
----Soundboard----

1 - Rimshot
2 - Tough Talk
3 - Tasty
4 - Bitch
5 - Doofenshmirtz Theme
6 - TMNT Theme
7 - Thats Crazy Bro
8 - Wiggle
9 - Suck A Dick
10 - Wrong
69 - User left
420 - Penis LR
354 - Offset Penis
543 - My Anaconda BITCH
------------------


""")
        
    else:
            if ctx.author.voice == None:
                await ctx.channel.send("You must be in a voice channel to use this command")
            else:
                #try:
                choice = choice[0]
                if choice == "1":    
                    await vc.play(discord.FFmpegPCMAudio("rimshot.mp3"))
                elif choice == "2":
                    await vc.play(discord.FFmpegPCMAudio("fellow.mp3"))
                elif choice == "3":
                    await vc.play(discord.FFmpegPCMAudio("tasty.mp3"))
                elif choice == "4":
                    await vc.play(discord.FFmpegPCMAudio("bitch.mp3"))
                elif choice == "5":
                    await vc.play(discord.FFmpegPCMAudio("evil_inc.mp3"))
                elif choice == "6":
                    await vc.play(discord.FFmpegPCMAudio("tmnt.mp3"))
                elif choice == "7":
                    await vc.play(discord.FFmpegPCMAudio("bro.mp3"))
                elif choice == "8":
                    await vc.play(discord.FFmpegPCMAudio("wiggle.mp3"))
                elif choice == "9":
                    await vc.play(discord.FFmpegPCMAudio("suck.mp3"))
                elif choice == "10":
                    await vc.play(discord.FFmpegPCMAudio("wrong.mp3"))
                elif choice == "69":
                    await vc.play(discord.FFmpegPCMAudio("userLeft.mp3"))
                elif choice == "420":
                    await vc.play(discord.FFmpegPCMAudio("PenisLR.mp3"))
                elif choice == "354":
                    await vc.play(discord.FFmpegPCMAudio("OffsetPenis.mp3"))
                elif choice == "543":
                    await vc.play(discord.FFmpegPCMAudio("my-anaconda-BITCH.mp3"))
                #except:
                #    await ctx.channel.send("Connect to a voice channel using $connect")

async def countMembers(channel):
    x = 0
    for member in channel.members:
        if not member.bot:
            x += 1
    return x

@bot.event
async def on_voice_state_update(member, before, after): #join/leave effects & active channel
    global vc
    try:
        if not before.channel == after.channel and after.channel == vc.channel: #joining channel
            if member.nick == None:
                output = gTTS(random.choice(["Some bitch joined the chat", "another ass assasinated", "oh fuck somebody joined"]))
            elif member.bot:
                output = gTTS(random.choice(["a robot has joined", "oh my cock and balls its a mother fucking robot", "a bot joined the chat"]))
            else:   
                output = gTTS(member.nick + random.choice([" joined the chat", " is a bitch", " joined the mother fucking chat", " is here. yaaaay", " is here. damn", " is here. what a shame", " joined. hopefully they will leave soon"]))
            output.save("tts.mp3")
            await vc.play(discord.FFmpegPCMAudio("tts.mp3"))
            
        elif not after.channel == vc.channel: #leaving channel
            if member.nick == None:
                output = gTTS(random.choice(["An anonomous bastard left", "an assbitch left the channel", "aw shit somebody left"]))
            elif member.bot:
                output = gTTS(random.choice(["a robot has left", "a bot left the chat"]))
            else:   
                output = gTTS(member.nick + random.choice([" left the chat", " is a bitch and left", " left the mother fucking chat", " is no longer here. yaaaay", " left. damn", " is gone. what a shame", " left. hopefully they wont come back"]))
            output.save("tts.mp3")
            await vc.play(discord.FFmpegPCMAudio("tts.mp3"))

    
        print(await countMembers(vc.channel) + " non-bot users in current channel")
        if await countMembers(vc.channel) == 0: #stay in active channel
            print("current channel is empty")
            print("scanning for activity")
            numList = []
            for channel in vc.guild.voice_channels:
                num = await countMembers(channel)
                numList.append(num)
                if num == max(numList):
                    activeChannel = channel
            print("scan complete")
            if await countMembers(activeChannel) == 0:
                print("no users found")
                await vc.disconnect()
            else:
                print("moving to " + str(activeChannel))
                await vc.move_to(activeChannel) 
    except:
        pass
    
@bot.command()
async def image(ctx, *args):
    if args == ():
        amount = 1
        source = "imgur"
        
    elif len(args) == 2:
        amount = args[0]
        source = args[1]
        
    elif len(args) == 1: 
        try:
            amount = int(args[0])
            source = "imgur"
            
        except:
            amount = 1
            source = args[0]
        
        
    if source == "imgur":
        for x in range(int(amount)):
            pic = discord.Embed()
            pic.set_image(url=IMGURgetURL())
            await ctx.channel.send(embed=pic)

    elif source == "printsc":
        for x in range(int(amount)):
            pic = discord.Embed()
            pic.set_image(url=PRINTSCgetURL())
            await ctx.channel.send(embed=pic)

@bot.command()
async def say(ctx, *, message):
    print(ctx.channel)
    output = gTTS(message)
    output.save("tts.mp3")
    try:
        vc.play(discord.FFmpegPCMAudio("tts.mp3"))
    except:
        await ctx.channel.send("Connect to a voice channel using $connect")

@bot.command()
async def spreadVC(ctx):
    for member in vc.channel.members:
        await member.move_to(random.choice(vc.guild.voice_channels))

@bot.command()
async def coaster(ctx, *users):
    members = []
    "698336923139309609"
    track = bot.get_channel(693125008192700507).category.voice_channels #hard coded coaster location
    if users[0] == "all":
        for member in vc.channel.members:
            if not member.bot:
                members.append(member)        
    else:     
        for member in vc.channel.members:
            if str(member.id) in users and not member.bot:
                members.append(member)
    
    for channel in track:
        for user in members:
            await user.move_to(channel)
        await asyncio.sleep(0.2)

    track.reverse()

    for channel in track:
        for user in members:
            await user.move_to(channel)
        await asyncio.sleep(0.2)

    for user in members:
        await user.move_to(vc.channel)

@bot.command()
async def fortune(ctx):
    if random.randint(1,1000) == 1:
        await ctx.send("You will live a happy life")
    else:
        await ctx.send("You will die alone and depressed")
        
def getSong(serverName, name):
    for song in os.listdir(serverName + "/Music"):
        if name in song:
            return song

def playNextSong(error):
    global queue
    print(os.listdir(serverName + "/Music"))
    print(queue[0]["video_id"])
    for song in os.listdir(serverName + "/Music"):
        if queue[0]["video_id"] in song:
            os.remove(serverName + "/Music/" + song)
            
    queue.pop(0)
        
    nextSong.set()

@bot.command()
async def play(ctx, *, song):
    global queue
    global serverName
    
    serverName = ctx.guild.name.replace(" ", "")
    
    if ctx.author.voice == None:
        await ctx.channel.send("You must be in a voice channel to use this command")

    else:
        if song == ():
            try:
                await vc.resume()

            except:
                pass
                
        else:                
            if not vc.is_playing(): #play song
                if len(queue) == 0:
                    loading = await ctx.channel.send("Loading song...")
                    newSong = yt.search(q=song,max_results=1, search_type="video")[0]
                    queue.append(newSong)
                    print("Attempting to download " + newSong["video_title"])
                    os.system("youtube-dl --extract-audio -o " + serverName + "/Music/%(id)s.%(ext)s " + newSong["video_id"])
                    print("Download Successful")
                    
                while len(queue) > 0:
                    nextSong.clear()
                    for song in os.listdir(serverName + "/Music"):
                        if queue[0]["video_title"] in song:
                            break
                    print("Attempting to stream " + queue[0]["video_title"])
                    vc.play(discord.FFmpegPCMAudio(serverName + "/Music/" + song), after=playNextSong)
                    print("Stream Successful")
                    await loading.edit(content="Now playing " + queue[0]["video_title"] + " by " + queue[0]["channel_title"])
                    await nextSong.wait()
                    
                    
            else: #add to queue
                loading = await ctx.channel.send("Loading song...")
                newSong = yt.search(q=song,max_results=1, search_type="video")[0]
                queue.append(newSong)
                print("Adding " + newSong["video_title"] + " to queue")
                print("Attempting to download " + newSong["video_title"])
                os.system("youtube-dl --extract-audio -o " + serverName + "/Music/%(id)s.%(ext)s " + newSong["video_id"])
                print("Download Successful")
                await loading.edit(content=newSong["video_title"] + " by " + newSong["channel_title"] + " has been added to the queue")

        #except:
        #    await ctx.channel.send("something funky happened")

@bot.command()
async def skip(ctx):
    if ctx.author.voice == None:
        await ctx.channel.send("You must be in a voice channel to use this command")

    elif not vc.is_playing():
        await ctx.channel.send("fuck you")

    else:
        
        await ctx.channel.send("Skipping...")
        print("Skipping...")
        vc.stop()
    
@bot.command()
async def stop(ctx):
    if ctx.author.voice == None:
        await ctx.channel.send("You must be in a voice channel to use this command")

    else:
        try:    
            vc.stop()
            await ctx.channel.send("Music stopped")

            
        except:
             await ctx.channel.send("Connect to a voice channel using $connect")

@bot.command()
async def np(ctx):
    try:
        if not vc.is_playing():
            await ctx.channel.send("Music is not currently playing")

        else:
            await ctx.channel.send("Now playing " + video["video_title"] + " by " + video["channel_title"])

    except:
        await ctx.channel.send("Connect to a voice chanel using $connect")

@bot.command()
async def pause(ctx):
    if ctx.author.voice == None:
        await ctx.channel.send("You must be in a voice channel to use this command")

    elif not vc.is_playing():
        await ctx.channel.send("Not currently playing audio")
        
    else:
        try:    
            vc.pause()
            await ctx.channel.send("Music paused. Resume with $resume or $play")
            
        except:
             await ctx.channel.send("Connect to a voice channel using $connect")

@bot.command()             
async def resume(ctx):
    if ctx.author.voice == None:
        await ctx.channel.send("You must be in a voice channel to use this command")

    elif not vc.is_paused():
        await ctx.channel.send("Player is not paused")
        
    else:
        try:    
            await vc.resume()
            
        except:
             await ctx.channel.send("Connect to a voice channel using $connect")

@bot.command()             
async def clearqueue(ctx):
    for item in os.listdir(serverName + "/Music"):
        os.remove(serverName + "/Music" + item)
        
    await ctx.channel.send("Queue cleared")
    
@bot.command()             
async def disconnect(ctx):
    if ctx.author.voice == None:
        await ctx.channel.send("You must be in a voice channel to use this command")

    else:
        try:
            await vc.disconnect()
            await ctx.channel.send("Disconnected from voice channel")

        except:
            await ctx.channel.send("Connect to a voice channel using $connect")

@bot.command()             
async def ping(ctx):
    await ctx.send("Ping = {}ms".format(round(bot.latency), 2))

bot.run("TOKEN")

import random
import datetime
import string
import urllib
import time
import cfscrape
import asyncio
import os

#yt = YouTubeDataAPI("AIzaSyDB-9pBXBWuvvaCSUUuXLOALv9EapjuAXA")
#yt = YouTubeDataAPI("AIzaSyC8HN3GCu4-lXolqfHCBlWVS9xRkSikvfI")
#yt = YouTubeDataAPI("AIzaSyAqvs-adIF_2xFWr1Gv51K1cHrliStoB14")
#yt = YouTubeDataAPI("AIzaSyAE4fTCHuX4wcTpMb8HLAHUexgu10-M5k8")
#yt = YouTubeDataAPI("AIzaSyAPcvoCSXaEAEIuJGDNfK8z0Qv3iz3jiH8")

yt = YouTubeDataAPI(random.choice(["AIzaSyDB-9pBXBWuvvaCSUUuXLOALv9EapjuAXA","AIzaSyC8HN3GCu4-lXolqfHCBlWVS9xRkSikvfI","AIzaSyAqvs-adIF_2xFWr1Gv51K1cHrliStoB14","AIzaSyAE4fTCHuX4wcTpMb8HLAHUexgu10-M5k8","AIzaSyAPcvoCSXaEAEIuJGDNfK8z0Qv3iz3jiH8"]))
 
bot = commands.Bot(command_prefix='$')

current = datetime.datetime.now()

scraper = cfscrape.create_scraper()

queue = asyncio.Queue()
nextSong = asyncio.Event()

@bot.event
async def on_ready():
    for server in bot.guilds:
        if not path.exists(server.name.replace(" ", "")):
            os.mkdir(server.name.replace(" ", ""))
            os.mkdir(server.name.replace(" ", "") + "/Music")
            print("Created a folder for " + server.name)
    print("ready to fuck")

def PRINTSCgetURL():    
    while True:
        url = "https://prnt.sc/"
        for x in range(6):
            url += random.choice(string.ascii_lowercase + string.digits)
    
            site = scraper.get(url)
            soup = BeautifulSoup(site.content, "html.parser")
            ImageURL = soup.find(id="screenshot-image")["src"]
            print(ImageURL)
            if not ImageURL[0] == "/":
                return ImageURL
                print(ImageURL)

def IMGURgetURL():
    url = "https://imgur.com/"
    while True:
        url = "https://imgur.com/"
        for x in range(5):
            url += random.choice(string.ascii_letters + string.digits)
        url += ".jpg"
        if not urllib.request.urlopen(url).geturl() == "https://i.imgur.com/removed.png":     
            return url
            print(url)

@bot.command()
async def connect(ctx):
    print("Attempting to connect to voice channel...")
    global vc
    if ctx.author.voice == None:
        await ctx.channel.send("You must be in a voice channel to use this command")

    else:
        vc = await ctx.author.voice.channel.connect(reconnect=True)
        await ctx.channel.send("Joining channel")
        print("Joining " + str(vc.channel))

    output = gTTS(random.choice(["katbot has joined the chat", "katbot is here", "sup boys katbot here"]))            
    output.save("tts.mp3")
    vc.play(discord.FFmpegPCMAudio("tts.mp3"))
    
@bot.command()
async def effect(ctx, *choice): #soundboard
    if choice == ():
        print("Displaying soundboard...")
        await ctx.channel.send("""
----Soundboard----

1 - Rimshot
2 - Tough Talk
3 - Tasty
4 - Bitch
5 - Doofenshmirtz Theme
6 - TMNT Theme
7 - Thats Crazy Bro
8 - Wiggle
9 - Suck A Dick
10 - Wrong
69 - User left
420 - Penis LR
354 - Offset Penis
543 - My Anaconda BITCH
------------------


""")
        
    else:
            if ctx.author.voice == None:
                await ctx.channel.send("You must be in a voice channel to use this command")
            else:
                #try:
                choice = choice[0]
                if choice == "1":    
                    await vc.play(discord.FFmpegPCMAudio("rimshot.mp3"))
                elif choice == "2":
                    await vc.play(discord.FFmpegPCMAudio("fellow.mp3"))
                elif choice == "3":
                    await vc.play(discord.FFmpegPCMAudio("tasty.mp3"))
                elif choice == "4":
                    await vc.play(discord.FFmpegPCMAudio("bitch.mp3"))
                elif choice == "5":
                    await vc.play(discord.FFmpegPCMAudio("evil_inc.mp3"))
                elif choice == "6":
                    await vc.play(discord.FFmpegPCMAudio("tmnt.mp3"))
                elif choice == "7":
                    await vc.play(discord.FFmpegPCMAudio("bro.mp3"))
                elif choice == "8":
                    await vc.play(discord.FFmpegPCMAudio("wiggle.mp3"))
                elif choice == "9":
                    await vc.play(discord.FFmpegPCMAudio("suck.mp3"))
                elif choice == "10":
                    await vc.play(discord.FFmpegPCMAudio("wrong.mp3"))
                elif choice == "69":
                    await vc.play(discord.FFmpegPCMAudio("userLeft.mp3"))
                elif choice == "420":
                    await vc.play(discord.FFmpegPCMAudio("PenisLR.mp3"))
                elif choice == "354":
                    await vc.play(discord.FFmpegPCMAudio("OffsetPenis.mp3"))
                elif choice == "543":
                    await vc.play(discord.FFmpegPCMAudio("my-anaconda-BITCH.mp3"))
                #except:
                #    await ctx.channel.send("Connect to a voice channel using $connect")

async def countMembers(channel):
    x = 0
    for member in channel.members:
        if not member.bot:
            x += 1
    return x

@bot.event
async def on_voice_state_update(member, before, after): #join/leave effects & active channel
    global vc
    try:
        if not before.channel == after.channel and after.channel == vc.channel: #joining channel
            if member.nick == None:
                output = gTTS(random.choice(["Some bitch joined the chat", "another ass assasinated", "oh fuck somebody joined"]))
            elif member.bot:
                output = gTTS(random.choice(["a robot has joined", "oh my cock and balls its a mother fucking robot", "a bot joined the chat"]))
            else:   
                output = gTTS(member.nick + random.choice([" joined the chat", " is a bitch", " joined the mother fucking chat", " is here. yaaaay", " is here. damn", " is here. what a shame", " joined. hopefully they will leave soon"]))
            output.save("tts.mp3")
            await vc.play(discord.FFmpegPCMAudio("tts.mp3"))
            
        elif not after.channel == vc.channel: #leaving channel
            if member.nick == None:
                output = gTTS(random.choice(["An anonomous bastard left", "an assbitch left the channel", "aw shit somebody left"]))
            elif member.bot:
                output = gTTS(random.choice(["a robot has left", "a bot left the chat"]))
            else:   
                output = gTTS(member.nick + random.choice([" left the chat", " is a bitch and left", " left the mother fucking chat", " is no longer here. yaaaay", " left. damn", " is gone. what a shame", " left. hopefully they wont come back"]))
            output.save("tts.mp3")
            await vc.play(discord.FFmpegPCMAudio("tts.mp3"))

    
        print(await countMembers(vc.channel) + " non-bot users in current channel")
        if await countMembers(vc.channel) == 0: #stay in active channel
            print("current channel is empty")
            print("scanning for activity")
            numList = []
            for channel in vc.guild.voice_channels:
                num = await countMembers(channel)
                numList.append(num)
                if num == max(numList):
                    activeChannel = channel
            print("scan complete")
            if await countMembers(activeChannel) == 0:
                print("no users found")
                await vc.disconnect()
            else:
                print("moving to " + str(activeChannel))
                await vc.move_to(activeChannel) 
    except:
        pass
    
@bot.command()
async def image(ctx, *args):
    if args == ():
        amount = 1
        source = "imgur"
        
    elif len(args) == 2:
        amount = args[0]
        source = args[1]
        
    elif len(args) == 1: 
        try:
            amount = int(args[0])
            source = "imgur"
            
        except:
            amount = 1
            source = args[0]
        
        
    if source == "imgur":
        for x in range(int(amount)):
            pic = discord.Embed()
            pic.set_image(url=IMGURgetURL())
            await ctx.channel.send(embed=pic)

    elif source == "printsc":
        for x in range(int(amount)):
            pic = discord.Embed()
            pic.set_image(url=PRINTSCgetURL())
            await ctx.channel.send(embed=pic)

@bot.command()
async def say(ctx, *, message):
    print(ctx.channel)
    output = gTTS(message)
    output.save("tts.mp3")
    try:
        vc.play(discord.FFmpegPCMAudio("tts.mp3"))
    except:
        await ctx.channel.send("Connect to a voice channel using $connect")

@bot.command()
async def spreadVC(ctx):
    for member in vc.channel.members:
        await member.move_to(random.choice(vc.guild.voice_channels))

@bot.command()
async def coaster(ctx, *users):
    members = []
    "698336923139309609"
    track = bot.get_channel(693125008192700507).category.voice_channels #hard coded coaster location
    if users[0] == "all":
        for member in vc.channel.members:
            if not member.bot:
                members.append(member)        
    else:     
        for member in vc.channel.members:
            if str(member.id) in users and not member.bot:
                members.append(member)
    
    for channel in track:
        for user in members:
            await user.move_to(channel)
        await asyncio.sleep(0.2)

    track.reverse()

    for channel in track:
        for user in members:
            await user.move_to(channel)
        await asyncio.sleep(0.2)

    for user in members:
        await user.move_to(vc.channel)

@bot.command()
async def fortune(ctx):
    if random.randint(1,1000) == 1:
        await ctx.send("You will live a happy life")
    else:
        await ctx.send("You will die alone and depressed")

def playNextSong(error):
    if vc.is_playing():
        vc.stop()
    nextSong.set()

@bot.command()
async def play(ctx, *, song):
    global queue
    global video

    serverName = ctx.guild.name.replace(" ", "")
    
    if ctx.author.voice == None:
        await ctx.channel.send("You must be in a voice channel to use this command")
    else:
        #try:
        if song == ():
            try:
                await vc.resume()

            except:
                song = os.listdir(serverName + "/Music")[0]
                vc.play(discord.FFmpegPCMAudio(song), after=playNextSong)
                
        else:
            loading = await ctx.channel.send("Loading song...")
            newSong = yt.search(q=song,max_results=1, search_type="video")[0]
            print("Adding " + newSong["video_title"] + " to queue")
            await queue.put(newSong)
            
        if not vc.is_playing():
            while not queue.empty():
                nextSong.clear()
                video = await queue.get()
                print("Attempting to download " + video["video_title"])
                os.system("youtube-dl --extract-audio -o " + serverName + "/Music/Song.%(ext)s " + video["video_id"])
                print(song)
                song = os.listdir(serverName + "/Music")[0]
                
                print("Download Successful")
                print("Attempting to stream " + video["video_title"])
                vc.play(discord.FFmpegPCMAudio(song), after=playNextSong)
                print("Stream Successful")
                await loading.edit(content="Now playing " + video["video_title"] + " by " + video["channel_title"])
                await nextSong.wait()
                queue.task_done()
                
        else:
            await loading.edit(content=newSong["video_title"] + " by " + newSong["channel_title"] + " has been added to the queue")
        #except:
        #    await ctx.channel.send("something funky happened")

@bot.command()
async def skip(ctx):
    if ctx.author.voice == None:
        await ctx.channel.send("You must be in a voice channel to use this command")

    elif not vc.is_playing():
        await ctx.channel.send("fuck you")

    else:
        
        await ctx.channel.send("Skipping...")
        print("Skipping...")
        playNextSong("")
    
@bot.command()
async def stop(ctx):
    if ctx.author.voice == None:
        await ctx.channel.send("You must be in a voice channel to use this command")

    else:
        try:    
            vc.stop()
            await ctx.channel.send("Music stopped")

            
        except:
             await ctx.channel.send("Connect to a voice channel using $connect")

@bot.command()
async def np(ctx):
    try:
        if not vc.is_playing():
            await ctx.channel.send("Music is not currently playing")

        else:
            await ctx.channel.send("Now playing " + video["video_title"] + " by " + video["channel_title"])

    except:
        await ctx.channel.send("Connect to a voice chanel using $connect")

@bot.command()
async def pause(ctx):
    if ctx.author.voice == None:
        await ctx.channel.send("You must be in a voice channel to use this command")

    elif not vc.is_playing():
        await ctx.channel.send("Not currently playing audio")
        
    else:
        try:    
            vc.pause()
            await ctx.channel.send("Music paused. Resume with $resume or $play")
            
        except:
             await ctx.channel.send("Connect to a voice channel using $connect")

@bot.command()             
async def resume(ctx):
    if ctx.author.voice == None:
        await ctx.channel.send("You must be in a voice channel to use this command")

    elif not vc.is_paused():
        await ctx.channel.send("Player is not paused")
        
    else:
        try:    
            await vc.resume()
            
        except:
             await ctx.channel.send("Connect to a voice channel using $connect")

@bot.command()             
async def clearqueue(ctx):
    global queue
    queue = asyncio.Queue()
    
@bot.command()             
async def disconnect(ctx):
    if ctx.author.voice == None:
        await ctx.channel.send("You must be in a voice channel to use this command")

    else:
        try:
            await vc.disconnect()
            await ctx.channel.send("Disconnected from voice channel")

        except:
            await ctx.channel.send("Connect to a voice channel using $connect")

@bot.command()             
async def ping(ctx):
    await ctx.send("Ping = {}ms".format(round(bot.latency), 2))

bot.run("TOKEN")
