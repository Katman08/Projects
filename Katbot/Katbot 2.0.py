from youtube_api import YouTubeDataAPI
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
        if not path.exists("C:/Users/Administrator/Desktop/Discord_Bot/" + server.name.replace(" ", "")):
            os.mkdir("C:/Users/Administrator/Desktop/Discord_Bot/" + server.name.replace(" ", ""))
            os.mkdir("C:/Users/Administrator/Desktop/Discord_Bot/" + server.name.replace(" ", "") + "/Music")
            print("Created a folder for " + server.name)
    for item in os.listdir("C:/Users/Administrator/Desktop/Discord_Bot/" + server.name.replace(" ", "") + "/Music"):
        os.remove("C:/Users/Administrator/Desktop/Discord_Bot/" + server.name.replace(" ", "") + "/Music/" + item)
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
    output.save("C:/Users/Administrator/Desktop/Discord_Bot/" + ctx.guild.name.replace(" ", "") + "tts.mp3")
    vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/" + ctx.guild.name.replace(" ", "") + "tts.mp3"))
    
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
                    await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/rimshot.mp3"))
                elif choice == "2":
                    await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/fellow.mp3"))
                elif choice == "3":
                    await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/tasty.mp3"))
                elif choice == "4":
                    await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/bitch.mp3"))
                elif choice == "5":
                    await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/evil_inc.mp3"))
                elif choice == "6":
                    await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/tmnt.mp3"))
                elif choice == "7":
                    await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/bro.mp3"))
                elif choice == "8":
                    await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/wiggle.mp3"))
                elif choice == "9":
                    await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/suck.mp3"))
                elif choice == "10":
                    await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/wrong.mp3"))
                elif choice == "69":
                    await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/userLeft.mp3"))
                elif choice == "420":
                    await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/PenisLR.mp3"))
                elif choice == "354":
                    await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/OffsetPenis.mp3"))
                elif choice == "543":
                    await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/my-anaconda-BITCH.mp3"))
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
            print("User joined")
            if member.bot:
                output = gTTS(random.choice(["a robot has joined", "oh my cock and balls its a mother fucking robot", "a bot joined the chat"]))
            else:   
                output = gTTS(member.display_name + random.choice([" joined the chat", " is a bitch", " joined the mother fucking chat", " is here. yaaaay", " is here. damn", " is here. what a shame", " joined. hopefully they will leave soon"]))
            output.save("C:/Users/Administrator/Desktop/Discord_Bot/" + member.guild.name.replace(" ", "") + "tts.mp3")
            await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/" + member.guild.name.replace(" ", "") + "tts.mp3"))
            
        elif not after.channel == vc.channel: #leaving channel
            print("User left")
            if member.bot:
                output = gTTS(random.choice(["a robot has left", "a bot left the chat"]))
            else:   
                output = gTTS(member.display_name + random.choice([" left the chat", " is a bitch and left", " left the mother fucking chat", " is no longer here. yaaaay", " left. damn", " is gone. what a shame", " left. hopefully they wont come back"]))
            output.save("C:/Users/Administrator/Desktop/Discord_Bot/" + member.guild.name.replace(" ", "") + "tts.mp3")
            await vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/" + member.guild.name.replace(" ", "") + "tts.mp3"))
    except:
        pass
    #try:
    print(str(await countMembers(vc.channel)) + " non-bot users in current channel")
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
        elif activeChannel == vc.channel:
            pass
        else:
            print("moving to " + str(activeChannel))
            await vc.move_to(activeChannel) 
    #except:
    #    pass
    
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
async def say(ctx, *putin):
    lang = putin[-1]
    text = " ".join(putin[:len(putin)-1])
    text_ = " ".join(putin)
    try:
        output = gTTS(text, lang=lang)
        print("saying " + text + " with langauge code " + lang + " as requested by " + ctx.author.display_name)
    except:
        output = gTTS(text_)
        print("saying " + text_ + " with langauge code en as requested by " + ctx.author.display_name)
    output.save("C:/Users/Administrator/Desktop/Discord_Bot/" + ctx.guild.name.replace(" ", "") + "tts.mp3")
    try:
        vc.play(discord.FFmpegPCMAudio("C:/Users/Administrator/Desktop/Discord_Bot/" + ctx.guild.name.replace(" ", "") + "tts.mp3"))
    except:
        await ctx.channel.send("Connect to a voice channel using $connect")

@bot.command()
async def spreadVC(ctx):
    for member in vc.channel.members:
        await member.move_to(random.choice(vc.guild.voice_channels))

@bot.command()
async def coaster(ctx, *users):
    members = []
    track = bot.get_channel(698336923139309609).category.voice_channels #hard coded coaster location
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
    for song in os.listdir("C:/Users/Administrator/Desktop/Discord_Bot/" + serverName + "/Music"):
        if name in song:
            return song

def playNextSong(error):
    global queue
    print(os.listdir("C:/Users/Administrator/Desktop/Discord_Bot/" + serverName + "/Music"))
    print(queue[0]["video_id"])
    for song in os.listdir("C:/Users/Administrator/Desktop/Discord_Bot/" + serverName + "/Music"):
        if queue[0]["video_id"] in song:
            os.remove("C:/Users/Administrator/Desktop/Discord_Bot/" + serverName + "/Music/" + song)
            
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
                    os.system("youtube-dl --extract-audio -o " + "C:/Users/Administrator/Desktop/Discord_Bot/" + serverName + "/Music/%(id)s.%(ext)s " + newSong["video_id"])
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
                os.system("youtube-dl --extract-audio -o " + "C:/Users/Administrator/Desktop/Discord_Bot/" + serverName + "/Music/%(id)s.%(ext)s " + newSong["video_id"])
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
    for item in os.listdir("C:/Users/Administrator/Desktop/Discord_Bot/" + serverName + "/Music"):
        os.remove("C:/Users/Administrator/Desktop/Discord_Bot/" + serverName + "/Music" + item)
        
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
