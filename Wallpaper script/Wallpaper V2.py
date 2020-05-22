from PIL import Image
import requests
import random
import time
import praw
import os

path = "C:/Users/Alex/OneDrive/Pictures/Wallpaper/"

print("Connecting to reddit API...")
reddit = praw.Reddit(client_id="jJAuiW1OnsnLZQ",
                     client_secret="qqj4vjK3OKRA3o6_Tjzz2bR_iXA",
                     user_agent="bgbyghuiolagayuhibnolfabnhiugdf",
                     username="RedditScrapper12",
                     password="Password@69")

print("Creating empty file...")
temp = Image.open(path + "empty.png").copy()
temp.save(path + "Background.png")

background = open(path + "Background.png", "wb")

print("Retrieving submission...")

submission = random.choice(list(reddit.subreddit(random.choice(["wallpaper", "wallpapers", "offensive_wallpapers", "EarthPorn", "nocontext_wallpapers", "CityPorn"])).hot(limit=100)))
while not submission.domain == "i.redd.it" and not submission.domain == "i.imgur.com" or submission.is_video:
    print("Submission not valid")
    print("Retrieving new submission...")
    submission = random.choice(list(reddit.subreddit(random.choice(["wallpaper", "wallpapers"])).hot(limit=100)))

print("Extracting binary")
ImageContent = requests.get(submission.url).content

print("Overwriting binary content of empty file...")
background.write(ImageContent)

background.close()

background = Image.open(path + "Background.png")

print("Determining overlay size...")

if background.width <= 1000:
    BirdSize = "250"
    pogAmount = random.randint(0,10)
    
elif background.width <= 1500:
    BirdSize = "500"
    pogAmount = random.randint(0,6)
    
elif background.width <= 3000:
    BirdSize = "1000"
    pogAmount = random.randint(0,3)

else:
    BirdSize = "2000"
    pogAmount = random.randint(0,1)
    
print("Preparing templates...")
birdOverlay = Image.open(path + "bird" + BirdSize + ".png")
background = Image.open(path + "Background.png")


output = background.copy()

if random.randint(1,3) < 3:
    print("Pasting bird overlay...")
    output.paste(birdOverlay, (background.width-birdOverlay.width, background.height-birdOverlay.height), birdOverlay)

for x in range(pogAmount):
    print("Pasting pog number " + str(x+1) + "...")
    pog = Image.open(path + "Pog" + str(random.randint(1,4)*100) + ".png")
    output.paste(pog, (random.randint(0,background.width), random.randint(0,background.height)), pog)
        
print("Archiving wallpaper...")
output.save(path + "Archive/" + submission.title[:15].replace(" ", "") + str(random.randint(1, 100000)) + ".png")

print("Saving wallpaper...")
output.save(path + "Wallpaper.png")

print("Attempting to force wallpaper change...")
print("Terminal may be closed once wallpaper changes")
for x in range(300):
    os.system("powershell.exe RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters")
    
print("Script completed successfully")
