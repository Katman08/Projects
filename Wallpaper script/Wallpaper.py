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

submission = random.choice(list(reddit.subreddit(random.choice(["wallpaper", "wallpapers"])).hot(limit=100)))
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
    overlaySize = "250"

elif background.width <= 1500:
    overlaySize = "500"

elif background.width <= 3000:
    overlaySize = "1000"

else:
    overlaySize = "2000"

print("Pasting overlay...")
overlay = Image.open(path + "overlay" + overlaySize + ".png")
background = Image.open(path + "Background.png")

output = background.copy()
output.paste(overlay, (background.width-overlay.width, background.height-overlay.height), overlay)

print("Archiving wallpaper...")
output.save(path + "Archive/" + submission.title[:15].replace(" ", "") + ".png")

print("Saving wallpaper...")
output.save(path + "Wallpaper.png")

print("Attempting to force wallpaper change...")
print("Terminal may be closed once wallpaper changes")
for x in range(200):
    os.system("powershell.exe RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters")
    
print("Script completed successfully")
