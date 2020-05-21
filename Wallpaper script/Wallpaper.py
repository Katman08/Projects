from PIL import Image
import requests
import random
import time
import praw
import os

path = ""

print("Connecting to reddit API...")
reddit = praw.Reddit(client_id="",
                     client_secret="",
                     user_agent="",
                     username="",
                     password="")

print("Retrieving image...")
submission = random.choice(list(reddit.subreddit(random.choice(["wallpaper", "wallpapers"])).hot(limit=100)))
binaryContent = requests.get(submission.url).content

print("Creating empty file...")
temp = Image.open(path + "empty.png").copy()
temp.save(path + "Background.png")

print("Overwriting binary content...")
background = open(path + "Background.png", "wb")
background.write(binaryContent)
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
os.system(path + "refresh.bat")

print("Script completed successfully")
