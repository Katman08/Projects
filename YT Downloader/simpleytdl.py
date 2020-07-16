from youtube_api import YouTubeDataAPI
import random
import os

yt = YouTubeDataAPI(random.choice(["AIzaSyDB-9pBXBWuvvaCSUUuXLOALv9EapjuAXA","AIzaSyC8HN3GCu4-lXolqfHCBlWVS9xRkSikvfI","AIzaSyAqvs-adIF_2xFWr1Gv51K1cHrliStoB14","AIzaSyAE4fTCHuX4wcTpMb8HLAHUexgu10-M5k8","AIzaSyAPcvoCSXaEAEIuJGDNfK8z0Qv3iz3jiH8"]))

def restart():
    searchResults = yt.search(q=input("Song: "),max_results=1, search_type="video")
    if searchResults == []:
        print("No song found")
        restart()

    else:
        song = searchResults[0]

    confirm = input(f"Confirm download of {song['video_title']} (y/n)").lower()
    while not confirm in ["y", "n"]:
        print("error")
        confirm = input(f"Confirm download of {song['video_title']} (y/n)").lower()

    if confirm == "n":
        restart()
    
    os.system(f"youtube-dl --extract-audio {song['video_id']}")
    restart()
    
restart()
