from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.app import App
from youtube_api import YouTubeDataAPI
import random
import os

yt = YouTubeDataAPI(random.choice(["AIzaSyDB-9pBXBWuvvaCSUUuXLOALv9EapjuAXA","AIzaSyC8HN3GCu4-lXolqfHCBlWVS9xRkSikvfI","AIzaSyAqvs-adIF_2xFWr1Gv51K1cHrliStoB14","AIzaSyAE4fTCHuX4wcTpMb8HLAHUexgu10-M5k8","AIzaSyAPcvoCSXaEAEIuJGDNfK8z0Qv3iz3jiH8"]))

class SongDownloader(BoxLayout):
    errorContent = Button(text="No song found")    
    noSongFound = Popup(title="uh oh i did a fucky wucky",content=errorContent, auto_dismiss=False)
    errorContent.bind(on_press=noSongFound.dismiss)

    successContent = Button(text="download completed")
    success = Popup(content=successContent, auto_dismiss=False)
    successContent.bind(on_press=success.dismiss)
    
    def audioDownload(self):
        searchResults = yt.search(q=self.songInput.text,max_results=1, search_type="video")
        if len(searchResults) == 0 or self.songInput.text == "":
            self.noSongFound.open()
        else:
            song = searchResults[0]
            self.success.open()
            os.system(f"youtube-dl --extract-audio {song['video_id']}")

            searchResults == []

    def videoDownload(self):
        searchResults = yt.search(q=self.songInput.text,max_results=1, search_type="video")
        if len(searchResults) == 0 or self.songInput.text == "":
            self.noSongFound.open()
        else:
            song = searchResults[0]
            self.success.open()
            os.system(f"youtube-dl {song['video_id']}")

            searchResults == []
        

class ytdl(App):
    def build(self):
        return SongDownloader()

if __name__ == '__main__':
    ytdl().run()
