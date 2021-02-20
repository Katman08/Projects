import os
import sys
import configparser
import winshell
import pathlib
from gtts import gTTS
from datetime import datetime
from playsound import playsound

if not os.path.isfile("config.ini"):
    config = configparser.ConfigParser()
    config["settings"] = {"active": False}
    config["classes"] = {
    "P1": "[Class Name]-/[Class Link]",
    "P2": "[Class Name]-/[Class Link]",
    "P3": "[Class Name]-/[Class Link]",
    "P5": "[Class Name]-/[Class Link]",
    "P6": "[Class Name]-/[Class Link]",
    "P7": "[Class Name]-/[Class Link]",
    "P8": "[Class Name]-/[Class Link]",
}
    
    config.write(open("config.ini", "w"))
    input("edit config file before running")
    exit()
    
if not os.path.isfile("SS.mp3"):
    gTTS("Enter SS Period").save("SS.mp3")
    
if not os.path.isfile("leave.mp3"):
    gTTS("Leaving class in 15. 14. 13. 12. 11. 10. 9. 8. 7. 6. 5. 4. 3. 2. 1.").save("leave.mp3")

config = configparser.ConfigParser()
config.read("config.ini")

if len(sys.argv) == 1:
    while True:
        now = datetime.now()
        endTimes = []
        results = []
        rawTimes = [(9,30), (11,5), (13,20), (14,55)]
        if now.weekday() == 1 or 4:
            rawTimes.append((10,20))
            
        for time in rawTimes:
            endTimes.append(now.replace(hour=time[0], minute=time[1]))
            
        for time in endTimes:
            results.append(time-now)

        while min(results).days < 0:
            results.remove(min(results))

        if int(min(results).seconds/60) >= 60:
            input(f"Current class ends in {int(min(results).seconds/60/60)} hour and {int(min(results).seconds/60%60)} minute(s)")
        else:
            input(f"Current class ends in {int(min(results).seconds/60)} minute(s)")

elif sys.argv[1] == "activate":
    config["settings"] = {"active": True}
    config.write(open("config.ini", "w"))
    config.write(open("C:\Windows\System32\config.ini", "w"))
    
    
elif sys.argv[1] == "deactivate":
    config["settings"] = {"active": False}
    config.write(open("config.ini", "w"))
    config.write(open("C:\Windows\System32\config.ini", "w"))

elif sys.argv[1] == "shortcuts":
    #i admire you for trying to fix this hot mess
    #if you are not here to fix this hot mess, fuck you
    for period in config["classes"]:
        print(period)
    #link = winshell.shortcut(f"{period} - {config['classes'][period].split('-/')[0]}.lnk")
    link = winshell.shortcut(f"{pathlib.Path(__file__).parent}\\fuck.lnk")
    link.path = sys.executable
    file = "E:\\school-hax\\classManager.py"
    link.arguments = f"{file} P1"
    link.working_directory = str(pathlib.Path(__file__).parent)
    link.write()

elif config["settings"]["active"] == "False":
    exit()

elif sys.argv[1] == "leave":
    playsound("leave.mp3")
    os.system("taskkill /f /im chrome.exe")

elif sys.argv[1] == "SS":
    playsound("SS.mp3")
    SSperiod = f"P{input('Enter SS Period: ')}"
    os.system(f"start {config['classes'][SSperiod].split('-/')[1]}")
    gTTS("Starting " + SSperiod + " at " + datetime.now().strftime('%I:%M')).save("tts.mp3")
    playsound("tts.mp3")
    
else:
    os.system(f"start {config['classes'][sys.argv[1]].split('-/')[1]}")
    gTTS("Starting " + config['classes'][sys.argv[1]].split('-/')[0] + " at " + datetime.now().strftime('%I:%M')).save("tts.mp3")
    playsound("tts.mp3")
