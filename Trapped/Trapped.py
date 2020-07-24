from pygame.locals import *
import pygame
import threading
import time
import random
import asyncio
pygame.init()

white = (255, 255, 255)
black = (0, 0, 0)
red = (255, 0, 0)
lightRed = (240, 165, 165)
green = (0, 255, 0)
width = 700
height = 400
screen = pygame.display.set_mode((width,height))
pygame.display.set_caption("g")
killList = []
possibleDirections = ["up", "down", "left", "right"]
font = pygame.font.SysFont("comicsansms", 35)
Level = 1
running = True

YSpawns = []
for x in range(height-50):
    if x % 20 == 0:
        YSpawns.append(x)

class Badboy():
    global killList
    
    spawnpoints = []
    for x in range(width):
        if x % 50 == 0:
            for z in range(random.randint(1,2)):
                spawnpoints.append(x)

    def checkWin():
        global running
        global spawnpoints
        if Badboy.spawnpoints == []:
            running = False
            lost = font.render("You Won", True, green)
            screen.blit(lost, (100,100))
            pygame.display.update()
        
    def spawn(self):
        if running:            
            enemy = pygame.draw.rect(screen, red,(xLocation, yLocation, 50, 50))
            killList.append(enemy)
        
    def attack(self):
        global Level
        global killList
        directionList = []
            
        for x in range(Level):
            directionList.append(random.choice(possibleDirections))
        Badboy.checkWin()
        if Level < 4 and random.randint(1,3) == 3:
            Level += 1
            
        xUP = xDOWN = xRIGHT = xLEFT = xLocation
        yUP = yDOWN = yRIGHT = yLEFT = yLocation
        bullet = None
        
        if "up" in directionList or "down" in directionList:
            xUP = random.randint(xLocation-15,xLocation+15)
        if "down" in directionList:
            xUP = random.randint(xLocation-15,xLocation+15)
        if "right" in directionList:
            yUP = random.randint(yLocation-15,yLocation+15)
        if "left" in directionList:
            yUP = random.randint(yLocation-15,yLocation+15)
            
        for rep in range(100):
            pygame.time.wait(25-Level)
            
            if "up" in directionList:
                pygame.draw.rect(screen, black,(xUP+25, yUP-60, 10, 50))
            if "down" in directionList:
                pygame.draw.rect(screen, black,(xDOWN+25, yDOWN+55, 10, 50))
            if "right" in directionList:
                pygame.draw.rect(screen, black,(xRIGHT+55, yRIGHT+25, 50, 10))
            if "left" in directionList:
                pygame.draw.rect(screen, black,(xLEFT-55, yLEFT+25, 50, 10))

            if "up" in directionList:  
                yUP -= 10
                bullet = pygame.draw.rect(screen, red,(xUP+25, yUP-55, 10, 50))
                killList.append(bullet)
            if "down" in directionList:
                yDOWN += 10
                bullet = pygame.draw.rect(screen, red,(xDOWN+25, yDOWN+50, 10, 50))
                killList.append(bullet)
            if "right" in directionList:                
                xRIGHT += 10
                bullet = pygame.draw.rect(screen, red,(xRIGHT+50, yRIGHT+25, 50, 10))
                killList.append(bullet)
            if "left" in directionList:                
                xLEFT -= 10
                bullet = pygame.draw.rect(screen, red,(xLEFT-50, yLEFT+25, 50, 10))
                killList.append(bullet)
            
            pygame.display.update()
        pygame.display.update() 
        
def finishSpawn():
    enemy = Badboy()
    enemy.spawn()
    if running:
        threading.Thread(target=enemy.attack).start()

rep = 0
def spawnBadboy():
    global xLocation
    global yLocation
    global rep
    rep += 1
    if rep >= (11-Level)*40 and running:
        rep = 0
        xLocation = random.choice(Badboy.spawnpoints)
        Badboy.spawnpoints.remove(xLocation)
        yLocation = random.choice(YSpawns)

        pygame.draw.rect(screen, lightRed,(xLocation, yLocation, 50, 50))
        pygame.display.update()
        threading.Timer(1, finishSpawn).start()


class Player():
    keys = [False, False, False, False]
    x = y = 200
    pygame.draw.rect(screen, white,(x, y, 10, 10))
    
    while running:
        pygame.time.wait(5)
        pygame.draw.rect(screen, black,(x, y, 10, 10))

        spawnBadboy()
        if not running:
            break
                
        for event in pygame.event.get():
            if event.type == QUIT:
                running = False
                
            if event.type == pygame.KEYDOWN:
                if chr(event.key) == "w":
                    keys[0] = True
                
                elif chr(event.key) == "s":
                    keys[1] = True
                    
                elif chr(event.key) == "a":
                    keys[2] = True

                elif chr(event.key) == "d":
                    keys[3] = True
                    
            if event.type == pygame.KEYUP:
                if chr(event.key) == "w":
                    keys[0] = False

                elif chr(event.key) == "s":
                    keys[1] = False
                    
                elif chr(event.key) == "a":
                    keys[2] = False

                elif chr(event.key) == "d":
                    keys[3] = False

        if keys[0]:
            y -= 1
            
        if keys[1]:
            y += 1
            
        if keys[2]:
            x -= 1
            
        if keys[3]:
            x += 1

        if x <= 0:
            x = 0
            
        elif x >= width-10:
            x = width-10

        if y <= 0:
            y = 0
            
        elif y >= height-10:
            y = height-10
            
        playerRect = pygame.draw.rect(screen, white,(x, y, 10, 10))
        if not playerRect.collidelist(killList) == -1:
            running = False
            lost = font.render("You Lost", True, green)
            screen.blit(lost, (100,100))
            pygame.display.update()
        pygame.display.update()
