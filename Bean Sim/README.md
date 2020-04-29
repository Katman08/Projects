This is a simple 2d platformer created in unity.

I custom coded c# scripts for the following game mechanics:

1. Left/Right movement
--acceleration and velocity cap accounted for
--velocity cap customizable without changing code
--movement speed customizable without changing code

2. Jumping
--Jjp height customizable without changing code
--current left/right movement accounted for
--must be touching line collider with tag "floor"

3. Enemies
--speed is customizable without changing code
--kill player on collision

4. Death and death counter
--on death. player's x/y is reverted to starting position, velocity is set to 0, and death counter -= 1
--max deaths is customizable without changing code
--player is sent to menu when death counter = 0

5. Coins and score counter
--on collison, coin is collected and score counter += 1
--when all coins are collected, level is finished

6.Menu
--contains two distinct levels and new levels and easily be added
