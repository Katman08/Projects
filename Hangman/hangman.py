import string

possibleWords = open("words_alpha.txt", encoding="utf8").readlines()
newPossibleWords = []
guessedLetters = []
wrongGuesses = 0

print(f"{str(len(possibleWords))} possible words")

def mostCommonChar(list):
    results = dict.fromkeys(string.ascii_lowercase, 0)
    for word in list:
        for char in string.ascii_lowercase:
            if char in word and not char in guessedLetters:
                results[char] += 1

    return max(results, key=results.get)
    
def main(possibleWords):
    global wrongGuesses
    newPossibleWords = []
    
    if len(possibleWords) == 1:
        print(f"Answer: {possibleWords[0]}")
        print(f"Wrong Guesses: {wrongGuesses}")
        input()

    elif len(possibleWords) == 0:
        print("No word found")
        return
    
    print(f"{str(len(possibleWords))} possible words")
    
    guess = mostCommonChar(possibleWords)
    guessedLetters.append(guess)
    print(f"Guess: {guess}")

    correct = input("Correct? (y/n) ").lower()
    while not correct in ["y","n"]:
        correct = input("Correct? (y/n) ").lower()

    if correct == "n":
        wrongGuesses += 1
        for word in possibleWords:
            if not guess in word:
                newPossibleWords.append(word)
        main(newPossibleWords)
                
    elif correct == "y":
        letterNum = int(input(f"Number of {guess}\'s: "))
        charLocations = []
        for x in range(letterNum):          
            charLocations.append(int(input(f"Letter location #{x+1}: "))-1)

        for word in possibleWords:
            fitsPattern = True
            for loc in charLocations:
                if not word[loc] == guess:
                    fitsPattern = False
                    
            if fitsPattern:
                newPossibleWords.append(word)
                    
        main(newPossibleWords)

length = int(input("Word Length: "))

for word in possibleWords:
    if len(word.rstrip()) == length:
        newPossibleWords.append(word.rstrip())    

main(newPossibleWords)
        
