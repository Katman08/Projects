import string


def step1(putin):
    putout = ''
    for symbol in putin:
        num = ord(symbol)
        num += 1
        putout += chr(num)

    return putout


def step2(putin):
    putin = list(putin)
    putin.reverse()
    putout = " ".join(putin)
    return putout


def step3(putin):
    putout = []
    for x in range(1, 10):
        putout.append(" " + str(x) + " " + string.ascii_letters[x])
    for x in putin:
        putout.append(x)
    for x in range(10, 20):
        putout.append(" " + str(x) + " " + string.ascii_letters[x])
    putout = "".join(putout)
    return putout


print(step3(step2(step1(flag))))
