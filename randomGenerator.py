import random

dictionary = open("./words.txt").read().split("\n")
dictionary.pop() # Remove the last empty row

possibleKeyChars = "abcdefghijklmnopqrstuvwxyz "

def RandomKey(length):
	return ''.join(random.choices(possibleKeyChars, k=length))

def RandomMessage(words):
	return ' '.join(random.choices(dictionary, k=words))


print(f"Random key: '{RandomKey(27)}'")
print("First random message: ", RandomMessage(5))
print("Second random message: ", RandomMessage(5))
