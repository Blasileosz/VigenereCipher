import random
import ciphersuite

def RandomKey(length):
	return ''.join(random.choices(ciphersuite.possibleKeyChars, k=length))

def RandomMessage(words):
	return ' '.join(random.choices(ciphersuite.dictionary, k=words))

if __name__ == "__main__":
	print(f"Random key: '{RandomKey(27)}'")
	print("First random message:  ", RandomMessage(5))
	print("Second random message: ", RandomMessage(5))
