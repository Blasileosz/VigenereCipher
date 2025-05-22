import re
import os

dictionary = open(os.path.dirname(os.path.abspath(__file__)) + "/words.txt").read().split("\n")
dictionary.pop() # Remove the last empty row

possibleKeyChars = "abcdefghijklmnopqrstuvwxyz "

def CharCode(char:str) -> int:
	return possibleKeyChars.index(char)


def CodeChar(code:int) -> str:
	return possibleKeyChars[code % 27]


def Encrypt(message:str, key:str) -> str:

	if len(key) < len(message):
		raise AttributeError("Encryption key cannot be shorter than message")
	
	if not ValidatePlaintext(message):
		raise AttributeError("Message must consist of valid words")
	
	if not ValidateKey(message):
		raise AttributeError("Key must consist of valid characters")

	ciphertext = ""

	for mChar, kChar in zip(message, key):
		mCharCode = CharCode(mChar)
		kCharCode = CharCode(kChar)
		ciphertext += CodeChar(mCharCode + kCharCode)

	return ciphertext


# The first argument accepts a suspected plaintext or an encryption key
# If it is supplied with a plaintext, it returns the corresponding key that encrypted the ciphertext
# If it is supplied with a key, it returns the plaintext that was encrypted with that key
def Decrypt(plaintextOrKey:str, ciphertext:str) -> str:
	
	if not ValidateKey(ciphertext):
		raise AttributeError("Ciphertext must consist of valid characters")
	
	# Works as long as the dictionary only contains lowercase words
	if not (ValidateKey(plaintextOrKey) or plaintextOrKey == ''):
		raise AttributeError("plaintextOrKey argument must consist of valid characters")
	
	keyOrPlaintext = ""

	for mChar, cChar in zip(plaintextOrKey, ciphertext):
		mCharindex = CharCode(mChar)
		cCharindex = CharCode(cChar)
		keyOrPlaintext += CodeChar(cCharindex - mCharindex)

	return keyOrPlaintext


def ValidateKey(key:str) -> bool:
	return bool(re.match("^[a-z\s]+$", key))


def ValidatePlaintext(plaintext:str) -> bool:
	words = plaintext.split(' ')
	return set(words).issubset(dictionary)


# Validates whether the key decrypts the ciphertexts to a valid sentence
def ValidateSuspectedKey(ciphertext1:str, ciphertext2:str, key:str) -> bool:
	plaintext1 = Decrypt(key, ciphertext1)
	plaintext2 = Decrypt(key, ciphertext2)

	return ValidatePlaintext(plaintext1 + ' ' + plaintext2) and len(key) >= min(len(ciphertext1), len(ciphertext2))


# Calculate all possible keys that are valid for the selected ciphertext
# partialKeyValidFor selects the already solved ciphertext
# 	- True means ciphertext1, False means ciphertext2
def BruteForceSlice(ciphertext1:str, ciphertext2:str, knownPartialKey:str, partialKeyValidFor:bool) -> list[str]:

	completeCiphertext = ciphertext1 if partialKeyValidFor else ciphertext2
	partialCiphertext = ciphertext2 if partialKeyValidFor else ciphertext1

	completePlaintext = Decrypt(knownPartialKey, completeCiphertext)
	partialPlaintext = Decrypt(knownPartialKey, partialCiphertext)
	partialWordStart = partialPlaintext.rfind(" ") + 1
	partialWord = partialPlaintext[partialWordStart:]

	#print(f"Complete ciphertext decrypted: '{completePlaintext}'")
	#print(f"Partial ciphertext decrypted:  '{partialPlaintext}'")
	#print(f"Partial plaintext: '{partialPlaintext}' start at {partialWordStart} (next partial word: '{partialWord}')")

	# Get all the valid endings for the partial word
	validEndings = [word for word in dictionary if word.startswith(partialWord)]
	if partialWord in validEndings:
		validEndings.remove(partialWord)
		validEndings.append(partialWord + " ") # To allow for overlap when sentences have whitespace at the same index

	# Try all valid endings
	# Possible optimization: If suprise doesn't work, suprised or suprisingly isn't going to either
	validKeys = []
	for suspectedMessage in validEndings:

		suspectedSentence = partialPlaintext[:partialWordStart] + suspectedMessage

		if len(suspectedSentence) > len(partialCiphertext):
			continue

		# Derive the first part of the key
		partialKey = Decrypt(suspectedSentence, partialCiphertext)

		# Decrypt the complete ciphertext with the partial key to check if the suspected message decrypts both ciphertexts to a valid sentence
		suspectedPlaintext = Decrypt(partialKey, completeCiphertext)

		# Plaintexts may not begin with a whitespace
		if suspectedPlaintext[0] == " ":
			continue

		plaintextParts = suspectedPlaintext.split(" ")

		# Check entire words if they exist (does verify the first words multiple times)
		# Should skip this if only one word is in the list (though it is skipped since [:-1] returns an empty array, and an empty set is subset of all sets)
		entireWordsExist = set(plaintextParts[:-1]).issubset(dictionary)
		if not entireWordsExist:
			continue

		# Check if the last part of the plaintext is a valid start of a word
		allMatches = len([word for word in dictionary if word.startswith(plaintextParts[-1])])
		if allMatches > 0:
			#print(f"For '{suspectedSentence}' found plaintext '{plaintext2}' with {len(allMatches)} matches using {partialKey:^30} as key")
			validKeys.append(partialKey)

	#print(f"{len(validKeys)} correct endings out of {len(validEndings)}")
	return validKeys


def SolveEncryptionKey(ciphertext1:str, ciphertext2:str) -> list[str]:
	keyStepper = 0
	keyBuffer = [""]
	keyMessageValidityBuffer = [False] # Stores which ciphertext the nth key is valid for

	# Step through each key and compute all of it's children
	while keyStepper < len(keyBuffer):
		nthKey = keyBuffer[keyStepper]
		nthKeyValidity = keyMessageValidityBuffer[keyStepper]

		for newkey in BruteForceSlice(ciphertext1, ciphertext2, nthKey, nthKeyValidity):
			# Avoid duplicates, as two separate branches may reach the same key
			if newkey not in keyBuffer:
				keyBuffer.append(newkey)
				keyMessageValidityBuffer.append(not nthKeyValidity) # Flip-flop ciphertexts

		keyStepper += 1

	# keyBuffer also stores intermediate keys, so each key needs to be validated
	validKeys = list(filter(lambda key: ValidateSuspectedKey(ciphertext1, ciphertext2, key), keyBuffer))
	return validKeys


# Get all the valid word permutations with a given length
# Initial whitespace is included in the length and also the output
def GetAllEndings(length:int, string:str = "") -> list[str]:

	searchLength = length - len(string)

	if searchLength == 0:
		return [string]
	
	if searchLength == 1:
		return []
	
	validWords = list(filter(lambda word: len(word) < searchLength, dictionary))

	output = []
	for word in validWords:
		sentence = string + ' ' + word
		completeSentences = GetAllEndings(length, sentence)

		output += completeSentences

	return output
