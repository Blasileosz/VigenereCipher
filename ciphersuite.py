import re
import os

dictionary = open(os.path.dirname(os.path.abspath(__file__)) + "/words.txt").read().split("\n")
dictionary.pop() # Remove the last empty row

possibleKeyChars = "abcdefghijklmnopqrstuvwxyz "

def CharCode(char:str) -> int:
	return possibleKeyChars.index(char)

def CodeChar(code:int) -> str:
	return possibleKeyChars[code % 27]

# Returns the cipher
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
# Returns the key or the plaintext based on which one is supplied in the first argument
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


# partialKeyValidFor is True if it decrypts the first ciphertext, otherwise the second
def BruteForceSlice(ciphertext1:str, ciphertext2:str, knownPartialKey:str, partialKeyValidFor:bool) -> list[str]:

	#print()

	completeCiphertext = ciphertext1 if partialKeyValidFor else ciphertext2
	partialCiphertext = ciphertext2 if partialKeyValidFor else ciphertext1

	completePlaintext = Decrypt(knownPartialKey, completeCiphertext)
	partialPlaintext = Decrypt(knownPartialKey, partialCiphertext)
	partialWordStart = partialPlaintext.rfind(" ") + 1

	#print(f"Complete ciphertext decrypted: '{completePlaintext}'")
	#print(f"Partial ciphertext decrypted:  '{partialPlaintext}'")
	#print(f"Partial plaintext: '{partialPlaintext}' start at {partialWordStart} (next partial word: '{partialPlaintext[partialWordStart:]}')")

	validEndings = [word for word in dictionary if word.startswith(partialPlaintext[partialWordStart:])] # TODO: Wouldn't need to be computed again, because allMatches already had done it
	if partialPlaintext[partialWordStart:] in validEndings:
		validEndings.remove(partialPlaintext[partialWordStart:])
		validEndings.append(partialPlaintext[partialWordStart:] + " ")
	#print("Valid endings for word:", len(validEndings))

	# Try all words
	# Possible optimization: If suprise doesn't work, suprised or suprisingly isn't going to either
	validKeys = []
	for suspectedMessage in validEndings:

		if len(partialPlaintext[:partialWordStart] + suspectedMessage) > len(partialCiphertext):
			continue

		# Derive the first part of the key
		partialKey = Decrypt(partialPlaintext[:partialWordStart] + suspectedMessage, partialCiphertext)

		#partialKey = knownPartialKey + partialKey

		# Decrypt message2 with the partial key and check if any words exist with that begining
		# Using the partial key, decrypt the first part of the other plaintext
		plaintext2 = Decrypt(partialKey, completeCiphertext)

		# Plaintexts may not begin with a whitespace (may casue problems later)
		if plaintext2[0] == " ":
			continue

		
		plaintextParts = plaintext2.split(" ")

		# Check entire words if they exist (does verify the first words multiple times)
		# Should skip this if only one word is in the list (though it is skipped since [:-1] returns an empty array, and an empty set is subset of all sets)
		entireWordsExist = set(plaintextParts[:-1]).issubset(dictionary)
		if not entireWordsExist:
			continue

		# Check if the last part of the plaintext is a valid start of a word
		lastPart = plaintextParts[-1]
		allMatches = len([word for word in dictionary if word.startswith(lastPart)])
		if allMatches > 0:
			#print(f"For '{partialPlaintext[:partialWordStart] + suspectedMessage}' found plaintext '{plaintext2}' with {len(allMatches)} matches using {partialKey:^30} as key")
			validKeys.append(partialKey)

	#print("Correct endings:", len(validKeys))
	return validKeys


def SolveEncryptionKey(ciphertext1:str, ciphertext2:str) -> list[str]:
	keyStepper = 0
	keyBuffer = [""]
	keyMessageValidityBuffer = [False]

	while keyStepper < len(keyBuffer):
		nthKey = keyBuffer[keyStepper]
		nthKeyValidity = keyMessageValidityBuffer[keyStepper]

		for newkey in BruteForceSlice(ciphertext1, ciphertext2, nthKey, nthKeyValidity):
			if newkey not in keyBuffer: # Two separate branches may reach the same key
				keyBuffer.append(newkey)
				keyMessageValidityBuffer.append(not nthKeyValidity)

		keyStepper += 1

	# TODO: This filter could be removed, if BruteForceSlice was recursive
	validKeys = list(filter(lambda key: ValidateSuspectedKey(ciphertext1, ciphertext2, key), keyBuffer))

	# TODO: handle when the entire key could not be retrieved

	return validKeys


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
