import re

dictionary = open("./words.txt").read().split("\n")
dictionary.pop() # Remove the last empty row

possibleKeyChars = "abcdefghijklmnopqrstuvwxyz "

def CharCode(char:str) -> int:
	return possibleKeyChars.index(char)

def CodeChar(code:int) -> str:
	return possibleKeyChars[code % 27]

message1 = "curiosity killed the cat" # 24
message2 = "early bird catches the worm" # 27

# When strigs have space at the same index
message1 = "application fund borrow suppose" # 31
message2 = "wake war reinforce head blood" # 29

#message1 = "pole his surround treaty cause" # 30
#message2 = "flower wet oil scared vast" # 26

encryptionKey = "abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz "

# Returns the cipher
def Encrypt(message:str, key:str) -> str:
	ciphertext = ""

	for mChar, kChar in zip(message, key):
		mCharCode = CharCode(mChar)
		kCharCode = CharCode(kChar)
		ciphertext += CodeChar(mCharCode + kCharCode)

	return ciphertext

# The first argument accepts a suspected plaintext or an encryption key
# Returns the key or the plaintext based on which one is supplied in the first argument
def Decrypt(plaintextOrKey:str, ciphertext:str) -> str:
	keyOrPlaintext = ""

	for mChar, cChar in zip(plaintextOrKey, ciphertext):
		mCharindex = CharCode(mChar)
		cCharindex = CharCode(cChar)
		keyOrPlaintext += CodeChar(cCharindex - mCharindex)

	return keyOrPlaintext

def ValidateKey(key:str) -> bool:
	return re.match("^[a-z\s]+$", key)

def ValidatePlaintext(plaintext:str) -> bool:
	words = plaintext.split(' ')
	return set(words).issubset(dictionary)

# Validates whether the key decrypts the ciphertexts to a valid sentence
def ValidateKey(ciphertext1:str, ciphertext2:str, key:str) -> bool:
	plaintext1 = Decrypt(key, ciphertext1)
	plaintext2 = Decrypt(key, ciphertext2)

	return ValidatePlaintext(plaintext1 + ' ' + plaintext2)


# partialKeyValidFor is True if it decrypts the first ciphertext, otherwise the second
def BruteForceSlice(ciphertext1:str, ciphertext2:str, knownPartialKey:str, partialKeyValidFor:bool) -> list[str]:

	print()

	completeCiphertext = ciphertext1 if partialKeyValidFor else ciphertext2
	partialCiphertext = ciphertext2 if partialKeyValidFor else ciphertext1

	completePlaintext = Decrypt(knownPartialKey, completeCiphertext)
	partialPlaintext = Decrypt(knownPartialKey, partialCiphertext)
	partialWordStart = partialPlaintext.rfind(" ") + 1

	print(f"Complete ciphertext decrypted: '{completePlaintext}'")
	print(f"Partial ciphertext decrypted:  '{partialPlaintext}'")
	print(f"Partial plaintext: '{partialPlaintext}' start at {partialWordStart} (next partial word: '{partialPlaintext[partialWordStart:]}')")

	validEndings = list(word for word in dictionary if word.startswith(partialPlaintext[partialWordStart:])) # TODO: Needs checked here and at the end of the function?
	if partialPlaintext[partialWordStart:] in validEndings:
		validEndings.remove(partialPlaintext[partialWordStart:])
		validEndings.append(partialPlaintext[partialWordStart:] + " ")
	print("Valid endings for word:", len(validEndings))

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

	print("Correct endings:", len(validKeys))
	return validKeys

ciphertext1 = Encrypt(message1, encryptionKey)
ciphertext2 = Encrypt(message2, encryptionKey)
print("Given ciphertexts:", ciphertext1, ciphertext2)

keyStepper = 0
possibleKeys = [("", False)]

while keyStepper < len(possibleKeys):
	nthKey = possibleKeys[keyStepper]

	for newkey in BruteForceSlice(ciphertext1, ciphertext2, nthKey[0], nthKey[1]):
		if (newkey, False) not in possibleKeys and (newkey, True) not in possibleKeys: # Two separate branches may reach the same key
			possibleKeys.append((newkey, not nthKey[1]))

	keyStepper += 1

# (3) abcdefghijklmnopqrstuvwcsht -> (3) abcdefghijklmnopqrstuvwc -> (3) abcdefghijklmnopqrstuv -> (3) abcdefghijklmnopqrst -> (3) abcdefghijklmnopqr

# abcdefghijklmnop
# abcdefghijklmn
# abcdefghijklmnopq

print("All keys:", len(possibleKeys))

print("Valid keys:")
for key, _ in possibleKeys:
	if len(key) == max(len(ciphertext1), len(ciphertext2)) and ValidateKey(ciphertext1, ciphertext2, key):
		print(f"#{key}# -> '{Decrypt(key, ciphertext1)}' --- '{Decrypt(key, ciphertext2)}'")
