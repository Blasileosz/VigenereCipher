dictionary = open("./words.txt").read().split("\n")
dictionary.pop() # Remove the last empty row

possibleKeyChars = "abcdefghijklmnopqrstuvwxyz "

def CharCode(char:str) -> int:
	return possibleKeyChars.index(char)

# TODO: validate message and key using regexp

message1 = "curiosity killed the cat"
message2 = "early bird catches the worm"

# TODO: Error when strigs have space at the same place
message1 = "application fund borrow suppose"
message2 = "wake war reinforce head blood"

encryptionKey = "abcdefghijklmnopqrstuvwxyz "

# Returns the cipher
def Encrypt(message:str, key:str) -> str:
	outCipher = ""

	for mChar, kChar in zip(message, key):
		mCharindex = possibleKeyChars.index(mChar)
		kCharindex = possibleKeyChars.index(kChar)
		outCipher += possibleKeyChars[(mCharindex + kCharindex) % 27]

	return outCipher

# Returns the key
# The first argument accepts a suspected message or an encryption key
def Decrypt(suspectedMessageOrKey:str, cipher:str) -> str:
	outKey = ""

	for mChar, cChar in zip(suspectedMessageOrKey, cipher):
		mCharindex = possibleKeyChars.index(mChar)
		cCharindex = possibleKeyChars.index(cChar)
		outKey += possibleKeyChars[(cCharindex - mCharindex) % 27]

	return outKey


def BruteForceFirstSlice(ciphertext1:str, ciphertext2:str):

	# Try all words
	# Possible optimization: If suprise doesn't work, suprised or suprisingly isn't going to either
	validPartials = []
	for suspectedMessage in dictionary:

		# Derive the first part of the key
		partialKey = Decrypt(suspectedMessage, ciphertext1)

		# Decrypt message2 with the partial key and check if any words exist with that begining
		# Using the partial key, decrypt the first part of the other plaintext
		plaintext2 = Decrypt(partialKey, ciphertext2)

		# Plaintexts may not begin with a whitespace (may casue problems later)
		if plaintext2[0] == " ":
			continue

		
		plaintextParts = plaintext2.split(" ")

		# Check entire words if they exist (does verify the first words multiple times)
		entireWordsExist = True
		for word in plaintextParts[:-1]:
			if word not in dictionary:
				entireWordsExist = False

		if not entireWordsExist:
			continue

		# Check if the last part of the plaintext is a valid start of a word
		lastPart = plaintextParts[-1]
		allMatches = list(word for word in dictionary if word.startswith(lastPart))
		if len(allMatches) > 0:
			print(f"Found plaintext {lastPart:^10} with {len(allMatches)} matches using {partialKey:^20} as key")
			validPartials.append(partialKey)

	return sorted(validPartials, key=lambda partial: -len(partial))


# partialKeyValidFor is True if it decrypts the first ciphertext, otherwise False
def BruteForceSlice(ciphertext1:str, ciphertext2:str, knownPartialKey:str, partialKeyValidFor:bool):

	print()

	completeCiphertext = ciphertext1 if partialKeyValidFor else ciphertext2
	partialCiphertext = ciphertext2 if partialKeyValidFor else ciphertext1

	completePlaintext = Decrypt(knownPartialKey, completeCiphertext)
	partialPlaintext = Decrypt(knownPartialKey, partialCiphertext)
	partialWordStart = partialPlaintext.rfind(" ") + 1

	print(f"Complete ciphertext decrypted: '{completePlaintext}'")
	print(f"Partial ciphertext decrypted:  '{partialPlaintext}'")
	print(f"Partial plaintext: '{partialPlaintext}' start at {partialWordStart} (next partial word: '{partialPlaintext[partialWordStart:]}')")

	validEndings = list(word for word in dictionary if word.startswith(partialPlaintext[partialWordStart:]))
	if partialPlaintext[partialWordStart:] in validEndings:
		validEndings.remove(partialPlaintext[partialWordStart:])
	print("Valid endings for word:", len(validEndings))

	# Try all words
	# Possible optimization: If suprise doesn't work, suprised or suprisingly isn't going to either
	validPartials = []
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
		# Should skip this if only one word is in the list (though it is skipped since [-1] return empty array)
		entireWordsExist = True
		for word in plaintextParts[:-1]:
			if word not in dictionary:
				entireWordsExist = False

		if not entireWordsExist:
			continue

		# Check if the last part of the plaintext is a valid start of a word
		lastPart = plaintextParts[-1]
		allMatches = list(word for word in dictionary if word.startswith(lastPart))
		if len(allMatches) > 0:
			#print(f"For '{partialPlaintext[:partialWordStart] + suspectedMessage}' found plaintext '{plaintext2}' with {len(allMatches)} matches using {partialKey:^30} as key")
			validPartials.append(partialKey)

	# if len(validPartials) == 0:
	# 	print("Bad edge")
	# 	return knownPartialKey
	# else:
	# 	for partk in validPartials:
	# 		return BruteForceSlice(partialCiphertext, completeCiphertext, partk, True)
	return sorted(validPartials, key=lambda partial: -len(partial))

ciphertext1 = Encrypt(message1, encryptionKey)
ciphertext2 = Encrypt(message2, encryptionKey)
print("Given ciphertexts:", ciphertext1, ciphertext2)

possibleKeys = list(map(lambda item: (item, True), BruteForceFirstSlice(ciphertext1, ciphertext2)))

for key, mode in possibleKeys:
	for newkey in BruteForceSlice(ciphertext1, ciphertext2, key, mode):
		possibleKeys.append((newkey, not mode))

# TODO: some keys are not valid, valid keys are listed twice
print("Valid keys:")
for key, mode in possibleKeys:
	if len(key) == max(len(ciphertext1), len(ciphertext2)):
		print(f"#{key}# -> '{Decrypt(key, ciphertext1)}' --- '{Decrypt(key, ciphertext2)}'")

