from ..ciphersuite import dictionary, possibleKeyChars, Encrypt

def GetWordLengthFrequency():
	freq = {}

	for word in dictionary:
		wordLen = len(word)
		freq[wordLen] = freq.get(wordLen, 0) + 1

	print(sorted(freq.items(), key=lambda item: item[0]))

def GetEncryptionSpread():
	freq = {}
	for chari in possibleKeyChars:
		for charj in possibleKeyChars:
			cipherChar = Encrypt(chari, charj)
			freq[cipherChar] = freq.get(cipherChar, 0) + 1
	
	print(freq)

print("World length frequency:")
GetWordLengthFrequency()

print("\nEncryption spread:")
GetEncryptionSpread()
