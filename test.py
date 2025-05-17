dictionary = open("./words.txt").read().split("\n")
dictionary.pop() # Remove the last empty row

shortestWord = 10000
longestWord = 0

wordLenCount = {}

for word in dictionary:
	wordLen = len(word)
	wordLenCount[wordLen] = wordLenCount.get(wordLen, 0) + 1

	if wordLen == 1:
		print(word)

print(sorted(wordLenCount.items(), key=lambda item: item[0]))


#letterFrequency = {}
