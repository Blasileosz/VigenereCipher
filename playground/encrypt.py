import sys
sys.path.append('..')

import ciphersuite

inMessage = input("Sentence to encrypt: ")
inKey = input("Key: ")

print("Encrypted sentence: ", ciphersuite.Encrypt(inMessage, inKey))
