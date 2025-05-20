import sys
sys.path.append('..')

import ciphersuite

inCiphertext1 = input("First ciphertext:  ")
inCiphertext2 = input("Second ciphertext: ")

keys = ciphersuite.SolveEncryptionKey(inCiphertext1, inCiphertext2)

print("Number of valid keys:", len(keys))

for key in keys:
	print(f"#{key}# -> '{ciphersuite.Decrypt(key, inCiphertext1)}' --- '{ciphersuite.Decrypt(key, inCiphertext2)}'")
