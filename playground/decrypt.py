import sys
sys.path.append('..')

import ciphersuite

inCiphertext = input("Ciphertext to decrypt: ")
print("Plaintext or Key:")
print("- If the plaintext is supplied, the key will be decrypted")
print("- If the key is supplied, the plaintext will be decrypted")
inKey = input("Plaintext or Key: ")

print("Encrypted sentence: ", ciphersuite.Decrypt(inKey, inCiphertext))
