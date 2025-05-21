import unittest
import random

import ciphersuite
import random_generator

class TestCipher(unittest.TestCase):

	testKey:str

	def setUp(self):
		self.testKey = random_generator.RandomKey(50) # Increase as needed

	def test_Encrypt_ShorterKey(self):
		with self.assertRaises(AttributeError, msg="Encrypt function allows shorter keys"):
			ciphersuite.Encrypt("a longer message", "short key")

	def test_Encrypt_InvalidMessage(self):
		with self.assertRaises(AttributeError, msg="Encrypt function allows invalid messages"):
			ciphersuite.Encrypt("Invalid messáge", "valid key here")
		
	def test_Encrypt_InvalidKey(self):
		with self.assertRaises(AttributeError, msg="Encrypt function allows invalid keys"):
			ciphersuite.Encrypt("valid message", "Invalid kéj hére")

	def test_Decrypt_InvalidMessage(self):
		with self.assertRaises(AttributeError, msg="Decrypt function allows invalid messages"):
			ciphersuite.Encrypt("Invalid messáge", "valid key here")
		
	def test_Decrypt_InvalidKey(self):
		with self.assertRaises(AttributeError, msg="Decrypt function allows invalid keys"):
			ciphersuite.Encrypt("valid message", "Invalid kéj háre")

	def test_BaseCase(self):
		ciphertext1 = ciphersuite.Encrypt("curiosity killed the cat", self.testKey) # Len=24
		ciphertext2 = ciphersuite.Encrypt("early bird catches the worm", self.testKey) # Len=27
		
		validKeys = ciphersuite.SolveEncryptionKey(ciphertext1, ciphertext2)

		self.assertIn(self.testKey[:27], validKeys, "None of the found keys decrypt to the original messages")

	# When messages have space at the same index
	def test_OverlappingWhitespaces(self):
		ciphertext1 = ciphersuite.Encrypt("wake war reinforce head blood", self.testKey) # Len=29
		ciphertext2 = ciphersuite.Encrypt("application fund borrow suppose", self.testKey) # Len=31
		
		validKeys = ciphersuite.SolveEncryptionKey(ciphertext1, ciphertext2)

		self.assertIn(self.testKey[:31], validKeys, "None of the found keys decrypt to the original messages")

	def test_EntireWordLonger(self):
		ciphertext1 = ciphersuite.Encrypt("civil commitment native pray mess", self.testKey) # Len=33
		ciphertext2 = ciphersuite.Encrypt("criticize specifically limited agency principal", self.testKey) # Len=47
		
		validKeys = ciphersuite.SolveEncryptionKey(ciphertext1, ciphertext2)

		self.assertIn(self.testKey[:47], validKeys, "None of the found keys decrypt to the original messages")

	def test_RecursiveVSOld(self):
		ciphertext1 = ciphersuite.Encrypt("curiosity killed the cat", self.testKey)
		ciphertext2 = ciphersuite.Encrypt("early bird catches the worm", self.testKey)
		
		validKeys1 = ciphersuite.SolveEncryptionKey(ciphertext1, ciphertext2)
		validKeys2 = ciphersuite.SolveEncryptionKeyRecursive(ciphertext1, ciphertext2)

		self.assertEqual(set(validKeys1), set(validKeys2), "The two functions output does not match")

	def test_EndingGenerator(self):
		stringLen = random.randint(5, 9) # Takes a while to compute
		endings = ciphersuite.GetAllEndings(stringLen)
		endingCount = len(endings)
		validEndingClount = len(list(filter(lambda ending: len(ending) == stringLen, endings)))

		self.assertEqual(endingCount, validEndingClount, f"The function returned an incorrect number of endings with length={stringLen}")

if __name__ == "__main__":
	unittest.main()
