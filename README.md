# Vigenère cipher

Az algoritmus és a sebezhetőségének a bemutatása két üzenet azonos kulccsal való titkosítását felhasználva.
- További módszerek az algoritmus feltörésére: [Five Ways to Crack a Vigenère Cipher](https://www.cipherchallenge.org/wp-content/uploads/2020/12/Five-ways-to-crack-a-Vigenere-cipher.pdf)

## Struktúra

- A [ciphersuite.py](./ciphersuite.py) fájl tartalmazza a kódoló, dekódoló és a kulcs visszafejtő függvényeket
- A [random_generator.py](./random_generator.py) fájl tartalmaz segéd függvényeket valósnak látszó üzenetek és kulcsok generálására
	- A fájlt magában futtatva ad egy kulcsot és két üzenetet
- A [test_cipher.py](./test_cipher.py) fájl tartalmazza a függvényeket ellenőrző és bemutató unittesteket 
- A [playground](./playground/) mappa tesztelés során használatos fájlokat tartalmaz
