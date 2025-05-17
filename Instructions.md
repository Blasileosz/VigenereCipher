# 1.

Az alábbiakban egy rejtjelezési algoritmus leírása található:

- az üzenet az angol abc szerinti kisbetűkből (a-z) és szóközből (' ') állhat
- a kulcs ugyanezeket a karaktereket tartalmazhatja
- a kulcsnak legalább akkorának kell lennie mint az üzenetnek
- a rejtjelezés minden karakterre a következő műveletből  áll:
- rendeljünk a karakterhez egy kódot: a = 0, b = 1, ... z = 25, ' ' (szóköz) = 26
	- a rejtjelezett üzenet n. karaktere az üzenet n. karakter kódja + kulcs n. karakter kódja    
	- ha az eredmény nagyobb mint 26, akkor az eredmény a 27-el való osztás maradéka
- ha a kulcs hosszabb mint az üzenet, akkor a rejtjeles üzenet hossza az üzenet hossza lesz

> ## Pl.
> - Üzenet: `helloworld`
> - Kulcs:  `abcdefgijkl`
> - Rejtjelezett üzenet: `hfnosauzun`

**Készíts függvényt, amely megvalósítja a fenti rejtjelezést (az üzenet és a kulcs megadásával), és egy másikat amely megoldja azt!**


# 2.

A fenti rejtjelezés biztonságos, ha a kulcs véletlenszerű és egy kulcs csak egy üzenethez van felhasználva. Ha egy kulcsot több üzenethez is
felhasználnak, akkor támadhatóvá válik.

Ha tudjuk, hogy az üzenet értelmes angol nyelvű mondatokból áll (írásjelek nélkül, csak szóközökkel), akkor a támadásra egy lehetőség példán keresztül bemutatva:

- van két rejtjelezett üzenet, amelyekről tudjuk hogy ugyanazzal a kulccsal készültek

- tegyük fel hogy tudjuk (vagy próbálkozással arra jutunk), hogy az első üzenet azzal a szóval kezdődik, hogy "early "

- a rejtjeles üzenetbe ezt visszahelyettesítve a karaktereket ('e','a','r','l','y',' ') megkapjuk a kulcs egy részletét, amelyet a másik
rejtjeles üzeneten alkalmazva egy szótöredéket kapunk:  "curios"

- a szótöredékből kitalálható, hogy mi lehet a teljes szó (vagy egy szótár segítségével kipróbálható): "curiosity "

- a szó végének újabb karaktereit visszahelyettesítve ('i','t','y',' '") megkapjuk a kulcs egy újabb részletét, amelyet a másik
rejtjeles üzeneten alkalmazva egy újabb szótöredéket kapunk:  "bird", amiből látszik, hogy az általunk választott szó megfelelő volt.

- folyamatos próbálkozással szerencsés esetben a teljes rejtjeles üzeneteket fel lehet fedni, ha nem akkor vissza kell lépni, és más szavakat választani

- a fenti példában a két üzenet a következő volt:

	- `curiosity killed the cat`
	- `early bird catches the worm`

**Készíts függvényt, amely két megadott rejtjeles üzenet esetén megpróbálja a közösen alkalmazott kulcsot kitalálni!**

- A megvalósításhoz használd a mellékelt angol szólistát!

- Feltételezzük, hogy az üzenetekben használt összes szó megtalálható a szólistában, a szavak listában nem szereplő alakjával nem kell most törődni.

- Előfordulhat, hogy több kulcs is értelmesnek látszó eredményt ad, ilyenkor a függvény az összes lehetséges kulcsot adja vissza!

---

**A megoldások tetszőleges fejlesztési környezetben készíthetőek.**

**Ha lehetséges, akkor a választott környezetben elterjedt tesztesetekkel (pl. Java esetén JUnit) legyen a függvények működése bemutatva.**
