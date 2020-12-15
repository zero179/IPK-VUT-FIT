# README
*Autor : Šimon Feňko (xfenko01)*

Cieľom bolo implementovať server, ktorý bude podporovať komunikáciu protokolom HTTP a bude zaisťovať preklad doménových mien a naopak.
Na implementáciu projektu som použil programovací jazyk python 3 pomocou knižnice funkcií socket. Beží na základe cyklu a čaká na požiadavky, ktoré sú následne tvorené za pomoci nástroj CURL. Následne server vyhodnotí dotaz a odošle príslušnú odpoveď.

- server .py je implementovaný ako IPv4 server 
- podporuje metódy GET a POST
- spúšťa sa za pomoci make run PORT = <číslo portu>
- pracuje na lokálnom serveri
- kontroluje pri spustení, či je rozsah Portu 0 až 65535

# Metóda GET
-preklad jedného dotazu
- vyžaduje parametre 1. name a 2. type, ktoré ale môžu byť zadané v ľubovolnom poradí
- program musí kontrolovať správnosť zadaného formátu, v prípade nesprávnej hlavičky aj nesprávne zadaného doménoveho mena nastane prípad chyba 400 Bad Request
- v prípade, že je formát správny ale meno sa nepodarí preložiť nastane prípad chyba 404 Not Found

# Metóda POST
- v tele obsahuje viac dotazov(zoznam)
- vyžaduje súbor s požiadavkami
- kontroluje správnosť požiadavkou aj hlavičky




 