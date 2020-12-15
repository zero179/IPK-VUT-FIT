Tento program pracuje ako sietovy analyzator v jazyku C, ktory na vybranom rozhrani filtruje pakety. Ak rozhranie nezadáme vypisu sa vsetky dostupne rozhrania. Ak zadame port, napriklad port 23 filtrujeme pakety podla daneho portu. Ak zadame -t alebo --tcp budeme zobrazovat len tcp pakety a naopak ak zadame-u alebo --udp tak filtrujeme len udp pakety. V pripade ze nezadame ani jednu z tychto paketov vypisujeme obidve. Ak zadavame n a jeho hodnotu ako integer, jeho hodnota znaci kolko paketov chceme vypisat ak ju nezadame vypise sa 1 paket.

Ukazka vstupov:
./ipk-sniffer -i eth0 -p 23 -t
./ipk-sniffer -i eth0 -p 23 -t -u
./ipk-sniffer -i eth0 -p 23 -t --udp -n 3
./ipk-sniffer


Projekt obsahu subory:
readme
manual.pdf
makefile
ipk-sniffer

Tento program nepodporuje IPv6 iba IPv4.