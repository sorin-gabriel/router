Precizari:
```
-> Tabela ARP este dinamica
-> Cautarea in tabela de rutare se face prin cautare binara: O(logN)
-> Se foloseste o coada de asteptare pentru pachete
-> Coding style: in surse am optat pentru un numar maxim de 100 de caractere
pe linie, deoarece anumite instructiuni necesita un spatiu orizontal mai mare
```
Conform comentariilor din sursa, descrierea pe scurt a implementarii este urmatoarea:
```
-> La pornire, routerul isi initializeaza tabela de rutare (citeste intrarile
din fisier, le pune in memorie, le sorteaza), initializeaza o tabela ARP goala,
initializeaza o coada de asteptare goala si apoi intra in bucla si asteapta
pachete
```
In bucla:
```
-> La primirea unui pachet se extrage Ethernet header, adresele IP si MAC pe
care a venit pachetul
```
```
-> Daca pachetul e de tip ARP:

    -> Se actualizeaza tabela ARP
    -> Daca mesajul este un request, se trimite reply
    -> Daca mesajul este un reply, se trimit din coada de asteptare pachetele
    care asteptau acest reply
```
```
-> Daca pachetul e de tip IP, se actualizeaza headerul IP:

    -> Daca checksum-ul este gresit, se arunca pachetul
    -> Se actualizeaza TTL; daca pachetul a expirat, se trimite ICMP error
    (time exceeded)
    -> Se actualizeaza checksum-ul

    -> Daca pachetul este de tip ICMP:

        -> Daca checksum-ul headerului ICMP este gresit, se arunca pachetul
        -> Daca mesajul este de tip echo request si este destinat acestui
        router, se trimite echo reply

    -> Daca pachetul este de tip IP (!= ICMP):

        -> Daca nu exista o ruta potrivita, se trimite ICMP error (destination
        unreach)
        -> Daca exista o ruta, dar nu se cunoaste MAC-ul urmatorului dispozitiv,
        pachetul este pus in coada de asteptare:

            -> Daca nu exista alte pachete in coada de asteptare pentru a fi
            trimise catre aceeasi destinatine, trimite un ARP request
            -> Daca exista alte pachete, inseamna ca un ARP request a fost deja
            trimis

        -> Daca exista o ruta si se cunoaste MAC-ul urmatorului dispozitiv,
        trimite pachetul
```
