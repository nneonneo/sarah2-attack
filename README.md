## Cryptanalysis of the the Sarah2 pen-and-paper cipher

Please see the [writeup](https://robertxiao.ca/hacking/sarah2) for more detail.

This repo contains a reimplementation of the Sarah2 cipher in Python (sarah2.py), and two attacks which fully reveal the key (attack.py). Running attack.py generates a random key, then attempts to recover it using the two methods outlined in the writeup. It takes a few seconds to run and is substantially faster if run with PyPy.
