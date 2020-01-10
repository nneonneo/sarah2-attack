from sarah2 import Sarah2Cipher, ALPHABET, INT_TO_PAIR, PAIR_TO_INT
from collections import defaultdict

def permute(msg):
    return msg[::2] + msg[1::2]

def invpermute(msg):
    mid = len(msg) // 2
    return ''.join(a + b for a, b in zip(msg[:mid], msg[mid:]))

'''
All attack functions take a single encryption function as a parameter,
so they can't cheat by looking at the key.
'''

def attack_long_messages(encrypt, sz=10000):
    ''' Attack by encrypting long messages of a fixed length.

    By obtaining the encryptions of enough large messages, we can leak most of the key.
    This is a variant of the slide attack, where we basically brute-force the first round.

    On average, this attack encrypts 3655000 characters, and obtains 99.9% of the key entries
    (ref: https://math.stackexchange.com/a/72229/24813 with n=729, k=5000).
    '''

    pt = '_' * sz
    ct = encrypt(pt)
    # apply final permutation, so that ct and ct2 differ by only substitution
    ct = permute(ct)

    def make_key(ct, ct2):
        # guess that ct and ct2 differ by just one substitution
        mkey = [None] * (len(ALPHABET) * len(ALPHABET))

        for i in range(0, sz, 2):
            idx = PAIR_TO_INT[ct[i:i+2]]
            target = ct2[i:i+2]
            if mkey[idx] is not None and mkey[idx] != target:
                # failed: contradiction
                return None
            mkey[idx] = target
        return mkey

    for x in ALPHABET:
        # progress counter
        print("Trying %s?" % x)
        for y in ALPHABET:
            # xxxxxx..yyyyyy.. is the encryption of ________... after one round
            pt2 = x * (sz // 2) + y * (sz // 2)
            ct2 = encrypt(pt2)
            mkey = make_key(ct, ct2)
            if mkey is not None:
                return mkey

def attack_short_messages(encrypt, sz=16):
    ''' Attack by encrypting short messages of a particular format.

    This is a variant of the slide attack which "learns" the S-Box from a few ciphertexts.

    It requires encrypting exactly 1458 short messages of any specific length from 8 to 16.
    (27 of these encryptions are redundant, so we could theoretically get away with 1431 messages).

    Lengths as short as 4 are viable, but with sz=4 this fails with probability ~30%.
    '''

    hsz = sz // 2

    # 729 encryptions: "abababab..." for all ab, plus final permutation
    ma = {c: permute(encrypt(c * hsz)) for c in INT_TO_PAIR}
    # 729 encryptions: "xxxx..yyyy.." for all xy
    mb = {c: encrypt(permute(c * hsz)) for c in INT_TO_PAIR}
    # For each S-Box entry A->B, ma[A] corresponds with mb[B].
    # We just have to find those correspondences to break the cipher.

    # At this point, it's pure computation - we simply have to work out which correspondences
    # are consistent with the current known key. We conservatively only choose correspondences
    # which yield one possible result (we could also backtrack from multiple possibilities).
    key = [None] * (len(ALPHABET) * len(ALPHABET))
    ikey = [None] * (len(ALPHABET) * len(ALPHABET))

    def tryset(pt, pt2, ct, ct2):
        tkey = key[:]
        tikey = ikey[:]
        def trypair(x, y):
            ix = PAIR_TO_INT[x]
            iy = PAIR_TO_INT[y]
            if tkey[ix] is not None and tkey[ix] != y:
                return False
            if tikey[iy] is not None and tikey[iy] != x:
                return False
            tkey[ix] = y
            tikey[iy] = x
            return True
        if not trypair(pt, pt2):
            return None
        for i in range(0, sz, 2):
            if not trypair(ct[i:i+2], ct2[i:i+2]):
                return None
        return tkey, tikey

    prevcount = key.count(None)
    while None in key:
        for pt, ct in ma.items():
            # With what we now know, expand search to find all ma/mb pairs
            poss = []
            for pt2, ct2 in mb.items():
                res = tryset(pt, pt2, ct, ct2)
                if res:
                    poss.append(res)
                    if len(poss) >= 2:
                        break
            if len(poss) == 0:
                raise ValueError("failed - should not happen")
            elif len(poss) == 1:
                key, ikey = poss[0]
        count = key.count(None)
        if count == prevcount:
            # failure - couldn't recover all entries (probably recovered none)
            break
        prevcount = count

    return key

if __name__ == '__main__':
    cipher = Sarah2Cipher()
    # print out our key just for demonstration - we don't use it in the attack obviously!
    print(cipher.key)

    ## Long message attack
    # we force the number of rounds to "HARD" (2 * log2(n)) here, but the slide attack
    # will work no matter how many rounds you use
    nr = Sarah2Cipher.HARD
    nkey = attack_long_messages(lambda pt: cipher.encrypt(pt, nr), sz=10000)
    print("long attack (sz=10000) obtained key:")
    print(nkey)

    # this attack still works with smaller messages but recovers less of the key
    # unrecovered key entries are denoted as None
    nkey = attack_long_messages(lambda pt: cipher.encrypt(pt, nr), sz=2000)
    print("long attack (sz=2000) obtained key:")
    print(nkey)


    ## Short message attack
    # perform the attack with size 8; this has a small chance (~1%) of failing and recovering nothing
    nr = Sarah2Cipher.HARD
    nkey = attack_short_messages(lambda pt: cipher.encrypt(pt, nr), sz=8)
    print("short attack (sz=8) obtained key:")
    print(nkey)

    # short message attack works with basically any length from 4 upwards
    # however, with sz=4 there's a decent chance of failure (empirically, about 30% fail rate)
    nr = Sarah2Cipher.HARD
    nkey = attack_short_messages(lambda pt: cipher.encrypt(pt, nr), sz=4)
    print("short attack (sz=4) obtained key:")
    print(nkey)
