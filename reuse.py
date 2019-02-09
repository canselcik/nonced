#!/usr/bin/python

import argparse
import ecdsa
from ecdsa import SigningKey, NIST224p, VerifyingKey
from ecdsa.util import sigencode_string, sigdecode_string
from ecdsa.numbertheory import inverse_mod
from hashlib import sha1

def reuse(publicKeyOrderInteger, signaturePair1, signaturePair2, messageHash1, messageHash2):
    # R  = r1 == r2
    r1 = int.from_bytes(signaturePair1[0], byteorder='big')
    r2 = int.from_bytes(signaturePair2[0], byteorder='big')

    s1 = int.from_bytes(signaturePair1[1], byteorder='big')
    s2 = int.from_bytes(signaturePair2[1], byteorder='big')

    # L1 = Hash(message_1)
    # L2 = Hash(message_2)
    L1 = int.from_bytes(messageHash1, byteorder='big')
    L2 = int.from_bytes(messageHash2, byteorder='big')

    if r1 != r2:
        print("ERROR: The signature pairs given are not susceptible to this attack")
        return None

    # pk = Private Key (unknown at first)
    # K  = K value that was used (unknown at first)
    # N  = integer order of G (part of public key, known)

    # From Signing Defintion
    # s1 = (L1 + pk * R) / K Mod N    and     s2 = (L2 + pk * R) / K Mod N
    # Rearrange
    # K = (L1 + pk * R) / s1 Mod N    and     K = (L2 + pk * R) / s2 Mod N
    # Set Equal
    # (L1 + pk * R) / s1 = (L2 + pk * R) / s2     Mod N
    # Solve for pk (private key)
    # pk Mod N = (s2 * L1 - s1 * L2) / R * (s1 - s2)
    # pk Mod N = (s2 * L1 - s1 * L2) * (R * (s1 - s2)) ** -1
    numerator = (((s2 * L1) % publicKeyOrderInteger) - ((s1 * L2) % publicKeyOrderInteger))
    denominator = inverse_mod(r1 * ((s1 - s2) % publicKeyOrderInteger), publicKeyOrderInteger)

    privateKey = numerator * denominator % publicKeyOrderInteger
    return privateKey

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Do the thing')
    parser.add_argument('pubkey', metavar='pubkey', type=str, nargs=1, help='hex encoded pubkey')
    parser.add_argument('r', metavar='r', type=str, nargs=1, help='hex encoded shared r')
    parser.add_argument('hash1', metavar='hash1', type=str, nargs=1, help='hex encoded hash of the first message')
    parser.add_argument('s1', metavar='s1', type=str, nargs=1, help='hex encoded s for the first message')
    parser.add_argument('hash2', metavar='hash2', type=str, nargs=1, help='hex encoded hash of the second message')
    parser.add_argument('s2', metavar='s2', type=str, nargs=1, help='hex encoded s for the second message')
    args = parser.parse_args()

    vk = VerifyingKey.from_string(bytes.fromhex(args.pubkey[0][2:]), curve=ecdsa.SECP256k1)

    s1 = bytes.fromhex(args.s1[0])
    z1 = bytes.fromhex(args.hash1[0])

    s2 = bytes.fromhex(args.s2[0])
    z2 = bytes.fromhex(args.hash2[0])

    r = bytes.fromhex(args.r[0])

    print(reuse(vk.pubkey.order, (r,s1), (r,s2), z1, z2))
