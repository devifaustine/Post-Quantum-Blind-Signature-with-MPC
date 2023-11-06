from math import ceil, floor, log2
from bytes_utils import xor, chunkbytes

# TODO: fix and add comments - understand and modify it
class WOTS(object):

    def __init__(self, n, w, F, Gl):
        """
        Initializes WOTS+ (Winternitz One Time Signatures)
        :param n: length of hashes in bits
        :param w: Winternitz parameter, chain length and block size trade-off
        :param F: function used to construct chains (n/8 bytes -> n/8 bytes)
        :param Gl: PRG to generate the chain bases, based on seed and number of bytes
        """
        self.n = n
        self.w = w
        self.l1 = ceil(n / log2(w))
        self.l2 = floor(log2(self.l1 * (w - 1)) / log2(w)) + 1
        self.l = self.l1 + self.l2 # determine the total number of chain
        # perm = ChaCha().permuted
        self.F = F # self.F = lambda m: perm(m + C)[:32]
        self.Gl = lambda seed: Gl(seed=seed, n=self.l * self.n // 8)

    def chains(self, x, masks, chainrange):
        """

        :param x: secret key / signature
        :param masks: array or iterable (?)
        :param chainrange:
        :return:
        """
        x = list(x)
        for i in range(self.l):
            for j in chainrange[i]:
                x[i] = self.F(xor(x[i], masks[j]))
        return x

    def int_to_basew(self, x, base):
        for _ in range(self.l1):
            yield x % base
            x //= base

    def chainlengths(self, m):
        M = int.from_bytes(m, byteorder='little')
        M = list(self.int_to_basew(M, self.w))
        C = sum(self.w - 1 - M[i] for i in range(self.l1))
        C = list(self.int_to_basew(C, self.w))
        return M + C

    def keygen(self, seed, masks):
        sk = self.Gl(seed)
        sk = chunkbytes(sk, self.n // 8)
        return self.chains(sk, masks, [range(0, self.w-1)]*self.l)

    def sign(self, m, seed, masks):
        sk = self.Gl(seed)
        sk = chunkbytes(sk, self.n // 8)
        B = self.chainlengths(m)
        return self.chains(sk, masks, [range(0, b) for b in B])

    def verify(self, m, sig, masks):
        B = self.chainlengths(m)
        return self.chains(sig, masks, [range(b, self.w-1) for b in B])