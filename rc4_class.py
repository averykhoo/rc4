from typing import Union


class RC4(object):
    def __init__(self, key: Union[str, bytes, bytearray]):
        """
        >>> RC4('key').encode_str('test')
        [127, 9, 71, 153]
        >>> RC4('key').decode_str(RC4('key').encode_str('test'))
        'test'

        :param key:
        """
        self.i = 0
        self.j = 0
        self.s = self.KSA(key)

    # noinspection PyPep8Naming
    @staticmethod
    def KSA(key):
        """
        Key Scheduling Algorithm (from wikipedia):

        for i from 0 to 255
            s[i] := i
        endfor
        j := 0
        for i from 0 to 255
            j := (j + s[i] + key[i mod keylength]) mod 256
            swap values of s[i] and s[j]
        endfor

        :param key:
        :return: new s box
        """
        if isinstance(key, str):
            key = [ord(char) for char in key]  # key.encode('utf8')

        key_length = len(key)
        s = list(range(256))

        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % key_length]) & 0xFF
            s[i], s[j] = s[j], s[i]

        return s

    # noinspection PyPep8Naming
    def PRGA(self, size):
        """
        Psudo Random Generation Algorithm (from wikipedia):
        i := 0
        j := 0
        while GeneratingOutput:
            i := (i + 1) mod 256
            j := (j + S[i]) mod 256
            swap values of S[i] and S[j]
            k := S[(S[i] + S[j]) mod 256]
            output k
        endwhile

        :param size:
        :return:
        """
        key_stream = []

        # while GeneratingOutput:
        for _ in range(size):
            self.i = (self.i + 1) & 0xFF
            self.j = (self.j + self.s[self.i]) & 0xFF
            self.s[self.i], self.s[self.j] = self.s[self.j], self.s[self.i]
            k = self.s[(self.s[self.i] + self.s[self.j]) & 0xFF]
            key_stream.append(k)

        return key_stream

    def encode_decode(self, content_bytes):
        key_stream = self.PRGA(len(content_bytes))
        return bytes([content_bytes[i] ^ key_stream[i] for i in range(len(content_bytes))])

    def encode_str(self, input_str):
        return list(self.encode_decode(input_str.encode('utf8')))

    def decode_str(self, input_bytes):
        return self.encode_decode(input_bytes).decode('utf8')


class RC4A(RC4):
    def __init__(self, key, skip=0):
        """
        >>> RC4A('key').encode_str('test')
        [127, 110, 31, 24]
        >>> RC4A('key').decode_str(RC4A('key').encode_str('test'))
        'test'

        >>> RC4A('key', 1234).encode_str('test')
        [250, 235, 192, 199]
        >>> RC4A('key', 1234).decode_str(RC4A('key', 1234).encode_str('test'))
        'test'

        :param key:
        :param skip:
        """
        super(RC4A, self).__init__(key)
        self.S2 = self.KSA(key)
        self.j2 = 0

        # to toggle the PRGA between S boxes
        self.first_op = True

        if skip > 0:
            self.PRGA(skip)

    def PRGA(self, size):
        key_stream = []

        for _ in range(size):
            if self.first_op:
                self.first_op = False

                self.i = (self.i + 1) & 0xFF
                self.j = (self.j + self.s[self.i]) & 0xFF
                self.s[self.i], self.s[self.j] = self.s[self.j], self.s[self.i]
                k = self.S2[(self.s[self.i] + self.s[self.j]) & 0xFF]
                key_stream.append(k)

            else:
                self.first_op = True

                self.j2 = (self.j2 + self.S2[self.i]) & 0xFF
                self.S2[self.i], self.S2[self.j2] = self.S2[self.j2], self.S2[self.i]
                k = self.s[(self.S2[self.i] + self.S2[self.j2]) & 0xFF]
                key_stream.append(k)

        return key_stream


class VMPC(RC4):
    def __init__(self, key, skip=0):
        """
        >>> VMPC('key').encode_str('test')
        [19, 95, 153, 146]
        >>> VMPC('key').decode_str(VMPC('key').encode_str('test'))
        'test'

        :param key:
        :param skip:
        """
        super(VMPC, self).__init__(key)

        if skip > 0:
            self.PRGA(skip)

    def PRGA(self, size):
        key_stream = []

        for _ in range(size):
            a = self.s[self.i]
            self.j = self.s[(self.j + a) & 0xFF]
            b = self.s[self.j]

            k = self.s[(self.s[b] + 1) & 0xFF]
            key_stream.append(k)

            self.s[self.i] = b
            self.s[self.j] = a
            self.i = (self.i + 1) & 0xFF

        return key_stream


class RCPlus(RC4):
    def __init__(self, key, skip=0):
        """
        >>> RCPlus('key').encode_str('test')
        [39, 207, 224, 135]
        >>> RCPlus('key').decode_str(RCPlus('key').encode_str('test'))
        'test'

        :param key:
        :param skip:
        """
        super(RCPlus, self).__init__(key)

        if skip > 0:
            self.PRGA(skip)

    def PRGA(self, size):
        key_stream = []

        for _ in range(size):
            self.i = (self.i + 1) & 0xFF
            a = self.s[self.i]

            self.j = (self.j + a) & 0xFF
            b = self.s[self.j]

            self.s[self.i] = b
            self.s[self.j] = a

            v = (self.i << 5 ^ self.j >> 3) & 0xFF
            w = (self.j << 5 ^ self.i >> 3) & 0xFF

            c = (self.s[v] + self.s[self.j] + self.s[w]) & 0xFF
            k = (self.s[(a + b) % 256] + self.s[c ^ 0xAA]) & 0xFF ^ self.s[(self.j + b) & 0xFF]

            key_stream.append(k)

        return key_stream


class RCDrop(RC4):
    """
    The paper by Ilya Mironov says:

     - Our most conservative recommendation is based on the experimental data on the tail probability of the strong
       uniform time T (Section 5.5).

     - This means that discarding the initial 12 * 256 bytes most likely eliminates the possibility of a strong attack.

     - Dumping several times more than 256 bytes from the output stream (twice or three times this number) appears
       to be just as reasonable a precaution.

     - We recommend doing so in most applications.

    I.e. the "most conservative" recommendation is to use RC4-drop(3072),
         but RC4-drop(768) "appears to be just as reasonable".

    The latter is the default for this algorithm.
    """

    def __init__(self, key, skip=768):
        """
        >>> RCDrop('key', 4096).encode_str('test')
        [101, 75, 195, 218]
        >>> RCDrop('key', 4096).decode_str(RCDrop('key', 4096).encode_str('test'))
        'test'

        :param key:
        :param skip:
        """
        super(RCDrop, self).__init__(key)

        if skip > 0:
            self.PRGA(skip)


if __name__ == '__main__':
    # does it crash
    RC4('key').PRGA(4096)
    RC4A('key').PRGA(4096)
    VMPC('key').PRGA(4096)
    RCDrop('key', 4096).PRGA(4096)
    RCPlus('key').PRGA(4096)

    print('RC4', RC4('key').encode_str('test'))
    # [127, 9, 71, 153]
    print(RC4('key').decode_str(RC4('key').encode_str('test')))
    # test

    print('RC4A', RC4A('key').encode_str('test'))
    # [127, 110, 31, 24]
    print(RC4A('key').decode_str(RC4A('key').encode_str('test')))
    # test

    print('RC4A-drop', RC4A('key', 1234).encode_str('test'))
    # [250, 235, 192, 199]
    print(RC4A('key', 1234).decode_str(RC4A('key', 1234).encode_str('test')))
    # test

    print('VMPC', VMPC('key').encode_str('test'))
    # [19, 95, 153, 146]
    print(VMPC('key').decode_str(VMPC('key').encode_str('test')))
    # test

    print('RCDrop', RCDrop('key', 4096).encode_str('test'))
    # [101, 75, 195, 218]
    print(RCDrop('key', 4096).decode_str(RCDrop('key', 4096).encode_str('test')))
    # test

    print('RCPlus', RCPlus('key').encode_str('test'))
    # [39, 207, 224, 135]
    print(RCPlus('key').decode_str(RCPlus('key').encode_str('test')))
    # test
