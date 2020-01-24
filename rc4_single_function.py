import codecs
from typing import List
from typing import Union


def rc4(key: Union[str, bytes, bytearray],
        input_bytes: Union[bytes, bytearray],
        initialization_vector: Union[bytes, bytearray] = b'',
        ) -> bytearray:
    """
    single-function RC4-drop stream encryption
    uses IV to determine how much of keystream to skip
    e.g. to mimic RC4-drop-768, set IV to b'\xFE\x02'

    :param key: 1 to 256 bytes (remainder will be ignored)
    :param input_bytes: data to encrypt / decrypt
    :param initialization_vector: 1 to 16 bytes (remainder will be ignored)
    :return: encoded bytes
    """
    if not isinstance(key, (str, bytes, bytearray)):
        raise TypeError('key should be bytes')
    if not isinstance(input_bytes, (bytes, bytearray)):
        raise TypeError('input should be bytes')
    if not isinstance(initialization_vector, (bytes, bytearray)):
        raise TypeError('IV should be bytes')
    assert len(key) > 0

    # convert to bytes (kind of)
    if isinstance(key, str):
        key = [ord(char) for char in key[:256]]
    key_length = len(key)

    # generate S-box
    j = 0
    s: List[int] = list(range(256))
    for i in range(256):
        j = (j + s[i] + key[i % key_length]) & 0xFF
        s[i], s[j] = s[j], s[i]

    # init variables
    i = 0
    j = 0

    # skip N bytes using the IV
    if initialization_vector:
        skip = (510 + sum(c << i for i, c in enumerate(initialization_vector[:16]))) & 0xFFFF

        for _ in range(skip):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]

    # don't destroy the input bytes
    if isinstance(input_bytes, bytes):
        output_bytes = bytearray(input_bytes)  # bytes are immutable
    else:
        output_bytes = input_bytes[:]  # shallow copy

    # in-place xor with key stream
    for idx in range(len(output_bytes)):
        i += 1
        i &= 0xFF
        j += s[i]
        j &= 0xFF
        s[i], s[j] = s[j], s[i]

        output_bytes[idx] ^= s[(s[i] + s[j]) & 0xFF]

    return output_bytes


def _encrypt_to_hex(key, text):
    """
    # Test case 1
    # key = 'Key' # '4B6579' in hex
    # plaintext = 'Plaintext'
    # ciphertext = 'BBF316E8D940AF0AD3'
    >>> _encrypt_to_hex('Key', 'Plaintext')
    'BBF316E8D940AF0AD3'

    # Test case 2
    # key = 'Wiki' # '57696b69'in hex
    # plaintext = 'pedia'
    # ciphertext = 1021BF0420
    >>> _encrypt_to_hex('Wiki', 'pedia')
    '1021BF0420'

    # Test case 3
    # key = 'Secret' # '536563726574' in hex
    # plaintext = 'Attack at dawn'
    # ciphertext = 45A01F645FC35B383552544B9BF5
    >>> _encrypt_to_hex('Secret', 'Attack at dawn')
    '45A01F645FC35B383552544B9BF5'

    :param key:
    :param text:
    :return:
    """
    return codecs.encode(bytes(rc4(key.encode('ascii'), text.encode('utf8'))), 'hex_codec').decode('ascii').upper()


def _decrypt_from_hex(key, text):
    """
    # Test case 1
    # key = 'Key' # '4B6579' in hex
    # plaintext = 'Plaintext'
    # ciphertext = 'BBF316E8D940AF0AD3'
    >>> _decrypt_from_hex('Key', 'BBF316E8D940AF0AD3')
    'Plaintext'

    # Test case 2
    # key = 'Wiki' # '57696b69'in hex
    # plaintext = 'pedia'
    # ciphertext = 1021BF0420
    >>> _decrypt_from_hex('Wiki', '1021BF0420')
    'pedia'

    # Test case 3
    # key = 'Secret' # '536563726574' in hex
    # plaintext = 'Attack at dawn'
    # ciphertext = 45A01F645FC35B383552544B9BF5
    >>> _decrypt_from_hex('Secret', '45A01F645FC35B383552544B9BF5')
    'Attack at dawn'

    :param key:
    :param text:
    :return:
    """
    return rc4(key.encode('ascii'), codecs.decode(text, 'hex_codec')).decode('utf8')
