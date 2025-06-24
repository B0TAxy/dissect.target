import hashlib
import logging
from binascii import Error as binascii_Error
from binascii import hexlify, unhexlify
from struct import pack, unpack

from Crypto.Util.Padding import unpad
from Cryptodome.Cipher import AES, ARC4, DES
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from dissect.cstruct import cstruct

ntds_crypto_def = """
typedef struct {
    char Header[8];
    char KeyMaterial[16];
    uint8 EncryptedPek[];
} PEKLIST_ENC;

typedef struct {
    char Header[32];
    uint8 DecryptedPek[];
} PEKLIST_PLAIN;

typedef struct {
    char Header[1];
    char Padding[3];
    char Key[16];
} PEK_KEY;

typedef struct {
    uint16 AlgorithmID;
    uint16 Flags;
    uint32 PekID;
    uint8 Salt[16];
    uint8 EncryptedData[];
} ENC_SECRET_WIN2K;

typedef struct {
    uint16 AlgorithmID;
    uint16 Flags;
    uint32 PekID;
    uint8 Salt[16];
    uint32 SecretLength;
    uint8 EncryptedData[];
} ENC_SECRET_WIN16;
"""

c_ntds_crypto = cstruct().load(ntds_crypto_def)

PEKLIST_ENC = c_ntds_crypto.structs.PEKLIST_ENC
PEKLIST_PLAIN = c_ntds_crypto.structs.PEKLIST_PLAIN
PEK_KEY = c_ntds_crypto.structs.PEK_KEY


# Wrapper for ENC_SECRET
class ENC_SECRET:
    SECRET_ENCRYPTION_ALGORITHMS = {
        "DB_RC4": 0x10,
        "DB_RC4_SALT": 0x11,
        "REP_RC4_SALT": 0x12,
        "DB_AES": 0x13,
    }

    def __init__(self, data: bytes):
        self.raw_data = data
        self.algo_id = unpack("<H", data[:2])[0]

        self.is_aes = False
        self.is_rc4 = False

        if self.algo_id == self.SECRET_ENCRYPTION_ALGORITHMS["DB_AES"]:
            self.struct = c_ntds_crypto.structs.ENC_SECRET_WIN16(data)
            self.is_aes = True
        elif self.algo_id in (
            self.SECRET_ENCRYPTION_ALGORITHMS["DB_RC4"],
            self.SECRET_ENCRYPTION_ALGORITHMS["DB_RC4_SALT"],
            self.SECRET_ENCRYPTION_ALGORITHMS["REP_RC4_SALT"],
        ):
            self.struct = c_ntds_crypto.structs.ENC_SECRET_WIN2K(data)
            self.is_rc4 = True
        else:
            logging.error(f"Unknown algorithm ID {self.algo_id} in secret")
            raise ValueError(f"Unknown algorithm ID: {self.algo_id}")

        self.algo_type = next(k for k, v in self.SECRET_ENCRYPTION_ALGORITHMS.items() if v == self.algo_id)

    def __getattr__(self, name):
        return getattr(self.struct, name)

    def pack(self):
        return self.struct.pack()


def transform_key(key7: bytes) -> bytes:
    """Convert 7-byte input to 8-byte DES key with odd parity."""
    if len(key7) != 7:
        raise ValueError("Key must be exactly 7 bytes")

    key8 = bytearray(8)
    key8[0] = key7[0] & 0xFE
    key8[1] = ((key7[0] << 7) | (key7[1] >> 1)) & 0xFE
    key8[2] = ((key7[1] << 6) | (key7[2] >> 2)) & 0xFE
    key8[3] = ((key7[2] << 5) | (key7[3] >> 3)) & 0xFE
    key8[4] = ((key7[3] << 4) | (key7[4] >> 4)) & 0xFE
    key8[5] = ((key7[4] << 3) | (key7[5] >> 5)) & 0xFE
    key8[6] = ((key7[5] << 2) | (key7[6] >> 6)) & 0xFE
    key8[7] = (key7[6] << 1) & 0xFE

    # Set odd parity bit
    for i in range(8):
        b = key8[i]
        if bin(b).count("1") % 2 == 0:
            key8[i] |= 1

    return bytes(key8)


def load_certificate(cert_type: str, data: bytes) -> x509.Certificate:
    if cert_type == "PEM":
        return x509.load_pem_x509_certificate(data, backend=default_backend())
    if cert_type == "DER":
        return x509.load_der_x509_certificate(data, backend=default_backend())
    raise ValueError("cert_type must be 'PEM' or 'DER'")


def dump_certificate(cert_type: str, cert: x509.Certificate) -> bytes:
    if cert_type == "PEM":
        return cert.public_bytes(encoding=x509.Encoding.PEM)
    if cert_type == "DER":
        return cert.public_bytes(encoding=x509.Encoding.DER)
    raise ValueError("cert_type must be 'PEM' or 'DER'")


FILETYPE_PEM = "PEM"
FILETYPE_ASN1 = "DER"


def format_asn1_to_pem(data: bytes):
    try:  # is it hex encoded?
        cert = load_certificate(FILETYPE_ASN1, unhexlify(data))
    except binascii_Error:  # or raw bytes?
        cert = load_certificate(FILETYPE_ASN1, data)
    return dump_certificate(FILETYPE_PEM, cert).decode()


def deriveKey(baseKey):
    key = pack("<L", baseKey)
    key1 = [key[0], key[1], key[2], key[3], key[0], key[1], key[2]]
    key2 = [key[3], key[0], key[1], key[2], key[3], key[0], key[1]]

    return transform_key(bytes(key1)), transform_key(bytes(key2))


def decryptAES(key, value, iv=b"\x00" * 16):
    plainText = b""
    if iv != b"\x00" * 16:
        aes256 = AES.new(key, AES.MODE_CBC, iv)

    for index in range(0, len(value), 16):
        if iv == b"\x00" * 16:
            aes256 = AES.new(key, AES.MODE_CBC, iv)
        cipherBuffer = value[index : index + 16]
        # Pad buffer to 16 bytes
        if len(cipherBuffer) < 16:
            cipherBuffer += b"\x00" * (16 - len(cipherBuffer))
        plainText += aes256.decrypt(cipherBuffer)
    try:
        return unpad(plainText, 16)
    except ValueError:
        # data is certainly unpadded
        return plainText


class PEK_LIST:
    def __init__(self, rawEncPekList: bytes, bootKey: bytes):
        self.__encryptedPekList = PEKLIST_ENC(rawEncPekList)
        self.__decryptedPekList = None
        self.__bootKey = bootKey
        self.plainPekList = list()

        if self.__encryptedPekList["Header"][:4] == b"\x02\x00\x00\x00":
            # Up to Windows 2012 R2 looks like header starts this way
            md5 = hashlib.new("md5")
            md5.update(self.__bootKey)
            for i in range(1000):
                md5.update(self.__encryptedPekList["KeyMaterial"])
            tmpKey = md5.digest()
            rc4 = ARC4.new(tmpKey)
            self.__decryptedPekList = PEKLIST_PLAIN(rc4.encrypt(self.__encryptedPekList["EncryptedPek"]))
            pek_len = len(PEK_KEY())
            for i in range(len(self.__decryptedPekList["DecryptedPek"]) // pek_len):
                cursor = i * pek_len
                pek = PEK_KEY(self.__decryptedPekList["DecryptedPek"][cursor : cursor + pek_len])
                logging.info("PEK # %d found and decrypted: %s", i, hexlify(pek["Key"]).decode("utf-8"))
                self.plainPekList.append(pek["Key"])

        elif self.__encryptedPekList["Header"][:4] == b"\x03\x00\x00\x00":
            # Windows 2016 TP4 header starts this way
            # Encrypted PEK Key seems to be different, but actually similar to decrypting LSA Secrets.
            # using AES:
            # Key: the bootKey
            # CipherText: PEKLIST_ENC['EncryptedPek']
            # IV: PEKLIST_ENC['KeyMaterial']
            self.__decryptedPekList = PEKLIST_PLAIN(
                decryptAES(
                    self.__bootKey, self.__encryptedPekList["EncryptedPek"], self.__encryptedPekList["KeyMaterial"]
                )
            )

            # PEK list entries take the form:
            #   index (4 byte LE int), PEK (16 byte key)
            # the entries are in ascending order, and the list is terminated
            # by an entry with a non-sequential index (08080808 observed)
            pos, cur_index = 0, 0
            while True:
                pek_entry = self.__decryptedPekList["DecryptedPek"][pos : pos + 20]
                if len(pek_entry) < 20:
                    break  # if list truncated, should not happen
                index, pek = unpack("<L16s", pek_entry)
                if index != cur_index:
                    break  # break on non-sequential index
                self.plainPekList.append(pek)
                logging.info("PEK # %d found and decrypted: %s", index, hexlify(pek).decode("utf-8"))
                cur_index += 1
                pos += 20

    def removeRC4Layer(self, encSecret: ENC_SECRET) -> str:
        md5 = hashlib.new("md5")
        md5.update(self.plainPekList[int(encSecret["PekID"])])
        md5.update(encSecret["Salt"])
        tmpKey = md5.digest()
        rc4 = ARC4.new(tmpKey)
        plainText = rc4.encrypt(encSecret["EncryptedData"])
        return plainText

    def __removeDESLayer(self, cipher: bytes, rid: str) -> str:
        Key1, Key2 = deriveKey(int(rid))
        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)
        plainText = Crypt1.decrypt(cipher[:8]) + Crypt2.decrypt(cipher[8:])
        return plainText

    def decryptSecret(
        self, rawSecret: bytes, rid: bytes = b"", isHistory: bool = False, hasDES: bool = True, isADAM: bool = False
    ) -> str:
        try:
            encSecret = ENC_SECRET(rawSecret)
        except ValueError as e:
            logging.exception(e)
            return "DEC_ERROR_INIT"
        except Exception as e:
            logging.exception(e)
            return "DEC_ERROR_UNK"
        if hasattr(encSecret, "is_rc4"):
            tmpPlain = self.removeRC4Layer(encSecret)
            # need the rid too
            # TO:DO test this
            # return "TO:DO:RC4:PASS:RID"
        elif hasattr(encSecret, "is_aes"):
            # encSecret.dump()
            tmpPlain = decryptAES(
                self.plainPekList[int(encSecret["PekID"])], encSecret["EncryptedData"], encSecret["Salt"]
            )

        if isADAM:
            if isHistory and rid:
                history = list()
                (count,) = unpack("<i", tmpPlain[:4])
                for i in range(count):
                    history.append(
                        hexlify(tmpPlain[4 + 4 * (i + 1) + i * 16 : 4 + 4 * (i + 1) + (i + 1) * 16]).decode("utf-8")
                    )
                return history
            if rid:
                return hexlify(tmpPlain).decode("utf-8")
            return "MISSING_RID_" + hexlify(tmpPlain).decode("utf-8")

        # has DES layer ??
        if hasDES:
            if isHistory and rid:
                history = list()
                for i in range(len(tmpPlain) // 16):
                    history.append(hexlify(self.__removeDESLayer(tmpPlain[i * 16 : (i + 1) * 16], rid)).decode("utf-8"))
                return history
            if rid:
                return hexlify(self.__removeDESLayer(tmpPlain, rid)).decode("utf-8")
            return "MISSING_RID_" + hexlify(tmpPlain).decode("utf-8")
        return tmpPlain
