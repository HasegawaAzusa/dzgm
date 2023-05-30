from hmac import digest


IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
T = [0x79cc4519] * 16 + [0x7a879d8a] * 48

def FF(X: int, Y: int, Z: int):
    """
    FFj 布尔函数，调用方式 FF[j](X, Y, Z)
    """
    ...
FF = [lambda X, Y, Z: X ^ Y ^ Z] * 16 + [lambda X, Y, Z: (X & Y) | (X & Z) | (Y & Z)] * 48

def GG(X: int, Y: int, Z: int):
    """
    GGj 布尔函数，调用方式 GG[j](X, Y, Z)
    """
    ...
GG = [lambda X, Y, Z: X ^ Y ^ Z] * 16 + [lambda X, Y, Z: (X & Y) | ((~X) & Z)] * 48

ROTL = lambda X, P: ((X << P) | (X >> (32 - P))) & 0xFFFFFFFF
def P0(X: int):
    """
    置换函数 P0
    """    
    return X ^ ROTL(X, 9) ^ ROTL(X, 17)

def P1(X: int):
    """
    置换函数 P1
    """    
    return X ^ ROTL(X, 15) ^ ROTL(X, 23)

def padding(msg: bytes):
    """
    消息填充
    参数：
        msg: 消息
    返回值：
        填充后的消息，长度为512的倍数
    """
    pad_length = (448 - len(msg) * 8) % 512 // 8 - 1
    return msg + b'\x80' + bytes(pad_length) + int(len(msg) * 8).to_bytes(8, 'big')

def expand(Bi: bytes):
    """
    消息扩展
    参数：
        Bi: 64字节512位的消息块
    返回值：
        [W[0],...,W[67]],[W_[0],...,W_[63]]
    """
    W = [int.from_bytes(Bi[i:i+4], 'big') for i in range(0, len(Bi), 4)] + [0] * 52
    for j in range(16, 68):
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6]
    W_ = [0] * 64
    for j in range(0, 64):
        W_[j] = W[j] ^ W[j + 4]
    return W, W_

def CF(Vi: bytes, Bi: bytes):
    """
    消息压缩
    参数：
        Vi: 16字节64位的杂凑值
        Bi: 64字节512位的消息块
    返回值：
        Vi+1: 16字节64位的杂凑值
    """
    A, B, C, D, E, F, G, H = Vi
    W, W_ = expand(Bi)
    for j in range(64):
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j % 32)) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ ROTL(A, 12)
        TT1 = (FF[j](A, B, C) + D + SS2 + W_[j]) & 0xFFFFFFFF
        TT2 = (GG[j](E, F, G) + H + SS1 + W[j]) & 0xFFFFFFFF
        D = C
        C = ROTL(B, 9)
        B = A
        A = TT1
        H = G
        G = ROTL(F, 19)
        F = E
        E = P0(TT2)
    Vii = [A, B, C, D, E, F, G, H]
    return [(i ^ j) for i, j in zip(Vi, Vii)]

def hash(msg: bytes):
    """
    哈希函数
    参数：
        msg: 消息
    返回值：
        32字节256比特的杂凑值（哈希值）
    """
    msg = padding(msg)
    hash_count = len(msg) // 64
    B = [msg[i:i+64] for i in range(0, len(msg), 64)]
    V = [IV] + [0] * hash_count
    for i in range(hash_count):
        V[i + 1] = CF(V[i], B[i])
    return b''.join(int(j).to_bytes(4, 'big') for j in V[i + 1])

def KDF(Z: bytes, klen: int):
    """
    密钥派生算法（非标准实现，基于字节流实现）
    参数：
        Z: 基密钥字节串
        klen: 派生的密钥字节长度
    """
    assert klen < (2 ** 32 - 1) * 32
    ct = int(0x00000001)
    Ha = b''
    for _ in range(klen // 32 + 1):
        msg = Z + ct.to_bytes(4, 'big')
        Ha = Ha + hash(msg)
        ct += 1
    return Ha[0:klen]

class SM3:
    def __init__(self, msg: bytes = b""):
        self.update(msg)
    
    def digest(self):
        """
        返回SM3哈希摘要
        """
        return hash(self.__message)
    
    def hexdigest(self):
        """
        返回SM3哈希摘要的十六进制字符串
        """
        return hash(self.__message).hex()

    def KDF(self, klen: int):
        """
        SM3密钥派生函数
        """
        assert klen < (2 ** 32 - 1) * 32
        Ha = self.__Ha
        for _ in range(klen // 32 + 1):
            msg = self.__message + self.__ct.to_bytes(4, 'big')
            Ha = Ha + hash(msg)
            self.__ct += 1
        self.__Ha = Ha[klen:]
        return Ha[0:klen]
    
    def update(self, msg: bytes = b''):
        """
        更新内部字节流
        """
        self.__ct = 0x00000001
        self.__Ha = b''
        self.__message = msg