from typing import Union, overload

Sbox = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
]

FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
]

ROTL = lambda X, P: ((X << P) | (X >> (32 - P))) & 0xFFFFFFFF

INT32 = lambda X: int.from_bytes(X, 'big') if isinstance(X, (bytes, tuple, list)) else X
BYTE8 = lambda X: X if isinstance(X, (bytes, tuple, list)) else int(X).to_bytes(4, 'big')

MODE_ECB = 'MODE_ECB'
MODE_CBC = 'MODE_CBC'
MODE_CFB = 'MODE_CFB'
MODE_OFB = 'MODE_OFB'

def PKCS7(data_to_pad: bytes, block_size: int) -> bytes:
    """
    PKCS7填充算法
    """
    remain_size = len(data_to_pad) % block_size
    if remain_size > 0:
        padding_len = block_size - remain_size
        data_to_pad = data_to_pad + bytes([padding_len] * padding_len)
    return data_to_pad

def ZERO(data_to_pad: bytes, block_size: int) -> bytes:
    """
    ZERO填充算法
    """
    remain_size = len(data_to_pad) % block_size
    if remain_size > 0:
        padding_len = block_size - remain_size
        data_to_pad = data_to_pad + bytes(padding_len)
    return data_to_pad

class SM4:
    Sbox = tuple(Sbox)
    FK = tuple(FK)
    CK = tuple(CK)

    @overload
    def __init__(self, key: bytes, mode = MODE_ECB):
        """
        SM4构造函数（非标准实现）
        如果key不足16字节则循环补全，如
        b'0123456789' -> b'0123456789012345'
        如果key大于16字节则截断
        参数：
            key: 密钥，可以是16字节的字节流
            mode: 加解密模式
        """
        ...
    
    @overload
    def __init__(self, key: list[int], mode = MODE_ECB):
        """
        SM4构造函数
        参数：
            key: 密钥，4组32比特4字节的数组
            mode: 加解密模式
        """
        ...
    
    def __init__(self, key, mode = MODE_ECB):
        if isinstance(key, bytes):
            if len(key) == 0:
                key = '0123456789abcdef'
            elif len(key) < 16:
                key += key[16 - (len(key) % 16)]
            elif len(key) > 16:
                key = key[:16]
            key = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]
        self.__MK = tuple(key)
        K = [self.MK[i] ^ SM4.FK[i] for i in range(4)] + [0] * 32
        for i in range(32):
            K[i + 4] = K[i] ^ SM4.T_(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i])
        self.__rk = tuple(K[4:])
        self.__mode = mode

    @property
    def MK(self):
        """
        加密密钥
        """
        return self.__MK
    
    @property
    def rk(self):
        """
        加密轮密钥
        """
        return self.__rk
    
    @property
    def rk_(self):
        """
        解密轮密钥
        """
        return self.__rk[::-1]
    
    @property
    def mode(self):
        return self.__mode

    @staticmethod
    @overload
    def tau(A: Union[int, tuple[int], list[int], bytes]):
        """
        非线性变换 `\\tau`
        参数：
            A: 每组8比特1字节，共4组的数组
        返回值
            tau变换结果
        """
        ...
    
    @staticmethod
    @overload
    def tau(a0: int, a1: int, a2: int, a3: int):
        """
        非线性变换 `\\tau`
        参数：
            (a0,a1,a2,a3): 每组8比特1字节，共4组的数组
        返回值
            tau变换结果
        """
        ...

    @staticmethod
    def tau(arg0, arg1 = None, arg2 = None, arg3 = None):
        if arg3 is None:
            arg0 = BYTE8(arg0)
            a0, a1, a2, a3 = arg0
        else:
            a0, a1, a2, a3 = arg0, arg1, arg2, arg3
        return (SM4.Sbox[a0], SM4.Sbox[a1], SM4.Sbox[a2], SM4.Sbox[a3])
    
    @staticmethod
    def L(X: Union[int, bytes, tuple[int], list[int]]):
        """
        线性变换 L
        参数：
            X: 32比特4字节
        返回值
            线性变换L的结果
        """
        X = INT32(X)
        return X ^ ROTL(X, 2) ^ ROTL(X, 10) ^ ROTL(X, 18) ^ ROTL(X, 24)

    @staticmethod
    def L_(X: Union[int, bytes, tuple[int], list[int]]):
        """
        线性变换 L'
        参数：
            X: 32比特4字节
        返回值
            线性变换L'的结果
        """
        X = INT32(X)
        return X ^ ROTL(X, 13) ^ ROTL(X, 23)

    @staticmethod
    def T(X: Union[int, bytes, tuple[int], list[int]]):
        """
        合成置换 T
        参数：
            X: 32比特4字节
        返回值
            合成置换T的结果
        """
        return SM4.L(SM4.tau(X))
    
    @staticmethod
    def T_(X: Union[int, bytes, tuple[int], list[int]]):
        """
        合成置换 T'
        参数：
            X: 32比特4字节
        返回值
            合成置换T'的结果
        """
        return SM4.L_(SM4.tau(X))

    @staticmethod
    def F(X0: Union[int, bytes, tuple[int], list[int]], X1: Union[int, bytes, tuple[int], list[int]], X2: Union[int, bytes, tuple[int], list[int]], X3: Union[int, bytes, tuple[int], list[int]], rk: int):
        """
        轮函数 F
        参数：
            (X0,X1,X2,X3): 每组32比特4字节的数组
            rk: 轮密钥
        返回值
            轮函数结果
        """
        X0, X1, X2, X3 = INT32(X0), INT32(X1), INT32(X2), INT32(X3)
        return X0 ^ INT32(SM4.T(X1 ^ X2 ^ X3 ^ rk))
    
    @staticmethod
    def round(X: Union[list[int], tuple[int]], rk: Union[list[int], tuple[int]]):
        """
        SM4轮运算
        参数：
            X: 轮输入(X0,X1,X2,X3)，每组32比特4字节
        返回值：
            轮输出
        """
        X = list(X) + [0] * 32
        for i in range(32):
            X[i + 4] = SM4.F(X[i], X[i + 1], X[i + 2], X[i + 3], rk[i])
        return (X[35], X[34], X[33], X[32])

    def __ECBEncrypt(self, X: list[int]):
        Y = []
        for i in range(0, len(X), 4):
            Y.extend(SM4.round(X[i:i+4], self.rk))
        return Y
    
    def __ECBDecrypt(self, X: list[int]):
        Y = []
        for i in range(0, len(X), 4):
            Y.extend(SM4.round(X[i:i+4], self.rk_))
        return Y

    def encrypt(self, M: bytes, padding = PKCS7):
        """
        SM4加密（非标准实现）
        参数：
            M: 字节流消息
            padding: 消息填充算法，给予`data_to_pad`和`block_size`，返回填充结果
        """
        M = padding(M, 16)
        X = [int.from_bytes(M[i:i+4]) for i in range(0, len(M), 4)]
        if self.mode == MODE_ECB:
            Y = self.__ECBEncrypt(X)
        else:
            raise RuntimeError('暂时不支持其他加密模式，TODO...')
        C = b''.join(int(y).to_bytes(4, 'big') for y in Y)
        return C
    
    def decrypt(self, C: bytes):
        """
        SM4加密（非标准实现）
        参数：
            C: 字节流密文
        """
        X = [int.from_bytes(C[i:i+4]) for i in range(0, len(C), 4)]
        if self.mode == MODE_ECB:
            Y = self.__ECBDecrypt(X)
        else:
            raise RuntimeError('暂时不支持其他加密模式，TODO...')
        M = b''.join(int(y).to_bytes(4, 'big') for y in Y)
        return M
