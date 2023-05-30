from . import sm3
from typing import Union
import random
from sage.rings.finite_rings.all import *
from sage.schemes.elliptic_curves.all import *
from sage.arith.all import *

default_p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
default_n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
default_a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
default_b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
default_Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
default_Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

C1C2C3 = "C1C2C3"
C1C3C2 = "C1C3C2"

def cathex(a: Union[int, bytes], b: Union[int, bytes], *args, byte_size = 32):
    """
    辅助函数，将多个字节串连接打包成 bytes
    输入为`int`时，默认将其打包为占位`byte_size`字节的字节串
    """
    if not isinstance(a, bytes):
        a = int(a).to_bytes(byte_size, 'big')
    if not isinstance(b, bytes):
        b = int(b).to_bytes(byte_size, 'big')
    rst = a + b
    for c in args:
        if not isinstance(c, bytes):
            c = int(c).to_bytes(byte_size, 'big')
        rst += c
    return rst

def point2hex(p: tuple[int, int], PC: str = "04"):
    """
    将点转化为十六进制字符串
    参数：
        p: 点，(x,y)
        PC: 前缀，默认为04
    返回值：
        十六进制字符串
    """
    return f"{PC}{int(p[0]):064X}{int(p[1]):064X}"

def hex2point(h: str, PC: str = "04"):
    """
    将十六进制字符串转化为点
    参数：
        h: 十六进制字符串
        PC: 前缀，默认为04
    返回值：
        点(x,y)
    """
    if not h.startswith(PC):
        raise RuntimeError(f'h({h})应该含有PC({PC})')
    h = h[len(PC):]
    x, y = h[:64], h[64:]
    return int(x, 16), int(y, 16)

class SM2:
    def __init__(self, private_key: int = None, public_key: tuple[int, int] = None, p: int = default_p, a: int = default_a, b: int = default_b, G: tuple[int, int] = (default_Gx, default_Gy), n: int = default_n):
        """
        SM2构造函数
        参数：
            private_key: 私钥，如为None则随机
            public_key: 公钥，如为None则计算private_key·G
            p: 模数
            a: 椭圆曲线参数
            b: 椭圆曲线参数
            G: 基点，如为None则随机
            n: 椭圆曲线阶数
        """
        self.__p = p
        self.__a = a
        self.__b = b
        self.__GF = GF(p)
        self.__E = EllipticCurve(self.__GF, [a, b])
        self.__E.set_order(n)
        if G is None:
            self.__G = self.__E.random_point()
        else:
            self.__G = self.__E(G)
        if private_key is None:
            self.__private_key = random.randint(2 ** 255, 2 ** 256)
        else:
            self.__private_key = private_key
        if public_key is None:
            self.__public_key = self.__private_key * self.__G
        else:
            self.__public_key = self.__E(public_key)
    
    @property
    def private_key(self):
        """
        椭圆曲线私钥
        """
        return self.__private_key
    
    @property
    def d(self):
        """
        椭圆曲线私钥
        """
        return self.__private_key
    
    @property
    def public_key(self):
        """
        椭圆曲线公钥
        """
        return self.__public_key
    
    @property
    def P(self):
        """
        椭圆曲线公钥
        """
        return self.__public_key
    
    @property
    def a(self):
        """
        椭圆曲线参数
        """
        return self.__a
    
    @property
    def b(self):
        """
        椭圆曲线参数
        """
        return self.__b
    
    @property
    def p(self):
        """
        椭圆曲线模数
        """
        return self.__p

    @property
    def GF(self):
        """
        椭圆曲线有限域
        """
        return self.__GF
    
    @property
    def order(self):
        """
        椭圆曲线阶数
        """
        return self.E.order()
        
    @property
    def E(self):
        """
        椭圆曲线
        """
        return self.__E

    @property
    def G(self):
        """
        椭圆曲线基点
        """
        return self.__G

    def encrypt(self, M: bytes, mode = C1C2C3, k0: int = None):
        """
        椭圆曲线公钥加密
        参数：
            M: 消息
            mode: 密文模式，C1C2C3或者C1C3C2
            k0: 指定加密随机数
        返回值：
            以指定模式产生的密文C
        """
        klen = len(M)
        while True:
            if k0 is None:
                k = random.randint(1, self.order - 1)
            else:
                k = k0
                k0 = None
            C1 = k * self.G
            T1 = k * self.P
            t = sm3.KDF(cathex(T1[0], T1[1]), klen)
            if any(i > 0 for i in t):
                break
        C2 = [(Mi ^ ti) for Mi, ti in zip(M, t)]
        C3 = sm3.hash(cathex(T1[0], M, T1[1]))
        if mode == C1C2C3:
            C = cathex(b"\x04", C1[0], C1[1], bytes(C2), C3)
        elif mode == C1C3C2:
            C = cathex(b"\x04", C1[0], C1[1], C3, bytes(C2))
        else:
            raise RuntimeError('模式只能是C1C2C3或者C1C3C2')
        return C
    
    def decrypt(self, C: bytes, mode = C1C2C3):
        """
        椭圆曲线公钥解密
        参数：
            C: 以指定模式产生的密文C
            mode: 密文模式，C1C2C3或者C1C3C2
        返回值：
            明文消息
        """
        if C[0] != 0x04:
            raise RuntimeError('SM2的密文起始必须是0x04')
        C = C[1:]
        klen = len(C) - 96
        C1 = (int.from_bytes(C[:32], 'big'), int.from_bytes(C[32:64], 'big'))
        if C1 not in self.E:
            raise RuntimeError('SM2的密文C1点必须是椭圆上的点')
        if mode == C1C2C3:
            C1 = self.E(C1)
            C2 = C[64:-32]
            C3 = C[-32:]
        elif mode == C1C3C2:
            C1 = self.E(C1)
            C2 = C[96:]
            C3 = C[64:96]
        else:
            raise RuntimeError('模式只能是C1C2C3或者C1C3C2')

        T1 = self.d * C1
        t = sm3.KDF(cathex(T1[0], T1[1]), klen)
        if all(i == 0 for i in t):
            raise RuntimeError('SM2的KDF计算结果错误')
        M = [(Ci ^ ti) for Ci, ti in zip(C2, t)]
        M = bytes(M)
        u = sm3.hash(cathex(T1[0], M, T1[1]))
        if u != C3:
            raise RuntimeError('SM2消息哈希验证错误')
        return M
    
    def sign(self, e: bytes, k0: int = None):
        """
        椭圆曲线签名生成
        参数：
            e: 数据产生的哈希值
            k0: 指定加密随机数
        返回值：
            签名(r, s)
        """
        while True:
            if k0 is None:
                k = random.randint(1, self.order - 1)
            else:
                k = k0
                k0 = None
            T = k * self.G
            r = (int.from_bytes(e, 'big') + int(T[0])) % self.order
            if r == 0 or r + k == self.order:
                continue
            s = inverse_mod(1 + self.d, self.order) * (k - r * self.d) % self.order
            if s == 0:
                continue
            return (r, s)

    def ZHash(self, ID: bytes):
        """
        产生32字节的杂凑值Z
        输入：
            ID: 可辩别标识
        输出：
            32字节的杂凑值Z
        """
        ENTL = len(ID) * 8
        return sm3.hash(cathex(int(ENTL).to_bytes(2, 'big'), ID, self.a, self.b, self.G[0], self.G[1], self.P[0], self.P[1]))

    def raw_sign(self, M: bytes, ID: bytes, k0: int = None):
        """
        椭圆曲线签名生成
        参数：
            M: 消息
            ID: 可辩别标识
            k0: 指定加密随机数
        返回值：
            签名(r, s)
        """
        Z = self.ZHash(ID)
        e = sm3.hash(Z + M)
        return self.sign(e, k0)
        
    def verify(self, e: bytes, r: int, s: int):
        """
        椭圆曲线签名验证
        参数：
            e: 数据产生的哈希值
            r, s: 数字签名
        返回值：
            验证是否通过
        """
        if r < 1 or r > self.order - 1:
            return False
        if s < 1 or s > self.order - 1:
            return False
        t = (r + s) % self.order
        if t == 0:
            return False
        T = s * self.G + t * self.P
        R = (int.from_bytes(e, 'big') + int(T[0])) % self.order
        if R != r:
            return False
        return True
    
    def raw_verify(self, M: bytes, ID: bytes, r: int, s: int):
        """
        椭圆曲线签名验证
        参数：
            M: 消息
            ID: 可辩别标识
            r, s: 数字签名
        返回值：
            验证是否通过
        """
        Z = self.ZHash(ID)
        e = sm3.hash(Z + M)
        return self.verify(e, r, s)
        