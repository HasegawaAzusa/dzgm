from dzgm import sm4

M = bytes.fromhex('0123456789abcdeffedcba9876543210')
key = M
e = sm4.SM4(key)
assert e.encrypt(M) == bytes.fromhex('681edf34d206965e86b3e94f536e4246')

for _ in range(1000000):
    M = e.encrypt(M)

assert M == bytes.fromhex('595298c7c6fd271f0402f804c33d3f66')
