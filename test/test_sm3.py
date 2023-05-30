from dzgm import sm3

msg = b'abc'
assert 0x66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0 == sm3.hash(msg)
msg = b'abcd' * 16
assert 0xdebe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732 == sm3.hash(msg)
