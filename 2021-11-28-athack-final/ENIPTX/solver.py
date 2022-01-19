from pwn import u32, p32, group, unhex, hexdump
from typing import List

key: List[int]
user_input: List[int]
matrix: List[List[int]]


def b(val: int) -> int:
    """cast to byte"""
    return val & 0xFF


def d(val: int) -> int:
    """cast to dword"""
    return val & 0xFFFFFFFF


def inv_xor_lookup(first_pass: bool) -> None:
    v1, v2, v3, v4, v5, v6, v7, v8 = key

    if first_pass:
        end = 3
    else:
        end = -1

    for i in range(7, end, -1):
        old = user_input[i]
        new = old ^ v4
        user_input[i] = new
        v17 = old + v1

        # 0xFFFFFF not dword
        v1 = matrix[0][b(v17)] ^ ((v17 >> 8) & 0xFFFFFF)
        v2 = matrix[1][b(v1 + v2)] ^ (((v1 + v2) >> 8) & 0xFFFFFF)
        v3 = matrix[2][b(v2 + v3)] ^ (((v2 + v3) >> 8) & 0xFFFFFF)
        v4 = matrix[3][b(v3 + v4)] ^ (((v3 + v4) >> 8) & 0xFFFFFF)
        v5 = matrix[4][b(v4 + v5)] ^ (((v4 + v5) >> 8) & 0xFFFFFF)
        v6 = matrix[5][b(v5 + v6)] ^ (((v5 + v6) >> 8) & 0xFFFFFF)
        v7 = matrix[6][b(v6 + v7)] ^ (((v6 + v7) >> 8) & 0xFFFFFF)
        v8 = matrix[7][b(v7 + v8)] ^ (((v7 + v8) >> 8) & 0xFFFFFF)


def inv_mangle_flag():
    # yes, these are supposed to be reversed
    v1 = u32(b'yDQ5')
    v2 = u32(b'97HD')
    v3 = u32(b'Z220')
    v4 = u32(b'rUbF')

    for i in range(0, 8, 1):
        old = user_input[i]
        new = v4 ^ old
        user_input[i] = new

        v1 = matrix[0][b(old + v1)] ^ (((old + v1) >> 8) & 0xFFFFFF)
        v2 = matrix[1][b(v1 + v2)] ^ (((v1 + v2) >> 8) & 0xFFFFFF)
        v3 = matrix[2][b(v2 + v3)] ^ (((v2 + v3) >> 8) & 0xFFFFFF)
        v4 = matrix[3][b(v3 + v4)] ^ (((v3 + v4) >> 8) & 0xFFFFFF)


def show():
    """small helper function for debugging"""
    print(hexdump(user_input))


# extracted from the binary
target = unhex("617E57049FD9B03B9AB986A2CE6863C66F508493614932C70BB5F5A41B62FCDE")


# dumped memory section
with open("eniptx_000000000064A000.bin", "rb") as f:
    f.seek(0x3c60)
    output = list(map(u32, group(4, f.read(0x20))))
    key = list(map(u32, group(4, f.read(0x20))))

    # load user_input and split into integers
    user_input = list(map(u32, group(4, f.read(0x20))))

    # override user_input with target vector
    user_input = list(map(u32, group(4, target)))

    # load matrix and split into 8 sub arrays of 256 * sizeof(uint32_t) => 1024 bytes
    matrix = group(1024, f.read(1024 * 8))
    matrix = [list(map(u32, group(4, subarray))) for subarray in matrix]


show()
inv_xor_lookup(first_pass=False)
show()
inv_mangle_flag()
show()
inv_xor_lookup(first_pass=True)
show()

print("original input:")
print(b"".join(map(lambda x: x[::-1], map(p32, user_input))))
