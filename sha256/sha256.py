def right_rotate(value, amount):
    return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF

class SHA256Debug:
    INITIAL_HASH = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    def __init__(self):
        self.reset()

    def reset(self):
        self.hash_values = self.INITIAL_HASH.copy()
        print("\nInitial Hash Values:")
        print(' '.join(f'{h:08x}' for h in self.hash_values))

    def _pad_message(self, message: bytes) -> bytes:
        original_byte_len = len(message)
        original_bit_len = original_byte_len * 8
        
        # Add padding bits
        message += b'\x80'
        message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
        message += original_bit_len.to_bytes(8, byteorder='big')
        
        print("\nPadded Message (hex):")
        print(' '.join(f'{b:02x}' for b in message))
        return message

    def _process_block(self, block: bytes, hash_values: list) -> list:
        # Initialize message schedule array
        w = [int.from_bytes(block[i:i+4], byteorder='big') for i in range(0, 64, 4)]
        
        # Print initial message block
        print("\nMessage Block (512 bits):")
        print(' '.join(f'{word:08x}' for word in w[:16]))
        
        # Extend the message schedule
        print("\nMessage Schedule Extension:")
        for i in range(16, 64):
            s0 = right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)
            print(f"W[{i:2d}] = {w[i]:08x}")
        
        # Initialize working variables
        a, b, c, d, e, f, g, h = hash_values
        print("\nInitial Working Variables:")
        print(f"a={a:08x} b={b:08x} c={c:08x} d={d:08x}")
        print(f"e={e:08x} f={f:08x} g={g:08x} h={h:08x}")
        
        # Compression function main loop
        print("\nCompression Function Rounds:")
        for i in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + self.K[i] + w[i]) & 0xFFFFFFFF
            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
            
            print(f"Round {i:2d}: {a:08x} {b:08x} {c:08x} {d:08x} {e:08x} {f:08x} {g:08x} {h:08x}")
        
        # Compute intermediate hash values
        new_hash = [(x + y) & 0xFFFFFFFF for x, y in zip(hash_values, [a, b, c, d, e, f, g, h])]
        print("\nIntermediate Hash Values:")
        print(' '.join(f'{h:08x}' for h in new_hash))
        return new_hash

    def hash(self, message: bytes) -> str:
        print("\nInput Message:", message)
        print("Input Message (hex):", ' '.join(f'{b:02x}' for b in message))
        
        # Pad message
        padded_message = self._pad_message(message)
        
        # Process message in 512-bit blocks
        for i in range(0, len(padded_message), 64):
            block = padded_message[i:i+64]
            self.hash_values = self._process_block(block, self.hash_values)
        
        # Produce final hash
        final_hash = ''.join(f'{h:08x}' for h in self.hash_values)
        print("\nFinal Hash:", final_hash)
        return final_hash

def main():
    # Test vector
    message = b'jNdRTA' + bytes.fromhex('0e8b22dfc589e87a')
    sha256 = SHA256Debug()
    hash_result = sha256.hash(message)
    
    # Expected hash for verification
    expected = "8205de54cb323e67fb2c6274a2ad4bd09cd81624a03b8482fb6192ee2216532d"
    print("\nVerification:")
    print(f"Expected: {expected}")
    print(f"Computed: {hash_result}")
    print(f"Status: {'MATCH' if hash_result == expected else 'MISMATCH'}")

if __name__ == "__main__":
    main()
