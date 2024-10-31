import os
import hashlib
import random
import string

def generate_salt_password_pairs(num_salts=10, pairs_per_salt=100):
    characters = string.ascii_letters + string.digits

    # Generate a list of random salts
    salts = [os.urandom(8).hex() for _ in range(num_salts)]

    with open("in.txt", "w") as in_file, open("out.txt", "w") as out_file:
        for salt in salts:
            for _ in range(pairs_per_salt):
                # Generate a random password of 6 characters using only letters and digits
                password = ''.join(random.choice(characters) for _ in range(6))

                # Combine salt and password
                combined = salt + password

                # Hash the combined string using SHA-256
                sha256_hash = hashlib.sha256(combined.encode()).hexdigest()

                # Write to in.txt (hash:salt only)
                in_file.write(f"{sha256_hash}:{salt}\n")

                # Write only values (hash:salt:password) to out.txt
                out_file.write(f"{sha256_hash}, {salt}, {password}\n")

# Call the function
generate_salt_password_pairs()
