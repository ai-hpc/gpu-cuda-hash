import hashlib
import time

# Method 1: Using a class to handle salt
class SaltedSHA256:
    def __init__(self, salt):
        self.salt = salt

    def hash_with_salt(self, password):
        combined = self.salt + password
        return hashlib.sha256(combined.encode()).hexdigest()

# Method 2: Directly combining salt and password each time
def hash_with_salt_direct(salt, password):
    combined = salt + password
    return hashlib.sha256(combined.encode()).hexdigest()

# Benchmarking function
def benchmark(salt, base_password, attempts):
    # Method 1
    salted_sha256 = SaltedSHA256(salt)
    start_time = time.time()
    for i in range(attempts):
        password_attempt = f"{base_password}{i}"
        hashed_attempt = salted_sha256.hash_with_salt(password_attempt)
    method1_time = time.time() - start_time

    # Method 2
    start_time = time.time()
    for i in range(attempts):
        password_attempt = f"{base_password}{i}"
        hashed_attempt = hash_with_salt_direct(salt, password_attempt)
    method2_time = time.time() - start_time

    print(f"Method 1 (Class): {method1_time:.6f} seconds")
    print(f"Method 2 (Direct): {method2_time:.6f} seconds")

# Example usage
salt = "fixed_salt"
base_password = "password"
attempts = 100000000  # Number of password attempts

benchmark(salt, base_password, attempts)
