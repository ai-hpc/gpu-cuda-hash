# Define the character set used for passwords
host_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

def password_to_index(password):
    index = 0
    base = len(host_charset)
    
    for char in password:
        index = index * base + host_charset.index(char)
    
    return index

def process_hash_file(input_file_path, output_file_path):
    with open(input_file_path, 'r') as infile, open(output_file_path, 'w') as outfile:
        for line in infile:
            # Assuming the password is the last 6 characters of each line
            password = line.strip()[-6:]
            index = password_to_index(password)
            outfile.write(f"{index}\n")

# Example usage
process_hash_file('hashcat-result.txt', 'password_indices.txt')
