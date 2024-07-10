import gnupg

def import_key(gpg, key_file):
    """Import a public key."""
    with open(key_file, 'r') as f:
        key_data = f.read()
    import_result = gpg.import_keys(key_data)

    if import_result.count != 1:
        raise ValueError(f"Key import failed: {import_result.stderr}")

    print(f"Key imported successfully. Key ID: {import_result.fingerprints[0]}")

    return import_result.fingerprints[0]

def encrypt_file(gpg, file_path, recipient):
    """Encrypt a file with PGP for a recipient."""
    # Read the data to be encrypted
    with open(file_path, 'rb') as f:
        data = f.read()

    # Encrypt the data
    encrypted_ascii_data = gpg.encrypt(data, recipient)

    # Check if the encryption was successful
    if not encrypted_ascii_data.ok:
        raise ValueError(f"Encryption failed: {encrypted_ascii_data.stderr}")

    # Write the encrypted data to a file
    with open('encrypted.pgp', 'w') as f:
        f.write(str(encrypted_ascii_data))

    print("File encrypted successfully.")

# Initialize the GPG object with 'always' trust model
gpg = gnupg.GPG()
gpg.options = ['--trust-model', 'always']

# Path to the public key file
key_file = 'FISANYCNYCAPS HRBKey.asc'

# Import the public key
recipient = import_key(gpg, key_file)

# Path to the file to be encrypted
file_path = 'PNET.TRIST.XDPYLX10.A927_Sent06272024.txt'

# Encrypt the file
encrypt_file(gpg, file_path, recipient)