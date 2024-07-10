import paramiko
import os
import logging
import re
from datetime import datetime
from gnupg import GPG
from google.cloud import storage, firestore, secretmanager
from firebase_admin import credentials, initialize_app
import shutil

# Initialize logging
logging.basicConfig(level=logging.INFO)

# Initialize Firebase
logging.info("Initializing Firebase...")
cred = credentials.Certificate('mobiledevtests-e9c70-firebase-adminsdk-a12uf-7d596b59b3.json')
app = initialize_app(cred, {
    'storageBucket': 'mobiledevtests-e9c70.appspot.com'  # replace with your Firebase Storage bucket URL
})
logging.info("Firebase initialized.")

# Function to retrieve secrets from Google Secret Manager
def get_secret(project_id, secret_id):
    logging.info(f"Retrieving secret: {secret_id}")
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(name=name)
    logging.info(f"Secret {secret_id} retrieved successfully.")
    return response.payload.data.decode('UTF-8')

# Initialize GPG
gpg = GPG()

def retrieve_files_from_server():
    logging.info("Starting file retrieval...")

    project_id = 'mobiledevtests-e9c70'  # Your Firebase or Google Cloud Project ID
    bucket_name = 'mobiledevtests-e9c70.appspot.com'  # Your Firebase Storage bucket name
    ssh_key_secret_id = 'my-ssh-key'
    ssh_password_secret_id = 'ssh-password'
    lftp_password_secret_id = 'lftp-password'
    pgp_private_key_secret_id = 'pgp-private-key'
    pgp_passphrase_secret_id = 'pgp-passphrase'
    droplet_ip = '159.223.129.121'
    droplet_user = 'root'
    remote_path = '/OUTGOING'
    local_path = './downloaded_files'  # Adjusted local path to the correct directory
    droplet_tmp_path = '/root/downloaded_files'

    # Retrieve secrets from Google Secret Manager
    logging.info("Retrieving secrets...")
    try:
        private_key = get_secret(project_id, ssh_key_secret_id)
        ssh_password = get_secret(project_id, ssh_password_secret_id)
        lftp_password = get_secret(project_id, lftp_password_secret_id)
        pgp_private_key = get_secret(project_id, pgp_private_key_secret_id)
        pgp_passphrase = get_secret(project_id, pgp_passphrase_secret_id)
    except Exception as e:
        logging.error(f"Error retrieving secrets: {e}")
        return

    logging.info("Secrets retrieved.")

    # Write private key to a temporary file
    key_path = os.path.join('/tmp', 'id_rsa')
    try:
        with open(key_path, 'w') as key_file:
            key_file.write(private_key)
        os.chmod(key_path, 0o600)
        logging.info("Private key written to temporary file.")
    except Exception as e:
        logging.error(f"Error writing private key to file: {e}")
        return

    # Ensure the key file exists
    if not os.path.isfile(key_path):
        logging.error(f"Key file does not exist: {key_path}")
        return

    # Import the PGP private key
    import_result = gpg.import_keys(pgp_private_key)
    logging.info(f"GPG import results: {import_result.results}")
    keys = gpg.list_keys(secret=True)
    logging.info(f"Keys in GPG keyring: {keys}")

    # Connect to the droplet using SSH
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=droplet_ip, username=droplet_user, key_filename=key_path, password=ssh_password)
        logging.info("Connected to the droplet via SSH.")
    except Exception as e:
        logging.error(f"Error connecting via SSH: {e}")
        return

    # Ensure the droplet_tmp_path directory exists
    try:
        stdin, stdout, stderr = ssh_client.exec_command(f"mkdir -p {droplet_tmp_path}")
        stdout.channel.recv_exit_status()  # Wait for the command to complete
        logging.info(f"Ensured {droplet_tmp_path} directory exists on the droplet.")
    except Exception as e:
        logging.error(f"Error creating directory on the droplet: {e}")
        ssh_client.close()
        return

    # Execute the lftp command to mirror files from the remote server to the DO droplet
    lftp_command = (
        f"lftp -p 18003 -e 'set ftp:passive-mode true; "
        f"mirror --include-glob PEDT.TRIST.XDEXP100.ERR.EXTR.A927_*.txt.pgp {remote_path} {droplet_tmp_path}; quit' "
        f"-u tristate_hm,{lftp_password} a127-hrfts.nyc.gov"
    )
    try:
        stdin, stdout, stderr = ssh_client.exec_command(lftp_command)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')

        logging.info(f"lftp mirror output: {output}")
        if error:
            logging.error(f"lftp mirror error: {error}")
            ssh_client.close()
            return

        logging.info("Files mirrored to DO droplet successfully.")
    except Exception as e:
        logging.error(f"Error executing lftp mirror command: {e}")
        return

    # SCP the mirrored files from the DO droplet to the local path on the local machine
    try:
        sftp = ssh_client.open_sftp()
        for file_name in sftp.listdir(droplet_tmp_path):
            if re.match(r'PEDT\.TRIST\.XDEXP100\.ERR\.EXTR\.A927_\d{8}\.txt\.pgp', file_name):
                remote_file_path = os.path.join(droplet_tmp_path, file_name)
                local_file_path = os.path.join(local_path, file_name)
                logging.info(f"Copying {remote_file_path} to {local_file_path}...")
                sftp.get(remote_file_path, local_file_path)
        sftp.close()
        logging.info("Files copied from DO droplet to local machine successfully.")
    except Exception as e:
        logging.error(f"Error during SCP: {e}")
        ssh_client.close()
        return

    ssh_client.close()
    logging.info("SSH connection closed.")

    # Process and decrypt files locally
    process_files(local_path, pgp_passphrase)

def process_files(local_path, pgp_passphrase):
    logging.info(f"Processing files in {local_path}...")

    # Initialize Firebase Storage and Firestore clients
    storage_client = storage.Client()
    bucket = storage_client.bucket('mobiledevtests-e9c70.appspot.com')
    db = firestore.Client()

    try:
        for file_name in os.listdir(local_path):
            if re.match(r'PEDT\.TRIST\.XDEXP100\.ERR\.EXTR\.A927_\d{8}\.txt\.pgp', file_name):
                logging.info(f"Processing file: {file_name}")
                input_file = os.path.join(local_path, file_name)
                decrypted_file_name = file_name.replace('.pgp', '')
                decrypted_file_path = os.path.join(local_path, decrypted_file_name)

                if os.path.getsize(input_file) > 0:
                    with open(input_file, 'rb') as f:
                        status = gpg.decrypt_file(f, passphrase=pgp_passphrase, output=decrypted_file_path)

                    if status.ok:
                        logging.info(f"Decryption successful for file: {file_name}")

                        # Ensure the decrypted file has a .txt extension
                        if not decrypted_file_path.endswith('.txt'):
                            txt_file_path = decrypted_file_path + '.txt'
                            os.rename(decrypted_file_path, txt_file_path)
                            decrypted_file_path = txt_file_path

                        # Check if the decrypted file is not empty before uploading
                        if os.path.getsize(decrypted_file_path) > 0:
                            # Upload decrypted files to Firebase Storage
                            upload_to_firebase(decrypted_file_path, bucket, db, os.path.basename(decrypted_file_path))
                        else:
                            logging.info(f"Decrypted file is empty: {decrypted_file_path}")
                            print(f"Decrypted file is empty: {decrypted_file_path}")

                    else:
                        logging.error("File decryption failed.")
                        logging.error(f"Status: {status.status}")
                        logging.error(f"Stderr: {status.stderr}")
                else:
                    logging.info(f"File is empty: {file_name}")
                    print(f"File is empty: {file_name}")
    except Exception as e:
        logging.error(f"Error during file processing: {e}")

def upload_to_firebase(decrypted_file, bucket, db, file_name):
    try:
        logging.info(f"Uploading decrypted file: {file_name}")
        print(f"Uploading decrypted file: {file_name}")
        # Upload the decrypted file to Firebase Storage
        blob = bucket.blob(file_name)
        with open(decrypted_file, 'rb') as my_file:
            blob.upload_from_file(my_file)
        # Make the file publicly accessible and get the download URL
        blob.make_public()
        download_url = blob.public_url
        # Add a new post to the Firestore database
        db.collection('posts').add({
            'categories': 'ERROR_FILES',
            'downloadURL': download_url,
            'image': file_name,
            'isEncrypted': False,
            'isRead': False,
            'timestamp': datetime.now(),
            'union': 'MISC',
            'users': ['admin01']
        })
        logging.info(f"Uploaded decrypted file: {file_name}")
        print(f"Uploaded decrypted file: {file_name}")
    except Exception as e:
        logging.error(f"Error uploading decrypted files to Firebase Storage: {e}")
        print(f"Error uploading decrypted files to Firebase Storage: {e}")

if __name__ == "__main__":
    retrieve_files_from_server()
    logging.info("Script execution completed.")
