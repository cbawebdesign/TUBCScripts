import re
from firebase_admin import credentials, firestore, initialize_app

# Initialize Firestore
cred = credentials.Certificate('amidnight1a-firebase-adminsdk-hvumu-ba8bc4e0a5.json')
default_app = initialize_app(cred)
db = firestore.client()

def get_all_user_ids_from_db():
    """Fetch all user IDs from the Firestore database."""
    users_ref = db.collection('users')
    docs = users_ref.stream()
    return [doc.id for doc in docs if doc.to_dict().get('Active', False) and doc.to_dict().get('union', '') == 'COBA' and doc.to_dict().get('DeductionStatus', '') == 'BW']

def get_all_user_ids_from_file(file_path, pattern):
    """Fetch all user IDs from the PGP encrypted file."""
    user_ids = []

    # Open the decrypted file
    with open(file_path, 'r') as f:
        decrypted_data = f.read()

    # Extract user IDs from the decrypted data
    for line in decrypted_data.splitlines():
        user_ids.extend(pattern.findall(line))

    return user_ids

def find_difference(list1, list2):
    """Find elements in list1 that are not in list2."""
    return list(set(list1) - set(list2))

# Define the pattern for user IDs
pattern = re.compile(r'072(\d*)1')

# Get all user IDs from the database and the file
db_user_ids = get_all_user_ids_from_db()
print(f"DB User IDs: {db_user_ids}")  # Debug print

file_user_ids = get_all_user_ids_from_file('decrypted.txt', pattern)
print(f"File User IDs: {file_user_ids}")  # Debug print

def get_user_info(user_id):
    """Fetch the info of a user from the Firestore database."""
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()
    user_info = user_doc.to_dict()
    return {
        'LastName': user_info.get('LastName', ''),
        'FirstName': user_info.get('FirstName', ''),
        'union': user_info.get('union', ''),
        'Status': user_info.get('Active', False),
        'DeductionStatus': user_info.get('DeductionStatus', '')
    }

# Find user IDs in the database that are not in the file
difference = find_difference(db_user_ids, file_user_ids)

with open('ACTIVEUSERSMISSING2.txt', 'w') as f:
    for user_id in difference:
        user_info = get_user_info(user_id)
        f.write(f"{user_id}, {user_info['FirstName']}, {user_info['LastName']}, {user_info['union']}, {user_info['Status']}, {user_info['DeductionStatus']}\n")