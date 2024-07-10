import re
import os
import gnupg
from itertools import islice
from firebase_admin import credentials, firestore, initialize_app

# Replace with your Firebase credentials file
cred = credentials.Certificate('amidnight1a-firebase-adminsdk-hvumu-ba8bc4e0a5.json')

# Initialize the Firebase app (ensure it's called only once)
initialize_app(cred)
os.environ['GPG_TTY'] = os.ttyname(0)
os.environ['GPG_OPTS'] = '--pinentry-mode loopback'
# Get Firestore client
db = firestore.client()
gpg = gnupg.GPG()
def get_all_user_ids_from_db():
    """Fetch all user IDs from the Firestore database."""
    users_ref = db.collection('users')
    docs = users_ref.stream()
    return [(doc.id, doc.to_dict().get('Active', False)) for doc in docs]
def decrypt(gpg, file_path, key_data):
    """Decrypt a PGP encrypted file."""
    # Import the key
    import_result = gpg.import_keys(key_data)
    if import_result.count != 1:
        print(f"Key import failed: {import_result.summary()}")

    # Read and print the encrypted data
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    #print(f"Encrypted data: {encrypted_data}")
    
    # Decrypt the file
    try:
        with open(file_path, 'rb') as f:
            status = gpg.decrypt_file(f, always_trust=True, output='decrypted.txt')

        # Check if the decryption was successful
        if not status.ok:
            raise ValueError(f"Decryption failed: {status.stderr}")

        # Read the decrypted data
        with open('decrypted.txt', 'r') as f:
            decrypted_data = f.read()

        return decrypted_data
    except ValueError as e:
        print(e)
        return None

def get_all_user_ids_from_file(file_path, pattern):
    """Fetch all user IDs from the PGP encrypted file."""
    user_ids = []

    # Open the decrypted file
    with open(file_path, 'r') as f:
        decrypted_data = f.read()

    #print(f"Decrypted data: {decrypted_data}")  # Add this line

    # Read the decrypted data line by line
    for line in decrypted_data.splitlines():
        user_ids.extend(pattern.findall(line))

    return user_ids
# ... rest of the code ...
def find_difference(list1, list2):
    """Find elements in list1 that are not in list2."""
    return list(set(list1) - set(list2))

pattern = re.compile(r'^827(\d*)1')
premium_pattern = re.compile(r'\+([0-9]+)\+')
date_pattern = re.compile(r'(\d{4}-\d{2}-\d{2})')
# Get all user IDs from the database and the file
db_user_ids = get_all_user_ids_from_db()

key_data = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Ipswitch PGP v12.6

lQPEBGWoJhEBCAC0+YgszKb+RG8Qd9oI0QhamLX5F5kLD2HN3T6Uo9E4P0QZakt7
jbS4VFwF5USAfMJxUYHwxGfKL01n2NhdjRPHJtNrt/EyilgwhyLBDmIFkHGDa/do
+7MiIF/lZBwp7CCZ1B8xcW2HH4tGYAoq2coiU21qP/Ym4YNf3hUOkfg8rhU0ScO2
xWXo8tHJOAlYFzYlXlMr7LXVuaQlwX1MHC8YbpiUDwykDfronxPJgeMM/R6W2YxE
vra4T/LUxlX8lr1JCGHFX58jOYfEeDCp8/SdjRhin41Vtd1zg8MRODNi/rXaAPuF
Bhsjm5zKWOIvtY2kL5jPN+7kcerEP0xFkBABAAID/gkDApUkzldN0KLrYJeC25ZW
pWkc0ZMf3/UFFStnCp1SCqcdj/t5P46CzAaogOd0hqlXUkFOJY1GyGBEUGGzBBVQ
vivhYGnaP2kdp4cTi2BXCy0W/9AQ0EZlhxneeWLezohpYgPc7Ezk5G+3RzQ0nV6s
2e/9zPOVlHmIJVgv5kgJhrm+XLpewU9bt8M3HStW8Bv6spSwd/TwKKKDM21gSS0N
DSh22eBRjfrbFnu2iO3OLwlnvyS+pgkSixOf0WGGxQn4Dt+MWe6aeIYSdmEOU3IG
LDpE/kk5SFIK7f69TP6YIv2QQONivVCAxPMFiO/AWJXftjzh15+oUzty9mPZAWPG
WHkcGA1uWbeslUm/yZZ451F+PEHo9Rkskgrl/REqI+5qKZr5J7NDjBhKZzYnjxsR
bTVFjhPXzUdi1wnnnUbJYWB4Bt3+lbNhP+6RRz9EHzagxzj0SCk32U87q5TGFp8y
85wwJDvStn+wcfQ7SluVyef6kH+DTfiGFMw0/bZLD46XErWgv9gXXJjy/CeNYFjy
+wMmPw6D5kAwvwfnXJdmdk0rh1AXNzXI+FboCPYnMojmTQLOULEQxITdZNBOefrD
akjjgP5smf3Jdu3PMbizjc9k4LGJ4VYnDegvoWwr7fzjFgg+6GjE2/86OpOnhZUa
jog/uTr1GxLWABQk2wf47b5qDcOeeRdGk5sWYtPC0J8BPI17fAmzFTs1JgnaTCpg
AmGHNHFHsuQUnWh5NpoDo/MDlNO36laLh+rV1bRTQUJku8SqzRBjE9ByzhAI635Z
XNd7H7T24U/Fk2YnlNuFtHvEvmr2aqVPD4dzOBOTQOr0tsqLrSpUmElD1cHvihyK
7WWgqSuC1CH3eQwcTVRi1dIVe451d/TdG5/97yF5XVE8QSi1nV8T0br0qgJoqF6P
ntj7RXVFILQrVHJpc3RhdGUyMDI0IDxiaWxsaW5nQHRyaXN0YXRlYmVuZWZpdHMu
bmV0PokBOwQQAQIAJQUCZagmEQIZAQYLCQMCAQQIFQIBAwgJCgsFGwMAAAAFCQWk
64sACgkQh1Vt7k5ZcQijbAgAo3dSeGRhwP2kPnoL5E3s0Ch44fjniVMHpi9mebwB
7tk/z6zM9OQOmyw6aCWRprtGT9TMUutZci1psgKHpNwgz0hYftX2jowFUHB/G8wb
BfqikuDoyJKMNccFBybThp09gENJjy+IYp2j472nc5Pfoem7KfpM/QQ8Ho2em5tJ
TadcQSe8N6tKGvxxKk/LrR7ZvdFWFRgD8jtL0VwSGoD6L+iw+WMBSb5Fm7XwFYU/
34NrKxnLAgDwnzWg4yX2FcZI8pbcS9yDjK2fLENSSdJk+XxrG+PgJvuOLjK0PyQr
XB+iXfu7d0bUlUuH//eGQxYspXiIj9Q2OvLM+tvJ1cV4sp0DxARlqCYRAQgAzybS
xDRt8+iKkB3K3hp1kZuJvKHn5e8z91UKj0WQ5xjBZySfVuYbgpo2VnNx7lH+WN8b
VbrY+19afSj9Y0DyDIUoO4RnWE4z2HuwnU8afCvNW7w1ja27fu0CDvUyxaxGE8gi
wRN3TZgFA4DFLr4hwfqwE6ljN+EvV2fbsE/fB/b137Tv4SiZC/eb87KwwdSYw56t
WyzK+ZqvTyoW9j3LA3YTplNxQnN+KTKO248zXbsrfAGeLSl3QHnjyt1gM/V7vqmv
C3kW1Bx0GpDu8TVumTji4YhnU7+d/lRRTrnUEetJNUaf9zipGagsP6G7OrEh4fqg
2r5boWyUNGiJwSRWiwACA/4JAwIBjg5VGNimAWD5vk6jtOEc0hdtV2je/rb1jiIZ
aKhpoYHeTK1si1S56LJMcFKfU2q91iBg7aHuJam1PMGNqO6W+c1arXPZTByilMGY
wV11432QlrwbD8o/PLB5GYi6FJSCP4f5RxYiEyQQdsVXs7edv1TrjKbmv/go6LP5
PTvPKSwgSlcsfl9ykYbNJbP5o960vBCDtTfhxkBgQQNrZe3tu3mLgk6ZiOvmJN66
7+cnHWVulr3SPwFTOFdMT76YmxO334uEQ4+iRlfMwlTifcvBPUBanT335l7Fa/jP
HBNmyTAnZxYSGOmatO0aCa4X5pE9kWuVR4UVkG4bTlhMchLlp/Gdyr0zKWAq/4z9
V/0z06Lf0sPtyk5UM2telrmc6arLpjXcMTOzj4fPoIV4Y5JKuuVEa9A2wiwTKrJH
Qh05XxpmFx77rru4ZS9ykDJvvPsIvwhUEVeZXKcIiloeSiWLA2XMDqaqphVp8Mgy
fBG/XtYZPJGgeASh16k47mnG5weDIL1QTecrM3+YcpJKJ9y4iPF86tEc6L68GJ/K
kh4lLuyG3GVupcGItDv9PA7EC5lMJ/ibNbgQ0Gy2em0f73XwjKsAg+XG/FrOh6V9
JmMXzWBg/peCWOhnFfT6/eoXsIG1pYkqT8X51QYBiTsHfiYe5sIKm377mhg4z0/l
SHidYshVRNjghn5Sr4eX3JTtGW6SiiUS28K9zA4+fM3zvylxqoUUsuT+b+zJohfR
CixmbMz9q7FYkYJqiufLotNwvInZ0mGUQcBCwlLXYojQskYfLW7JaWWAwYyG67by
P9lnyTeAfIkbhiwLv8uuGhuDm6Tu9F3EWLXdeYToPEDok0/1/iGm5KtqQkoNOdcu
6bssOSyOPknJqDOIbQKV6CxYdDqSXLHA0OoVXGEf6pzDJsYWNJCCbSGJASIEGAEC
AAwFAmWoJhEFGwwAAAAACgkQh1Vt7k5ZcQgZ5gf/Z2WokLxygpeD+anDepHkZXZf
vGLUe13M+JcrzHQCwL6jEM6eOAwWKfqKIW9ALg83D3OgsftlgQrelgo/WfZX8c2d
hB+jwV5OM+qA5CoEy/tGigIUfDdFSSuqtWF3yBNnLlGBdcjxrfXxG+ZsgwWgXE3W
hTQUpBxMyHXP+LzSQB8fDY2rAHJn/RfbzeUaxWv0wEyAmovfdsyobxmjqcHiNzqp
TVaf4+N6BQuVcbqUUca+1BUm6AJrCcYvTYurZA8FYY0KI6yoI9ojcFAzYTiOqBjl
rqtUennLQR6+FQmTTspLxnag8ICcLC0+dcHb3Ar3K/lQHF5j/cQP29OR1qV0eQ==
=020
-----END PGP PRIVATE KEY BLOCK-----
"""


decrypted_data = decrypt(gpg, 'PEDT.TRIST.XGRPI662.PAY00489_20240706.txt.pgp', key_data)

with open('decrypted.txt', 'w') as f:
    f.write(str(decrypted_data))

file_user_ids = get_all_user_ids_from_file('decrypted.txt', pattern)
print(f"File User IDs: {file_user_ids}")

db_users = get_all_user_ids_from_db()
db_user_ids = [user_id for user_id, active in db_users if active]
print(f"Database User IDs: {db_user_ids}")

difference = find_difference(db_user_ids, file_user_ids)
print(f"Difference: {difference}")

with open('ACTIVEUSERSMISSING.txt', 'w') as f:
    for user_id in difference:
        f.write(f"{user_id}\n")

with open('decrypted.txt', 'r', encoding='utf-8') as file:
    for line in islice(file, 2000):
        user_ids = pattern.findall(line)

        for user_id in user_ids:
            premium_match = premium_pattern.search(line)
            if premium_match:
                premium = float(premium_match.group(1)) / 100  # Convert to decimal
            else:
                premium = 0.0

            date_match = date_pattern.search(line)
            if date_match:
                date = date_match.group(1)
            else:
                date = None

            last_name = line[11:26].strip()  # Adjusted indices for last name
            first_name = line[26:41].strip()[:-1]  # Adjusted indices for first name

           # Print to newgg.txt regardless of whether the user exists in the database
            with open('newgg.txt', 'a') as f:
                f.write(f"User ID: {user_id}, First Name: {first_name}, Premium: {premium}, Date: {date}, Last Name: {last_name}\n")

            if user_id and date is not None:
                user_doc = db.collection('users').document(user_id).get()
                if user_doc.exists:
                    user_data = user_doc.to_dict()
                    current_total_premium = user_data.get('CurrentTotalPremium', 0.0)
                    first_name = user_data.get('FirstName', '')
                    last_name = user_data.get('LastName', '')
                    is_active = user_data.get('Active', False)
                    if is_active and current_total_premium != premium:
                        with open('mismatched_premiums.txt', 'a') as f:
                            f.write(f"Premium mismatch for User ID {user_id}, First Name: {first_name}, Last Name: {last_name}. File premium: {premium}, Database(Current Total Premium) premium: {current_total_premium}\n")

                    # Update user data in Firestore
                     # Update user data in Firestore
                   

                    # Get DeductionStatus from Firestore
                    db_status = user_data.get('DeductionStatus', '')

                    # Assuming you have the DeductionStatus from the file
                    file_status = 'WE'  # replace this with actual status from file

                    # If the status in the database is "WE" but in the file it's "BW", write this user's data to "DeductionStatusChanges.txt"
                    if db_status == 'BW' and file_status == 'WE':
                        with open('DeductionStatusChanges.txt', 'a') as f:
                             f.write(f"User ID: {user_id}, First Name: {first_name}, Last Name: {last_name}, File DeductionStatus: {file_status}, Database DeductionStatus: {db_status}\n")  
                

                else:
                    # User doesn't exist in Firestore, write to UsersNotInDatabase.txt
                    with open('UsersNotInDatabase.txt', 'a') as f:
                            f.write(f"User ID: {user_id}, First Name: {first_name}, Premium: {premium}, Date: {date}, Last Name: {last_name}\n")

                    print(f"User ID {user_id} does not exist in Firestore. Printing to document.")

print("Data updated in Firebase.")