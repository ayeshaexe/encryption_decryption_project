# hashlib 
import hashlib
# cryptography
from cryptography.fernet import Fernet
print(hashlib.algorithms_available) 
# this will print all the different hashing algoithms that we can use but some of them won't be avalible for all OS
print(hashlib.algorithms_guaranteed)
# this will print the guaranteed hashing algorithems that work on all OS SHA256(is secure)

h = hashlib.sha3_256()
print(h)

h = hashlib.new("SHA256")
h.update(b"Hello world")
print(h.digest()) # it outputs raw bytes 
print(h.hexdigest()) # it outputs hexa-decimal representation (recommended way) (a/f to 0-9)


hash_obj = hashlib.sha256(b"Hello")
binary_hash = hash_obj.digest()    
hex_hash = hash_obj.hexdigest()  

# Convert hex back to bytes (if needed)
bytes.fromhex(hex_hash) == binary_hash

print("---------------------------------------------")
print("Password using hashing")
h = hashlib.new("SHA256")
correct_password = "MyPassword123567"
h.update(correct_password.encode())
password_hash = h.hexdigest()
# print("Password: ",password_hash) # uncomment this to see the hash

user_input = input("Enter password to login: ")
h = hashlib.new("SHA256")
h.update(user_input.encode())
user_password = h.hexdigest()
# print("User hash: ", user_password) # uncomment this to see the hash


if password_hash == user_password:
    print("Loged In!")
else:
    print("Wrong Password!")


name = "ayesha"
hashing_name = hashlib.sha256(name.encode())
print(hashing_name) # <sha3_256 _hashlib.HASH object @ 000006266262 => the number are random and it's called Hash object
print(hashing_name.digest()) # returns the hash as raw bytes
print(hashing_name.hexdigest()) # hexadecimal representation a/f and 0-9 recommended way


print("--------------------------------------")
mess = "hello"
hashing_mess = hashlib.sha256(mess.encode())
print(hashing_mess)

# i was thinking to decode it but i asked ai that can i decode a hashing value the answer was no !
# because hashing is not reversible, it is mathetically impossible
# but if you want to decode then use encryption to reverse your value using python module cyrptography

# This example will show both encode and decode
KEY = Fernet.generate_key()
cipher = Fernet(KEY)
# print(cipher)
name = b"Ayesha"
encrypted_data = cipher.encrypt(name)
# print(encrypted_data) will print the encrypt value
decryption = cipher.decrypt(encrypted_data)
print(decryption) # b'Ayesha'
print(decryption.decode()) # Ayesha
