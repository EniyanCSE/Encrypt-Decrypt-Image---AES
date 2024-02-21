import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import openpyxl
import os

def encrypt_key(key, master_password):
    # Derive a key from the master password using PBKDF2
    salt = os.urandom(16)
    derived_key = PBKDF2(master_password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)

    # Initialize AES cipher with the derived key
    cipher = AES.new(derived_key, AES.MODE_GCM)

    # Encrypt the key
    ciphertext, tag = cipher.encrypt_and_digest(key)

    return salt, ciphertext, tag, cipher.nonce

def encrypt_image(input_file, output_file, key, master_password):
    # Read the image file
    with open(input_file, 'rb') as f:
        image_data = f.read()

    # Initialize AES cipher
    cipher = AES.new(key, AES.MODE_CBC)

    # Pad the image data to make its length a multiple of 16 bytes (AES block size)
    padded_data = pad(image_data, AES.block_size)

    # Encrypt the padded data
    encrypted_data = cipher.encrypt(padded_data)

    # Write the initialization vector (IV) and the encrypted data to the output file
    with open(output_file, 'wb') as f:
        # Write the initialization vector (IV) to the output file
        f.write(cipher.iv)
        # Write the encrypted data to the output file
        f.write(encrypted_data)

    # Encrypt the key and save it to an Excel file
    salt, ciphertext, tag, nonce = encrypt_key(key, master_password)
    wb = openpyxl.Workbook()
    sheet = wb.active
    sheet["A1"] = "Salt"
    sheet["B1"] = salt.hex()
    sheet["A2"] = "Ciphertext"
    sheet["B2"] = ciphertext.hex()
    sheet["A3"] = "Tag"
    sheet["B3"] = tag.hex()
    sheet["A4"] = "Nonce"
    sheet["B4"] = nonce.hex()
    wb.save("encryption_key.xlsx")

    messagebox.showinfo("Success", "Image encrypted successfully.")

def decrypt_key(salt, ciphertext, tag, nonce, master_password):
    # Derive a key from the master password using PBKDF2
    derived_key = PBKDF2(master_password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)

    # Initialize AES cipher with the derived key and nonce
    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)

    # Decrypt the key
    key = cipher.decrypt_and_verify(ciphertext, tag)

    return key

def decrypt_image(input_file, output_file, master_password):
    # Read the encrypted data from the input file
    with open(input_file, 'rb') as f:
        # Read the initialization vector (IV)
        iv = f.read(16)  # IV is 16 bytes for AES
        # Read the rest of the encrypted data
        encrypted_data = f.read()

    # Read the salt, ciphertext, tag, and nonce from the Excel file
    wb = openpyxl.load_workbook("encryption_key.xlsx")
    sheet = wb.active
    salt_hex = sheet["B1"].value
    ciphertext_hex = sheet["B2"].value
    tag_hex = sheet["B3"].value
    nonce_hex = sheet["B4"].value
    salt = bytes.fromhex(salt_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    tag = bytes.fromhex(tag_hex)
    nonce = bytes.fromhex(nonce_hex)

    # Decrypt the key
    key = decrypt_key(salt, ciphertext, tag, nonce, master_password)

    # Initialize AES cipher with the provided IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the encrypted data
    decrypted_data = cipher.decrypt(encrypted_data)

    # Unpad the decrypted data
    unpadded_data = unpad(decrypted_data, AES.block_size)

    # Write the decrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(unpadded_data)

    messagebox.showinfo("Success", "Image decrypted successfully.")

def upload_file(is_encrypt):
    input_file = filedialog.askopenfilename(initialdir="/", title="Select file")
    if not input_file:
        return

    if is_encrypt:
        output_dir = filedialog.askdirectory(initialdir="/", title="Select directory to save encrypted file")
        if not output_dir:
            return
        output_file = os.path.join(output_dir, os.path.basename(input_file)[:-4] + '_encrypted.enc')
        key = get_random_bytes(32)  # 32 bytes = 256 bits
        master_password = b'my_strong_master_password'
        encrypt_image(input_file, output_file, key, master_password)
    else:
        output_dir = filedialog.askdirectory(initialdir="/", title="Select output directory")
        if not output_dir:
            return
        output_file = os.path.join(output_dir, os.path.basename(input_file)[:-11] + '.jpeg')  # Remove '_encrypted.enc' from filename
        master_password = b'my_strong_master_password'
        decrypt_image(input_file, output_file, master_password)

# GUI setup
root = tk.Tk()
root.title("Image Encryption and Decryption")

encrypt_button = tk.Button(root, text="Encrypt", command=lambda: upload_file(is_encrypt=True))
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt", command=lambda: upload_file(is_encrypt=False))
decrypt_button.pack(pady=10)

root.mainloop()
