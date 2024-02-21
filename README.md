# Image Encryption and Decryption using AES

This Python application allows users to encrypt and decrypt image files using the Advanced Encryption Standard (AES) algorithm. It provides a graphical user interface (GUI) built with Tkinter for easy interaction.

## Requirements

- Python 3.x
- Crypto library (install via `pip install pycryptodome`)
- openpyxl library (install via `pip install openpyxl`)

## Usage

1. Clone the repository to your local machine:

    ```bash
    git clone https://github.com/EniyanCSE/Encrypt-Decrypt-Image---AES.git
    ```

2. Navigate to the project directory:

    ```bash
    cd encryption-decryption
    ```

3. Run the application:

    ```bash
    python app.py
    ```

4. The GUI will open, presenting two buttons: "Encrypt" and "Decrypt".
   
5. To encrypt an image:
    - Click on the "Encrypt" button.
    - Select the image file you want to encrypt.
    - Choose the directory where you want to save the encrypted file.
    - Enter a master password when prompted.
    - The encrypted image file and the encryption key will be saved in the specified directory.

6. To decrypt an encrypted image:
    - Click on the "Decrypt" button.
    - Select the encrypted image file.
    - Choose the directory where you want to save the decrypted image.
    - Enter the master password used during encryption when prompted.
    - The decrypted image file will be saved in the specified directory.

## Note

- Make sure to remember the master password used for encryption, as it will be required for decryption.
- The encryption key is stored in an Excel file (`encryption_key.xlsx`), which is also encrypted using the master password.
