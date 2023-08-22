import tkinter as tk
from tkinter import filedialog
import customtkinter
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import random
import zlib
import os
import struct
import sys


class ProcessFile:
    
    EXTENSION = '.enmt'
    MAGIC_NUMBER = b"ENMT"
    VERSION = 1

    def __init__(self) -> None:
        pass

    def process(self, file_path: str, passphase: str):
        if not os.path.exists(file_path):
            return False, "File not found."
        try:
            self.set_key(passphase)
            file_type = self.get_file_extension(file_path)
            if file_type == self.EXTENSION:
                file_type, data = self.read_encmate_file(file_path)
                data = self.aes_decryption(self.hex_decryption(data))
                file_type = self.aes_decryption(
                    self.hex_decryption(file_type)).decode()
                new_file_path = self.change_extension(file_path, file_type)
                with open(new_file_path, 'wb') as f:
                    f.write(data)
                os.startfile(new_file_path)
            else:
                with open(file_path, 'rb') as f:
                    data = f.read()
                data = self.hex_encryption(self.aes_encryption(data))
                file_type = self.hex_encryption(
                    self.aes_encryption(file_type.encode()))
                new_file_path = self.change_extension(
                    file_path, self.EXTENSION)
                self.write_encmate_file(new_file_path, data, file_type)
            os.remove(file_path)
            return True, 'Processing Successful.'
        except ValueError:
            return False, 'Invalid passphase.'
        except TypeError:
            return False, 'Invalid file format or version.'
        except Exception as e:
            return False, str(e)

    def write_encmate_file(self, file_path: str, binary_data: bytes, file_type: bytes):
        metadata = struct.pack("I", len(file_type))
        header = struct.pack("4s I", self.MAGIC_NUMBER, self.VERSION)
        compressed_data = zlib.compress(binary_data)
        with open(file_path, "wb") as file:
            file.write(header)
            file.write(metadata)
            file.write(file_type)
            file.write(compressed_data)

    def read_encmate_file(self, file_path):
        with open(file_path, "rb") as file:
            magic_number, version_number = struct.unpack("4s I", file.read(8))
            if magic_number == self.MAGIC_NUMBER and version_number == self.VERSION:
                file_type_length = struct.unpack("I", file.read(4))[0]
                file_type = file.read(file_type_length)
                compressed_data = file.read()
                binary_data = zlib.decompress(compressed_data)
                return file_type, binary_data
            else:
                raise TypeError('Invalid file format or version')

    def set_key(self, input_string: str):
        self.seed = zlib.crc32(input_string.encode('utf-8'))
        random.seed(self.seed)
        hash_func = hashlib.sha256()
        hash_func.update(input_string.encode())
        hash_value = hash_func.digest()
        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=hashlib.sha256(input_string.encode()).digest(),
            length=16,
            backend=backend
        )
        self.KEY = kdf.derive(hash_value)

    def change_extension(self, file_path, new_extension):
        directory, base_filename = os.path.split(file_path)
        filename_without_extension, _ = os.path.splitext(base_filename)
        new_file_path = os.path.join(
            directory, filename_without_extension + new_extension)
        return new_file_path

    def get_file_extension(self, file_path: str):
        _, extension = os.path.splitext(file_path)
        return extension

    def aes_encryption(self, data: bytes):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.KEY),
                        modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_data

    def hex_encryption(self, data: bytes):
        hex_data = data.hex()
        random_numbers = [random.randint(0, 15) for _ in range(len(hex_data))]
        encrypted_data = ""
        for i in range(len(hex_data)):
            encrypted_data += hex(int(hex_data[i], 16) ^ random_numbers[i])[2:]
        return bytes.fromhex(encrypted_data)

    def aes_decryption(self, data: bytes):
        iv = data[:16]
        data = data[16:]
        cipher = Cipher(algorithms.AES(self.KEY),
                        modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data

    def hex_decryption(self, data: bytes):
        encrypted_data = data.hex()
        random_numbers = [random.randint(0, 15)
                          for _ in range(len(encrypted_data))]
        decrypted_data = ""
        for i in range(len(encrypted_data)):
            decrypted_data += hex(int(encrypted_data[i], 16)
                                  ^ random_numbers[i])[2:]
        return bytes.fromhex(decrypted_data)

class DecrypterApp(customtkinter.CTk):

    WIDTH = 800
    HEIGHT = 130
    NAME = "EncryptoMate"
    LOGO = "logo.ico"
    file_manager = ProcessFile()

    def __init__(self, file_path:str | None = None):
        super().__init__()
        self.title(self.NAME)
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        executable_dir = os.path.dirname(sys.argv[0])
        logo_path = os.path.join(executable_dir, self.LOGO)
        self.iconbitmap(logo_path)
        self.configure(bg="#1a1a1a")
        self.create_widgets(file_path)
        self.bind("/", lambda event: self.input_box.focus())
        self.bind("<Return>", lambda event: self.submit())
        self.bind("<Escape>", lambda event: self.destroy())

    def create_widgets(self, file_path):
        self.input_var = tk.StringVar()
        self.selected_file = tk.StringVar()
        self.input_var.set("")
        self.selected_file.set(file_path)

        self.input_box = customtkinter.CTkEntry(
            self, textvariable=self.input_var, width=(self.WIDTH*0.666)-20, height=self.HEIGHT/2 - 10)
        self.input_box.grid(row=0, column=0, padx=10, pady=10, columnspan=4)

        self.encrypt_button = customtkinter.CTkButton(
            self, text="Process File", command=self.submit, width=(self.WIDTH*0.333)-20, height=self.HEIGHT/2 - 10, font=customtkinter.CTkFont(size=15))
        self.encrypt_button.grid(row=0, column=4, padx=10, pady=10, columnspan=2)

        self.warning_label = customtkinter.CTkLabel(
            self, text='Enter passphase to decrypt :- ' + self.selected_file.get(), height=self.HEIGHT/2 - 20, width=self.WIDTH-20, font=customtkinter.CTkFont(size=15))
        self.warning_label.grid(row=1, column=0, padx=10, pady=5, columnspan=6)

    def reset(self):
        self.input_var.set("")
        sys.exit(0)

    def submit(self):
        selected_file_path = self.selected_file.get()
        
        input_text = self.input_var.get()
        if not input_text:
            self.show_warning("Please enter a passphase.", 'e')
            return
        
        response, message = self.file_manager.process(selected_file_path, input_text)

        if response:
            self.show_warning(message, 's')
            self.reset()
        else:
            self.show_warning(message, 'e')

    def show_warning(self, message, message_type = None):
        if message_type == 'e':
            self.warning_label.configure(text_color="#ff0000")
            message = 'Error :- ' + message
        elif message_type == 's':
            self.warning_label.configure(text_color="#00ff00")
            message = 'Success :- ' + message
        else:
            self.warning_label.configure(text_color="#ffffff") 
            message = 'Info :- ' + message

        self.warning_label.configure(text=message)

class MainApp(customtkinter.CTk):

    WIDTH = 800
    HEIGHT = 200
    NAME = "EncryptoMate"
    LOGO = "logo.ico"
    file_manager = ProcessFile()

    def __init__(self, file_path:str | None = None):
        super().__init__()
        self.title(self.NAME)
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        executable_dir = os.path.dirname(sys.argv[0])
        logo_path = os.path.join(executable_dir, self.LOGO)
        self.iconbitmap(logo_path)
        self.configure(bg="#1a1a1a")
        self.create_widgets(file_path)
        self.bind("/", lambda event: self.input_box.focus())
        self.bind("<Return>", lambda event: self.submit())
        self.bind("<space>", lambda event: self.select_file())
        self.bind("<Escape>", lambda event: self.destroy())

    def create_widgets(self, file_path):
        self.input_var = tk.StringVar()
        self.selected_file = tk.StringVar()
        self.input_var.set("")
        if file_path:
            self.selected_file.set("Selected File: " + file_path)
        else:
            self.selected_file.set("Select File")

        self.file_button = customtkinter.CTkButton(self, textvariable=self.selected_file, command=self.select_file,
                                                   width=self.WIDTH-20, height=self.HEIGHT/3 - 10, font=customtkinter.CTkFont(size=15))
        self.file_button.grid(row=0, column=0, padx=10, pady=10, columnspan=6)

        self.input_box = customtkinter.CTkEntry(
            self, textvariable=self.input_var, width=(self.WIDTH*0.666)-20, height=self.HEIGHT/3 - 10)
        self.input_box.grid(row=1, column=0, padx=10, pady=5, columnspan=4)

        self.encrypt_button = customtkinter.CTkButton(
            self, text="Process File", command=self.submit, width=(self.WIDTH*0.333)-20, height=self.HEIGHT/3 - 10, font=customtkinter.CTkFont(size=15))
        self.encrypt_button.grid(row=1, column=4, padx=10, pady=5, columnspan=2)

        self.warning_label = customtkinter.CTkLabel(
            self, text="Enter passphase & Select a file.", height=self.HEIGHT/3 - 20, width=self.WIDTH-20, font=customtkinter.CTkFont(size=15))
        self.warning_label.grid(row=2, column=0, padx=10, pady=5, columnspan=6)

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file.set("Selected File: " + file_path)

    def reset(self):
        self.input_var.set("")
        self.selected_file.set("Select File")

    def submit(self):
        selected_file_path = self.selected_file.get().replace("Selected File: ", "")
        if selected_file_path == "Select File":
            self.show_warning("Please select a file.", 'e')
            return

        if not selected_file_path:
            self.show_warning("No file selected.", 'e')
            return
        
        input_text = self.input_var.get()
        if not input_text:
            self.show_warning("Please enter a passphase.", 'e')
            return
        
        response, message = self.file_manager.process(selected_file_path, input_text)

        if response:
            self.show_warning(message, 's')
            self.reset()
        else:
            self.show_warning(message, 'e')

    def show_warning(self, message, message_type = None):
        if message_type == 'e':
            self.warning_label.configure(text_color="#ff0000")
            message = 'Error :- ' + message
        elif message_type == 's':
            self.warning_label.configure(text_color="#00ff00")
            message = 'Success :- ' + message
        else:
            self.warning_label.configure(text_color="#ffffff") 
            message = 'Info :- ' + message

        self.warning_label.configure(text=message)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        if os.path.exists(file_path):
            app = DecrypterApp(file_path)
        else:
            exit()
    else:
        app = MainApp()
    app.mainloop()

# pyinstaller --noconfirm --onedir --windowed --add-data "C:\Python311\Lib\site-packages;customtkinter/" --icon logo.ico --hidden-import cryptography --hidden-import cffi --hidden-import customtkinter --hidden-import darkdetect --hidden-import pycparser "EncMate.py"
