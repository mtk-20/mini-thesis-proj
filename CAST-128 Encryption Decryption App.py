import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.Cipher import CAST
import os

class TextEncryptionDecryptionApp:
    
    def __init__(self, root):
        ttk.Label( text="Text File Encryption and Decryption Using CAST-128 Algorithm", font=('Times New Roman', 18, 'bold')).pack(pady=10)
        self.root = root
        self.root.title(" CAST-128 Encryption App ")
        self.root.geometry("950x750")
        self.root.resizable(True, True)

        self.style = ttk.Style()
        self.style.configure('TButton', font=('Arial', 12))
        self.style.configure('TLabel', font=('Arial', 12))
        self.style.configure('TEntry', font=('Arial', 12))

        self.key = None
        self.file_content = None

        self.create_tabs()
    
    def create_tabs(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(pady=10, expand=True, fill='both')

        encryption_frame = ttk.Frame(notebook)
        decryption_frame = ttk.Frame(notebook)

        encryption_frame.pack(fill='both', expand=True)
        decryption_frame.pack(fill='both', expand=True)

        notebook.add(encryption_frame, text='Encryption')
        notebook.add(decryption_frame, text='Decryption')

        self.create_encryption_page(encryption_frame)
        self.create_decryption_page(decryption_frame)
    
    def create_encryption_page(self, frame):
        
        frame.config(style='Custom.TFrame')
                
        ttk.Label(frame, text="Enter Secret Key (5 to 16 bytes):").pack(pady=5)
        self.key_entry_encrypt = ttk.Entry(frame, width=50, show="*")
        self.key_entry_encrypt.pack(pady=5)

        # Limit key entry to 16 characters
        self.key_entry_encrypt.config(validate="key", validatecommand=(self.root.register(self.limit_key_length), '%P', 16))

        self.file_path_encrypt = tk.StringVar()
        ttk.Entry(frame, width=50, textvariable=self.file_path_encrypt, state='readonly').pack(pady=5)
        
        browse_button_encrypt = ttk.Button(frame, text="Browse File", command=self.browse_file_encrypt)
        browse_button_encrypt.pack(pady=5)

        text_frame_encrypt = ttk.Frame(frame)
        text_frame_encrypt.pack(pady=5, fill='both', expand=True)

        self.file_content_display_encrypt = tk.Text(text_frame_encrypt, height=12, width=45, state='disabled')
        self.file_content_display_encrypt.pack(side=tk.LEFT, fill='both', expand=True,padx=10, pady=5)
        scrollb_file_encrypt = ttk.Scrollbar(text_frame_encrypt, command=self.file_content_display_encrypt.yview)
        scrollb_file_encrypt.pack(side=tk.LEFT, fill=tk.Y)
        self.file_content_display_encrypt['yscrollcommand'] = scrollb_file_encrypt.set

        self.encrypted_data_display = tk.Text(text_frame_encrypt, height=12, width=45, state='disabled')
        self.encrypted_data_display.pack(side=tk.LEFT, fill='both', expand=True,padx=10, pady=5)
        scrollb_encrypt = ttk.Scrollbar(text_frame_encrypt, command=self.encrypted_data_display.yview)
        scrollb_encrypt.pack(side=tk.LEFT, fill=tk.Y)
        self.encrypted_data_display['yscrollcommand'] = scrollb_encrypt.set

        button_frame_encrypt = ttk.Frame(frame)
        button_frame_encrypt.pack(pady=5, fill='x')

        encrypt_button_encrypt = tk.Button(button_frame_encrypt, text="Encrypt", command=self.encrypt_file, bg='#0040B0', fg='white', width=10, height=2)
        encrypt_button_encrypt.pack(side=tk.LEFT, expand=True, padx=10)

        delete_button_encrypt = tk.Button(button_frame_encrypt, text="Clear All", command=self.delete_encrypted_data, bg='#AA0808', fg='white', width=10, height=2)
        delete_button_encrypt.pack(side=tk.LEFT, expand=True, padx=10)

        save_button_encrypt = tk.Button(button_frame_encrypt, text="Save", command=self.save_encrypted_file, bg='#256F3A', fg='white', width=10, height=2)
        save_button_encrypt.pack(side=tk.LEFT, expand=True, padx=10)

    def create_decryption_page(self, frame):
        frame.config(style='Custom.TFrame')
         
        ttk.Label(frame, text="Enter Secret Key (5 to 16 bytes):").pack(pady=5)
        self.key_entry_decrypt = ttk.Entry(frame, width=50, show="*")
        self.key_entry_decrypt.pack(pady=5)

        # Limit key size
        self.key_entry_decrypt.config(validate="key", validatecommand=(self.root.register(self.limit_key_length), '%P', 16))

        self.file_path_decrypt = tk.StringVar()
        ttk.Entry(frame, width=50, textvariable=self.file_path_decrypt, state='readonly').pack(pady=5)
        
        browse_button_decrypt = ttk.Button(frame, text="Browse File", command=self.browse_file_decrypt)
        browse_button_decrypt.pack(pady=5)

        text_frame_decrypt = ttk.Frame(frame)
        text_frame_decrypt.pack(pady=5, fill='both', expand=True)

        self.file_content_display_decrypt = tk.Text(text_frame_decrypt, height=12, width=45, state='disabled')
        self.file_content_display_decrypt.pack(side=tk.LEFT, fill='both', expand=True,padx=10, pady=5)
        scrollb_file_decrypt = ttk.Scrollbar(text_frame_decrypt, command=self.file_content_display_decrypt.yview)
        scrollb_file_decrypt.pack(side=tk.LEFT, fill=tk.Y)
        self.file_content_display_decrypt['yscrollcommand'] = scrollb_file_decrypt.set

        self.decrypted_data_display = tk.Text(text_frame_decrypt, height=12, width=45, state='disabled')
        self.decrypted_data_display.pack(side=tk.LEFT, fill='both', expand=True,padx=10, pady=5)
        scrollb_decrypt = ttk.Scrollbar(text_frame_decrypt, command=self.decrypted_data_display.yview)
        scrollb_decrypt.pack(side=tk.LEFT, fill=tk.Y)
        self.decrypted_data_display['yscrollcommand'] = scrollb_decrypt.set

        button_frame_decrypt = ttk.Frame(frame)
        button_frame_decrypt.pack(pady=5, fill='x')

        decrypt_button_decrypt = tk.Button(button_frame_decrypt, text="Decrypt", command=self.decrypt_file, bg='#0040B0', fg='white', width=10, height=2)
        decrypt_button_decrypt.pack(side=tk.LEFT, expand=True, padx=10)

        delete_button_decrypt = tk.Button(button_frame_decrypt, text="Clear All", command=self.delete_decrypted_data, bg='#AA0808', fg='white', width=10, height=2)
        delete_button_decrypt.pack(side=tk.LEFT, expand=True, padx=10)

        save_button_decrypt = tk.Button(button_frame_decrypt, text="Save", command=self.save_decrypted_file, bg='#256F3A', fg='white', width=10, height=2)
        save_button_decrypt.pack(side=tk.LEFT, expand=True, padx=10)

        ttk.Label(text=" Supervisor - Daw Khin Moh Moh Win", font=('Times New Roman', 10, 'bold')).pack(side=tk.LEFT, expand=True, padx=10, pady=10)
        ttk.Label(text=" Co-Supervisor - Daw Than Win", font=('Times New Roman', 10, 'bold')).pack(side=tk.LEFT, expand=True, padx=10, pady=10)
        ttk.Label(text=" Student - Mg Myat Thukha (VI IT-20)", font=('Times New Roman', 10, 'bold')).pack(side=tk.LEFT, expand=True, padx=10, pady=10)
        
    def limit_key_length(self, new_value, max_length):
        return len(new_value) <= int(max_length)

    def browse_file_encrypt(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_encrypt.set(file_path)
            with open(file_path, 'rb') as file:
                self.file_content = file.read()
                self.file_content_display_encrypt.config(state='normal')
                self.file_content_display_encrypt.delete(1.0, tk.END)
                self.file_content_display_encrypt.insert(tk.END, self.file_content.decode('latin-1'))
                self.file_content_display_encrypt.config(state='disabled')

    def browse_file_decrypt(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_decrypt.set(file_path)
            with open(file_path, 'rb') as file:
                self.file_content = file.read()
                self.file_content_display_decrypt.config(state='normal')
                self.file_content_display_decrypt.delete(1.0, tk.END)
                self.file_content_display_decrypt.insert(tk.END, self.file_content.decode('latin-1'))
                self.file_content_display_decrypt.config(state='disabled')

    def encrypt_file(self):
        key = self.key_entry_encrypt.get().encode('utf-8')
        if not (5 <= len(key) <= 16):
            messagebox.showerror("Error", "Key must be between 5 and 16 bytes long.")
            return
        if self.file_content is None:
            messagebox.showerror("Error", "No file content to encrypt.")
            return

        # Using ECB mode
        cipher = CAST.new(key.ljust(16, b'\0'), CAST.MODE_ECB)
        padded_data = self.file_content.ljust((len(self.file_content) + 7) // 8 * 8, b'\0')
        ciphertext = cipher.encrypt(padded_data)

        # Prepend plaintext (first 16 bytes of the original file) to ciphertext for verification
        self.encrypted_data = self.file_content[:1] + ciphertext

        self.encrypted_data_display.config(state='normal')
        self.encrypted_data_display.delete(1.0, tk.END)
        self.encrypted_data_display.insert(tk.END, self.encrypted_data.decode('latin-1'))
        self.encrypted_data_display.config(state='disabled')

    def save_encrypted_file(self):
        if not hasattr(self, 'encrypted_data') or self.encrypted_data is None:
            messagebox.showerror("Error", "No encrypted data to save.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'wb') as file:
                file.write(self.encrypted_data)
            messagebox.showinfo("Saved", "File encrypted successfully.")

    def decrypt_file(self):
        key = self.key_entry_decrypt.get().encode('utf-8')
        if not (5 <= len(key) <= 16):
            messagebox.showerror("Error", "Key must be between 5 and 16 bytes long.")
            return
        if self.file_content is None:
            messagebox.showerror("Error", "No file content to decrypt.")
            return

        # Using ECB mode
        cipher = CAST.new(key.ljust(16, b'\0'), CAST.MODE_ECB) 
        ciphertext = self.file_content[1:]
        known_plaintext = self.file_content[:1]

        try:
            decrypted_data = cipher.decrypt(ciphertext).rstrip(b'\0')

            # Verify plaintext matches the start of the decrypted data
            if decrypted_data[:1] != known_plaintext:
                raise ValueError("Incorrect key for decryption.")

            self.decrypted_data_display.config(state='normal')
            self.decrypted_data_display.delete(1.0, tk.END)
            self.decrypted_data_display.insert(tk.END, decrypted_data.decode('utf-8', errors='ignore'))
            self.decrypted_data_display.config(state='disabled')
        except ValueError:
            messagebox.showerror("Error", "Incorrect key for decryption.")

    def save_decrypted_file(self):
        if not hasattr(self, 'decrypted_data_display') or self.decrypted_data_display.get("1.0", tk.END) == '\n':
            messagebox.showerror("Error", "No decrypted data to save.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(self.decrypted_data_display.get("1.0", tk.END))
            messagebox.showinfo("Saved", "File decrypted successfully.")

    def delete_encrypted_data(self):
        self.key_entry_encrypt.delete(0, tk.END)
        self.file_content_display_encrypt.config(state='normal')
        self.file_content_display_encrypt.delete(1.0, tk.END)
        self.file_content_display_encrypt.config(state='disabled')
        self.encrypted_data_display.config(state='normal')
        self.encrypted_data_display.delete(1.0, tk.END)
        self.encrypted_data_display.config(state='disabled')

    def delete_decrypted_data(self):
        self.key_entry_decrypt.delete(0, tk.END)
        self.file_content_display_decrypt.config(state='normal')
        self.file_content_display_decrypt.delete(1.0, tk.END)
        self.file_content_display_decrypt.config(state='disabled')
        self.decrypted_data_display.config(state='normal')
        self.decrypted_data_display.delete(1.0, tk.END)
        self.decrypted_data_display.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = TextEncryptionDecryptionApp(root)
    root.mainloop()