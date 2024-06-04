import customtkinter as ctk
from customtkinter import filedialog
from tkinter import messagebox

from encryption import decrypt_file, encrypt_file
from generate_key import generate_key_iv
from translation import Translation

class App:
    def __init__(self, root):
        self.root = root
        self.root.title(Translation.TITLE.value)

        self.main_frame = ctk.CTkFrame(root)
        self.main_frame.pack(fill="both", expand=True)

        self.encrypt_button = ctk.CTkButton(self.main_frame, text=Translation.ENCRYPT.value, command=self.show_encrypt_page)
        self.encrypt_button.place(relx=0.5, rely=0.4, anchor=ctk.CENTER)
        # self.encrypt_button.pack(pady=10)

        self.decrypt_button = ctk.CTkButton(self.main_frame, text=Translation.DECRYPT.value, command=self.show_decrypt_page)
        self.decrypt_button.place(relx=0.5, rely=0.6, anchor=ctk.CENTER)
        # self.decrypt_button.pack(pady=10)

        self.encrypt_frame = ctk.CTkFrame(root)
        self.decrypt_frame = ctk.CTkFrame(root)

        self.setup_encrypt_page()
        self.setup_decrypt_page()

    def setup_encrypt_page(self):
        self.file_path_var = ctk.StringVar()
        self.new_file_name_var = ctk.StringVar()
        self.encryption_key_var = ctk.StringVar()

        ctk.CTkLabel(self.encrypt_frame, text=Translation.SELECT_FILE_ENCRYPT.value).pack(pady=5)
        ctk.CTkEntry(self.encrypt_frame, textvariable=self.file_path_var, width=400).pack(pady=5)
        ctk.CTkButton(self.encrypt_frame, text=Translation.BROWSE.value, command=self.browse_file).pack(pady=5)

        ctk.CTkLabel(self.encrypt_frame, text=Translation.ENTER_NEW_NAME.value).pack(pady=5)
        ctk.CTkEntry(self.encrypt_frame, textvariable=self.new_file_name_var, width=400).pack(pady=5)

        ctk.CTkButton(self.encrypt_frame, text=Translation.ENCRYPT.value, command=self.encrypt_file_action).pack(pady=10)
        
        self.encryption_key_label = ctk.CTkLabel(self.encrypt_frame, text="", textvariable=self.encryption_key_var)
        self.encryption_key_label.pack(pady=5)
        
        self.copy_key_button = ctk.CTkButton(self.encrypt_frame, text=Translation.COPY_KEY.value, command=self.copy_key_to_clipboard)
        self.copy_key_button.pack(pady=5)
        if self.encryption_key_var.get() == ctk.StringVar().get():
          self.copy_key_button.configure(state=ctk.DISABLED)
        
        ctk.CTkButton(self.encrypt_frame, text=Translation.BACK.value, command=self.show_main_page).pack(pady=5)

    def setup_decrypt_page(self):
        self.decrypt_file_path_var = ctk.StringVar()
        self.key_var = ctk.StringVar()
        self.new_decrypt_file_name_var = ctk.StringVar()

        ctk.CTkLabel(self.decrypt_frame, text=Translation.SELECT_FILE_DECRYPT.value).pack(pady=5)
        ctk.CTkEntry(self.decrypt_frame, textvariable=self.decrypt_file_path_var, width=400).pack(pady=5)
        ctk.CTkButton(self.decrypt_frame, text=Translation.BROWSE.value, command=self.browse_file_decrypt).pack(pady=5)

        ctk.CTkLabel(self.decrypt_frame, text=Translation.ENTER_DECRYPT_KEY.value).pack(pady=5)
        ctk.CTkEntry(self.decrypt_frame, textvariable=self.key_var, width=400).pack(pady=5)

        ctk.CTkLabel(self.decrypt_frame, text=Translation.ENTER_NEW_NAME.value).pack(pady=5)
        ctk.CTkEntry(self.decrypt_frame, textvariable=self.new_decrypt_file_name_var, width=400).pack(pady=5)

        ctk.CTkButton(self.decrypt_frame, text=Translation.DECRYPT.value, command=self.decrypt_file_action).pack(pady=10)
        ctk.CTkButton(self.decrypt_frame, text=Translation.BACK.value, command=self.show_main_page).pack(pady=5)

    def show_main_page(self):
        # Clear all the variables
        self.file_path_var.set("")
        self.new_file_name_var.set("")
        self.encryption_key_var.set("")
        self.decrypt_file_path_var.set("")
        self.key_var.set("")
        self.new_decrypt_file_name_var.set("")

        # Disable copy key button
        self.copy_key_button.configure(state=ctk.DISABLED)

        self.encrypt_frame.pack_forget()
        self.decrypt_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)

    def show_encrypt_page(self):
        self.main_frame.pack_forget()
        self.decrypt_frame.pack_forget()
        self.encrypt_frame.pack(fill="both", expand=True)

    def show_decrypt_page(self):
        self.main_frame.pack_forget()
        self.encrypt_frame.pack_forget()
        self.decrypt_frame.pack(fill="both", expand=True)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_path_var.set(file_path)

    def browse_file_decrypt(self):
        file_path = filedialog.askopenfilename()
        self.decrypt_file_path_var.set(file_path)

    def encrypt_file_action(self):
        file_path = self.file_path_var.get()
        new_file_name = self.new_file_name_var.get()

        if not file_path or not new_file_name:
            messagebox.showerror("Error", Translation.ERROR_FILE_NAME.value)
            return

        new_file_path = new_file_name if new_file_name.endswith('.enc') else new_file_name + '.enc'
        key, iv = generate_key_iv()

        try:
            encrypt_file(file_path, new_file_path, key, iv)
            self.encryption_key_var.set(f"Encryption Key: {key.hex()}")
            self.copy_key_button.configure(state=ctk.NORMAL)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.copy_key_button.configure(state=ctk.DISABLED)

    def decrypt_file_action(self):
        file_path = self.decrypt_file_path_var.get()
        key = self.key_var.get()
        new_file_name = self.new_decrypt_file_name_var.get()

        if not file_path or not key or not new_file_name:
            messagebox.showerror("Error", Translation.ERROR_FILE_NAME_KEY.value)
            return

        try:
            key_bytes = bytes.fromhex(key)
        except ValueError:
            messagebox.showerror("Error", Translation.ERROR_INVALID_FORMAT.value)
            return

        new_file_path = new_file_name

        try:
            decrypt_file(file_path, new_file_path, key_bytes)
            messagebox.showinfo("Success", Translation.SUCCESS_ENCRYPT.value)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def copy_key_to_clipboard(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.encryption_key_var.get().split(": ")[1])
        messagebox.showinfo("Copied", Translation.KEY_COPIED.value)


if __name__ == "__main__":
    root = ctk.CTk()
    root.geometry("540x380")
    app = App(root)
    root.mainloop()
    