import tkinter as tk
from tkinter import Text, StringVar, Entry, Label, Button, GROOVE, END, Toplevel, messagebox
from encryption_logic import encrypt_message, decrypt_message

import subprocess

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.geometry("475x475")
        self.master.title("Cipherconnect")

        self.code = StringVar()

        Label(text="Enter text for Encryption and Decryption", fg="black", font=("calbri", 13)).place(x=10, y=10)
        self.text1 = Text(font="Robote 18", bg="white", relief=GROOVE, wrap=tk.WORD, bd=0)
        self.text1.place(x=10, y=10, width=355, height=100)

        Label(text="Enter secret key for Encryption and Decryption", fg="Black", font=("calbri", 13)).place(x=10, y=170)

        Entry(textvariable=self.code, width=20, bd=0, font=("arial", 25), show="*").place(x=10, y=195)

        Button(text="ENCRYPT", height="2", width=23, bg="red", fg="white", bd=0, command=self.encrypt).place(x=10, y=250)
        Button(text="DECRYPT", height="2", width=23, bg="green", fg="white", bd=0, command=self.decrypt).place(x=200, y=250)
        Button(text="RESET", height="2", width=50, bg="#1089ff", fg="white", bd=0, command=self.reset).place(x=10, y=300)
        Button(text="SAVE LOG", height="2", width=50, bg="#008080", fg="white", bd=0, command=self.save_log).place(x=10, y=350)

    def reset(self):
        
        self.code.set("")
        self.text1.delete(1.0, END)

    def decrypt(self):
        password = self.code.get()
        message = self.text1.get(1.0, END)
        
        if password == "1234":
            try:
                decrypted_message = decrypt_message(message)
                self.show_result("Decrypted", decrypted_message)
                self.save_to_log("Decryption Log", message, decrypted_message)
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Incorrect password")

    def encrypt(self):
        password = self.code.get()
        message = self.text1.get(1.0, END)

        if password == "1234":
            encrypted_message = encrypt_message(message)
            self.show_result("Encrypted", encrypted_message)
            self.save_to_log("Encryption Log", message, encrypted_message)
        else:
            messagebox.showerror("Error", "Incorrect password")

    def show_result(self, title, result):
        screen1 = Toplevel(self.master)
        screen1.title(title)
        screen1.geometry("400x200")
        screen1.configure(bg="#28a745")

        Label(screen1, text=f"{title} Message", font="arial", fg="white", bg="#28a745").place(x=10, y=0)
        text2 = Text(screen1, font="Rpbote 10", bg="white", relief=GROOVE, wrap=tk.WORD, bd=0)
        text2.place(x=10, y=40, width=380, height=150)

        text2.insert(END, result)

        Button(screen1, text="Open in Notepad", command=lambda: self.open_in_notepad(result)).place(x=10, y=160)

    def save_to_log(self, title, input_text, result):
        with open("encryption_log.txt", "a") as log_file:
            log_file.write(f"{title}\nInput Text: {input_text}\nResult: {result}\n\n")

    def open_in_notepad(self, result):
        with open("temp_result.txt", "w") as temp_file:
            temp_file.write(result)

        subprocess.Popen(["notepad.exe", "temp_result.txt"])

    def save_log(self):
        subprocess.Popen(["notepad.exe", "encryption_log.txt"])

def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
