from tkinter import *
from tkinter import messagebox
from PIL import ImageTk, Image
from random import choice, randint, shuffle
import sqlite3, hashlib
from functools import partial
import uuid
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import pyperclip

# ---------------------------- Encryption ------------------------------- #
backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = 0


def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# ---------------------------- DATABASE ------------------------------- #
with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS master_password(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL
);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL
);
""")


# ---------------------------- HASH ------------------------------- #
def hashPassword(input):
    return hashlib.sha256(input).hexdigest()


# ---------------------------- UI SETUP ------------------------------- #
def clean():
    for widget in windows.winfo_children():
        widget.destroy()


def create_Master_Key():
    img = ImageTk.PhotoImage(Image.open("logo.png"))
    logo = Label(windows, image=img)
    logo.place(x=235, y=5)

    # label
    master_pw = Label(windows, text="Create Master Password", font=("Verdana", 15))
    master_pw.place(x=250, y=210)
    re_master_pw = Label(windows, text="Re-enter Master Password", font=("Verdana", 15))
    re_master_pw.place(x=250, y=270)

    # # Entry
    pw = Entry(windows, width=18, show="*")
    pw.place(x=258, y=240)
    pw.focus()
    re_pw = Entry(windows, width=18, show="*")
    re_pw.place(x=258, y=300)

    def savePassword(event=None):
        if pw.get() == re_pw.get():
            sql = "DELETE FROM master_password WHERE id = 1"
            cursor.execute(sql)

            hashed_password = hashPassword(pw.get().encode("utf-8"))
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode("utf-8"))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(pw.get().encode()))

            insert_password = """INSERT INTO master_password(password, recoveryKey)
            VALUES(?, ?)"""
            cursor.execute(insert_password, [(hashed_password), (recoveryKey)])
            db.commit()
            for widget in windows.winfo_children():
                widget.destroy()
            confirmScreen(key)
        else:
            error = Label(windows, text="Password not match!", font=("Verdana", 13))
            error.place(x=275, y=370)

    # Button
    save = Button(windows, text="Save", font=("Verdana", 13), command=savePassword)
    save.place(x=310, y=335)

    # bind
    windows.bind("<Return>", savePassword)

    windows.mainloop()


def confirmScreen(key):
    img = ImageTk.PhotoImage(Image.open("logo.png"))
    logo = Label(windows, image=img)
    logo.place(x=235, y=5)

    lbl = Label(windows, text="Save this key to be able to recover account", font=("Verdana", 15))
    lbl.place(x=180, y=220)

    lbl2 = Label(windows, text=key, font=("Verdana", 13))
    lbl2.place(x=207, y=250)

    def copyKey():
        pyperclip.copy(lbl2.cget("text"))
        lbl3 = Label(windows, text="Copied!", font=("Verdana", 13))
        lbl3.place(x=305, y=310)

    copy_button = Button(windows, text="Copy Key", font=("Verdana", 13), command=copyKey)
    copy_button.place(x=280, y=273)

    goToMenu_button = Button(windows, text="Go to Menu", font=("Verdana", 14), command=mainPage)
    goToMenu_button.place(x=275, y=340)

    windows.mainloop()


def logInScreen():
    img = ImageTk.PhotoImage(Image.open("logo.png"))
    logo = Label(windows, image=img)
    logo.place(x=235, y=5)

    # label
    master_pw = Label(windows, text="Enter Master Password", font=("Verdana", 15))
    master_pw.place(x=255, y=220)

    # Entry
    pw = Entry(windows, width=15, show="*")
    pw.place(x=270, y=250)
    pw.focus()

    def getMasterPassword():
        check_hashed_password = hashPassword(pw.get().encode("utf-8"))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(pw.get().encode()))
        cursor.execute("SELECT * FROM master_password WHERE id = 1 AND password = ?", [(check_hashed_password)])
        return cursor.fetchall()

    def checkPassword(event=None):
        match = getMasterPassword()

        if match:
            for widget in windows.winfo_children():
                widget.destroy()
            mainPage()
        else:
            wrong_label = Label(windows, text="Wrong Password!", font=("Verdana", 13))
            wrong_label.place(x=285, y=355)
            pw.delete(0, "end")

    # button
    login_button = Button(windows, text="Login", width=5, font=("Verdana", 13), command=checkPassword)
    login_button.place(x=302, y=285)
    reset_pw = Button(windows, text="Reset Password", font=("Verdana", 13), command=resetScreen)
    reset_pw.place(x=275, y=318)

    # bind
    windows.bind_all("<Return>", checkPassword)

    windows.mainloop()


def resetScreen():
    clean()
    img = ImageTk.PhotoImage(Image.open("logo.png"))
    logo = Label(windows, image=img)
    logo.place(x=235, y=5)

    lbl1 = Label(windows, text="Enter recovery key", font=("Verdana", 15))
    lbl1.place(x=270, y=220)

    key_entry = Entry(windows, width=45)
    key_entry.place(x=140, y=255)
    key_entry.focus()

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(key_entry.get()).encode("utf-8"))
        cursor.execute("SELECT * FROM master_password WHERE id = 1 AND recoveryKey = ?", [(recoveryKeyCheck)])
        return cursor.fetchall()

    def checkRecoveryKey():
        checked = getRecoveryKey()

        if checked:
            clean()
            create_Master_Key()
        else:
            key_entry.delete(0, "end")
            wrong_label = Label(windows, text="key does not matched", font=("Verdana", 13))
            wrong_label.place(x=265, y=325)

    submit_button = Button(windows, text="Submit", width=5, font=("Verdana", 13), command=checkRecoveryKey)
    submit_button.place(x=302, y=288)

    windows.mainloop()


def mainPage():
    clean()
    img = ImageTk.PhotoImage(Image.open("logo.png"))
    logo = Label(windows, image=img)
    logo.place(x=235, y=5)

    def toAddPasswordMenu():
        for widget in windows.winfo_children():
            widget.destroy()
        addPasswordMenu()

    def toViewTable():
        for widget in windows.winfo_children():
            widget.destroy()
        viewTable()

    add_button = Button(windows, text="NEW ENTRY", width=20, font=("Verdana", 13), command=toAddPasswordMenu)
    add_button.place(x=235, y=220)
    view_button = Button(windows, text="VIEW VAULT", width=20, font=("Verdana", 13), command=toViewTable)
    view_button.place(x=235, y=250)

    windows.mainloop()


def addPasswordMenu():
    def generate_password():
        letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                   'u',
                   'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
                   'P',
                   'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

        password_letters = [choice(letters) for _ in range(randint(8, 10))]
        password_symbols = [choice(symbols) for _ in range(randint(2, 4))]
        password_numbers = [choice(numbers) for _ in range(randint(2, 4))]

        password_list = password_letters + password_symbols + password_numbers
        shuffle(password_list)

        password = "".join(password_list[:11])
        password_entry.delete(0, "end")
        password_entry.insert(0, password)

    def addEntry():
        website = encrypt(website_entry.get().encode(), encryptionKey)
        email = encrypt(email_entry.get().encode(), encryptionKey)
        password = encrypt(password_entry.get().encode(), encryptionKey)
        insert_fields = """INSERT INTO vault(website, username, password)
        VALUES(?, ?, ?)"""
        cursor.execute(insert_fields, (website, email, password))
        db.commit()
        done_message = Label(windows, text="Saved!", font=("Verdana", 13))
        done_message.place(x=300, y=340)

    def reset():
        for widget in windows.winfo_children():
            widget.destroy()
        addPasswordMenu()

    def toMainPage():
        for widget in windows.winfo_children():
            widget.destroy()
        mainPage()

    img = ImageTk.PhotoImage(Image.open("add_logo.png"))
    logo = Label(windows, image=img)
    logo.place(x=235, y=5)

    # # Labels
    website_label = Label(text="Website", font=("Verdana", 15))
    website_label.place(x=170, y=201)
    email_label = Label(text="Email/Username", font=("Verdana", 15))
    email_label.place(x=110, y=231)
    password_label = Label(text="Password", font=("Verdana", 15))
    password_label.place(x=160, y=261)

    # # Entries
    website_entry = Entry(width=25)
    website_entry.place(x=240, y=200)
    website_entry.focus()
    email_entry = Entry(width=25)
    email_entry.place(x=240, y=232)
    password_entry = Entry(width=13)
    password_entry.place(x=240, y=264)

    # Buttons
    back_btn = Button(text="<", font=("Verdana", 15, "bold"), command=toMainPage)
    back_btn.place(x=10, y=10)
    generate_password_button = Button(text="Generate", font=("Verdana", 15), command=generate_password)
    generate_password_button.place(x=380, y=263)
    save_button = Button(text="Save", font=("Verdana", 15), width=18, command=addEntry)
    save_button.place(x=330, y=298)
    reset_button = Button(text="Reset", font=("Verdana", 15), width=18, command=reset)
    reset_button.place(x=110, y=298)

    windows.mainloop()


def viewTable():
    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        for widget in windows.winfo_children():
            widget.destroy()
        viewTable()

    def copy_pwd(input):
        cursor.execute("SELECT password FROM vault WHERE id = ?", (input,))
        pyperclip.copy(decrypt(cursor.fetchall()[0][0], encryptionKey).decode("utf-8"))

    def toMainPage():
        for widget in windows.winfo_children():
            widget.destroy()
        global start
        start = 0
        mainPage()

    def constructTable():
        back_btn = Button(text="<", font=("Verdana", 15, "bold"), command=toMainPage)
        back_btn.place(x=10, y=10)
        Website_label = Label(windows, text="Website", font=("Verdana", 13, "bold"))
        Website_label.grid(row=0, column=0, padx=80, pady=10)
        Email_label = Label(windows, text="Email", font=("Verdana", 13, "bold"))
        Email_label.grid(row=0, column=1, padx=60, pady=10)
        Password_label = Label(windows, text="Password", font=("Verdana", 13, "bold"))
        Password_label.grid(row=0, column=2, padx=60, pady=10)
        next_page_button = Button(windows, text=">", width=2, font=("Verdana", 15, "bold"),
                                  command=printVault_increment)
        next_page_button.place(x=590, y=350)
        pre_page_button = Button(windows, text="<", width=2, font=("Verdana", 15, "bold"),
                                 command=printVault_decrement)
        pre_page_button.place(x=530, y=350)

    def copy(text):
        text = str(text)
        pyperclip.copy(text)

    def printVault(start):
        cursor.execute("SELECT * FROM vault")
        array = cursor.fetchall()
        array_length = len(array)
        global total
        total = array_length
        if array_length != 0:
            for item in array[start:start + 5]:
                web = Label(windows, text=(decrypt(item[1], encryptionKey)), font=("Verdana", 13), pady=20)
                web.grid(row=item[0] + 1, column=0)
                user = Label(windows, text=(decrypt(item[2], encryptionKey)), font=("Verdana", 13), pady=20)
                user.grid(row=item[0] + 1, column=1)
                password = decrypt(item[3], encryptionKey)
                pwd = Label(windows, text=password, font=("Verdana", 13), pady=20)
                pwd.grid(row=item[0] + 1, column=2)
                copy_button = Button(windows, text="[]", font=("Verdana", 13),
                                     command=partial(copy_pwd, item[0]))
                copy_button.grid(row=item[0] + 1, column=3)
                delete_btn = Button(windows, text="✖", font=("Verdana", 13),
                                    command=partial(removeEntry, item[0]))
                delete_btn.grid(row=item[0] + 1, column=4)

    def printVault_increment():
        global start
        if start < total:
            start += 5
        for widget in windows.winfo_children():
            widget.destroy()
        constructTable()
        printVault(start)

    def printVault_decrement():
        global start
        if start != 0:
            start -= 5
        for widget in windows.winfo_children():
            widget.destroy()
        constructTable()
        printVault(start)

    constructTable()
    printVault(start)

    windows.mainloop()


# ---------------------------- main ------------------------------- #
# ---------------------------- global variables ------------------------------- #
total = 0
start = 0
windows = Tk()
windows.title("Password Manager")
windows.geometry("700x410")
windows.config(padx=10, pady=10)
cursor.execute("SELECT * FROM master_password")
if cursor.fetchall():
    logInScreen()
else:
    create_Master_Key()

windows.mainloop()
