from tkinter import *
from tkinter import messagebox
import os
import base64
import stat
import string
from openpyxl import Workbook
from openpyxl import load_workbook
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# import cryptography


# UI Setup
bgColor = "#002120"
wdgtXPad = 5
wdgtYPad = 7

# Key
symkey = None

# Hard-coded items
folderName = ".mypass"
encryptedPassFilename = ".reserve.mpdb.xlsx"
saltedHashPassFilename = ".auth.mpdb.xlsx"
folderPath = os.path.join(os.path.expanduser("~"), folderName)
encryptedPassFilePath = os.path.join(os.path.expanduser("~"), folderName, encryptedPassFilename)
saltedHashPassFilePath = os.path.join(os.path.expanduser("~"), folderName, saltedHashPassFilename)

# Key check
passIsSame = False


def initialize():
    """
    If the first time, create a folder created and called ~/.mypass.
    The file the passwords will be stored will be called reserve.mpdb.
    This reserve.mpdb will be an encrypted excel sheet with the Fernet library and will perform python functions to
    store into local variable after decrypting the sheet. Once information is extracted, the file is encrypted again.
    The user's password that is salted and hashed will be stored in a different file for future comparisons.

    When the user exits then

    :return:
    """

    if not os.path.exists(folderPath):
        os.mkdir(folderPath)
    if (not os.path.exists(encryptedPassFilePath) and not os.path.exists(saltedHashPassFilePath)):
        os.chmod(folderPath, stat.S_IRWXU)
        # passwords = Workbook()
        # passwords.save(encryptedPassFilePath)
        # hashes = Workbook()
        # hashes.save(saltedHashPassFilePath)
        setPassword()
        drawWindow()
    else:
        checkPassword()
        if passIsSame:
            drawWindow()
        else:
            quit()


def drawWindow():
    """
    Draws the entire main window of MyPass GUI to add additional passwords
    :return:
    """
    window = Tk()
    window.resizable(False, False)
    window.title("MyPass")
    window.configure(bg=bgColor)
    window.config(padx=50, pady=50)
    window.minsize(width=550, height=550)

    window.iconbitmap("resources/my-pass-logo.ico")
    canvas = Canvas(height=400, width=400)
    logoImg = PhotoImage(file="resources/my-pass-logo.png")
    canvas.create_image(200, 200, image=logoImg)
    canvas.configure(bg=bgColor)
    canvas.grid(column=1, row=1, columnspan=1)

    # View passwords
    viewPass = Button(text="PASSWORDS", font=("Arial", 12, "bold"), bg="#fcac50")
    viewPass.grid(column=0, row=6, padx=wdgtXPad, pady=wdgtYPad)

    # Labels in columns 0
    websiteLabel = Label(text="Website:", font=("Arial", 14, "bold"), fg="white", bg=bgColor)
    websiteLabel.grid(column=0, row=2)
    emailLabel = Label(text="Email/Username:", font=("Arial", 14, "bold"), fg="white", bg=bgColor)
    emailLabel.grid(column=0, row=3)
    passwdLabel = Label(text="Password:", font=("Arial", 14, "bold"), fg="white", bg=bgColor)
    passwdLabel.grid(column=0, row=4)

    # Input fields in columns 1
    website = ""
    email = ""
    passwd = ""
    websiteInput = Entry(textvariable=website, width=80)
    websiteInput.grid(column=1, row=2, columnspan=2, padx=wdgtXPad, pady=wdgtYPad)
    websiteInput.focus()

    emailInput = Entry(textvariable=email, width=80)
    emailInput.grid(column=1, row=3, columnspan=2, padx=wdgtXPad, pady=wdgtYPad)

    passwdInput = Entry(textvariable=passwd, width=61)
    passwdInput.grid(column=1, row=4, padx=wdgtXPad, pady=wdgtYPad)

    addBtn = Button(text="ADD", width=60, bg="#1dd8f4", font=("Arial", 10, "bold"), command=lambda: addBtnCallback(websiteInput.get(), emailInput.get(), passwdInput.get()))
    addBtn.grid(column=1, row=5, columnspan=2, padx=wdgtXPad, pady=wdgtYPad)

    # Button field in column 2
    genPass = Button(text="Generate Pass", font=("Arial", 10, "bold"), bg="#81f991", command=lambda: genPassword(passwdInput))
    genPass.grid(column=2, row=4, padx=wdgtXPad, pady=wdgtYPad)

    window.mainloop()


def genPassword(passwdField):
    """
    Randomly generates a password with cryptographic randomness
    :return:
    """
    thePass = ""
    totalAllowedCharacters = ['!','#','$','%', '&','(',')','*','+','_','^']
    totalAllowedCharacters += string.ascii_letters
    totalAllowedCharacters += string.digits
    totalCharacters = len(totalAllowedCharacters) - 1
    for x in range(25):
        singleChar = totalAllowedCharacters[int.from_bytes(os.urandom(32),"little") % totalCharacters]
        thePass += singleChar
    passwdField.delete(0,len(passwdField.get()))
    passwdField.insert(0,thePass)



def encryptFile(userInput):
    """
    Encrypts the entire password file after adding the information to the file.
    The new window will refresh with the added information.
    :param userInput:
    :return:
    """
    pass



def decryptFile(userInput):
    """
    Decrypts the entire password file
    :param userInput: String input that the user has entered
    :return:
    """
    pass



def addBtnCallback(website, email, passwd):
    """
    Will add all the information from the input fields and place it into the excel file.
    :return: None
    """
    passWb = load_workbook(encryptedPassFilePath)
    passWs = passWb["Passwords"]
    lastRow = passWs.max_row
    passWs.cell(column=1, row=lastRow+1, value=website)
    passWs.cell(column=2, row=lastRow+1, value=email)
    passWs.cell(column=3, row=lastRow+1, value=passwd)
    passWb.save(encryptedPassFilePath)
    messagebox.showinfo(message="Credentials were added!")



def setPassword():
    """
    Opens a new window that inquires for user's new master password. This will include the salt as well.
    :return:
    """
    window = Tk()
    window.resizable(False, False)
    window.title("MyPass New Password")
    width=50
    window.configure(bg=bgColor)
    window.config(padx=50, pady=50)
    window.minsize(width=550, height=150)

    # Labels in columns 0
    passwordLabel = Label(text="New Password:", font=("Arial", 14, "bold"), fg="white", bg=bgColor)
    passwordLabel.grid(column=0, row=0)
    confirmPassLabel = Label(text="Confirm Password:", font=("Arial", 14, "bold"), fg="white", bg=bgColor)
    confirmPassLabel.grid(column=0, row=1)

    password = ""
    confirmPass = ""
    passwordInput = Entry(textvariable=password, width=width, show='*')
    passwordInput.grid(column=1, row=0, columnspan=2, padx=wdgtXPad, pady=wdgtYPad)
    passwordInput.focus()

    confirmPassInput = Entry(textvariable=confirmPass, width=width, show='*')
    confirmPassInput.grid(column=1, row=1, columnspan=2, padx=wdgtXPad, pady=wdgtYPad)

    # Set password Button
    setPassBtn = Button(text="Set Password", font=("Arial", 14, "bold"), bg="#81f991", command=lambda: savePassword(window, passwordInput.get(), confirmPassInput.get()))
    setPassBtn.grid(column=2, row=2,  columnspan=2, padx=wdgtXPad, pady=wdgtYPad)
    window.mainloop()



def savePassword(window, passwd, confirmPasswd):
    """
    Save password into the .auth.mpdb.xlsx file.
    :param window: The New Password window
    :param passPath: Path of the excel sheet that stores the hashed password with the salt
    :param passwd: Users password
    :param confirmPasswd: Users password to make sure the user typed the password correctly
    :return:
    """
    if (passwd != confirmPasswd):
        print("Passwords do not match!")
    else:
        salt1 = os.urandom(32)
        passwdB = bytes(confirmPasswd, 'UTF-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt1,
            iterations=390000,
        )
        symkey = base64.urlsafe_b64encode(kdf.derive(passwdB))
        safeSalt = base64.urlsafe_b64encode(salt1)
        hashesWb = Workbook()
        ws = hashesWb.active
        ws.title = "Master Pass"
        ws.cell(column=1,row=1,value=symkey)
        ws.cell(column=2, row=1, value=safeSalt)
        hashesWb.save(saltedHashPassFilePath)
        passwordWb = Workbook()
        passWs = passwordWb.active
        passWs.title = "Passwords"
        passwordWb.save(encryptedPassFilePath)
        window.destroy()



def checkPassword():
    """
    Window will prompt user to enter the decryption password to access the file which is located in ~/.mypass/reserve.mpdb.
    Will determine if reserve.mpdb has been tampered with previously by saving the encrypted hash. The encrypted hash will use the
    user's private key to encrypt.
    :return: string input of the password in sha256 hash form
    """
    window = Tk()
    window.resizable(False, False)
    window.title("MyPass Password")
    width=50
    window.configure(bg=bgColor)
    window.config(padx=50, pady=50)
    window.minsize(width=550, height=150)

    # Labels in columns 0
    passwordLabel = Label(text="Password:", font=("Arial", 14, "bold"), fg="white", bg=bgColor)
    passwordLabel.grid(column=0, row=0)
    password = ""

    passwordInput = Entry(textvariable=password, width=width, show='*')
    passwordInput.grid(column=1, row=0, columnspan=2, padx=wdgtXPad, pady=wdgtYPad)
    passwordInput.focus()


    # Set password Button
    setPassBtn = Button(text="Enter", font=("Arial", 14, "bold"), bg="#81f991",command=lambda: compareMasterPassword(window, passwordInput.get()))
    setPassBtn.grid(column=2, row=2,  columnspan=2, padx=wdgtXPad, pady=wdgtYPad)
    window.mainloop()



def compareMasterPassword(window, password):
    """
    Compares the inputted password to the one inside the excel file and determines if it is the same.
    :param window: the main TK window that's open
    :param passPath: Path to the excel file
    :param password: the inputted password from the user
    :return: None
    """
    global passIsSame
    hashesWb = load_workbook(saltedHashPassFilePath)
    ws = hashesWb["Master Pass"]
    origPass = bytes(ws['A1'].value,'utf-8')
    salt = base64.urlsafe_b64decode(ws['B1'].value)
    passwdB = bytes(password, 'UTF-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    enteredPass = base64.urlsafe_b64encode(kdf.derive(passwdB))
    if origPass == enteredPass:
        passIsSame = True
        symkey = enteredPass
        window.destroy()
    else:
        passIsSame = False
        window.destroy()


def main():
    initialize()

if __name__ == "__main__":
    main()

