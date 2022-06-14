from tkinter import *

# UI Setup
bgColor = "#002120"
wdgtXPad = 5
wdgtYPad = 7
window = Tk()
window.resizable(False,False)
window.title("MyPass")
window.configure(bg=bgColor)
window.config(padx=50, pady=50)
window.minsize(width=550,height=550)
canvas = Canvas(height=400, width=400)
logoImg = PhotoImage(file="resources/my-pass-logo.png")
canvas.create_image(200, 200, image=logoImg)
canvas.configure(bg=bgColor)
canvas.grid(column=1,row=0,columnspan=1)

# Labels in columns 0
websiteLabel = Label(text="Website:", font=("Arial", 14, "bold"), fg="white",bg=bgColor)
websiteLabel.grid(column=0,row=1)
emailLabel = Label(text="Email/Username:", font=("Arial", 14, "bold"), fg="white",bg=bgColor)
emailLabel.grid(column=0,row=2)
passwdLabel = Label(text="Password:", font=("Arial", 14, "bold"), fg="white",bg=bgColor)
passwdLabel.grid(column=0,row=3)

# Input fields in columns 1
website=""
email=""
passwd=""
websiteInput = Entry(textvariable=website,width=80)
websiteInput.grid(column=1,row=1,columnspan=2,padx=wdgtXPad,pady=wdgtYPad)
emailInput = Entry(textvariable=email,width=80)
emailInput.grid(column=1,row=2,columnspan=2,padx=wdgtXPad,pady=wdgtYPad)
passwdInput = Entry(textvariable=passwd,width=61)
passwdInput.grid(column=1,row=3,padx=wdgtXPad,pady=wdgtYPad)
addBtn = Button(text="ADD",width=60,bg="#1dd8f4",font=("Arial", 10, "bold"))
addBtn.grid(column=1,row=4,columnspan=2,padx=wdgtXPad,pady=wdgtYPad)

# Button field in column 2
genPass = Button(text="Generate Pass",font=("Arial", 10, "bold"), bg="#81f991")
genPass.grid(column=2,row=3,padx=wdgtXPad,pady=wdgtYPad)

window.mainloop()

# Generate Password
# Save Password as encrypted text
# Require password to un-encrypt
