from tkinter import *
from tkinter import messagebox
import base64

# Function to handle decryption
def decrypt():
    password = code.get()  # Get the entered password

    # Check if the password is correct
    if password == '1234':
        # Create a new window for decryption
        window2 = Toplevel(window)
        window2.title("Decryption")
        window2.geometry("400x300")
        window2.configure(bg="#18ba33")

        # Get the message to be decrypted
        message = text1.get(1.0, END).strip()  # Strip any extra spaces or newlines
        if not message:  # Show error if no text is provided
            messagebox.showerror("Error", "No text to decrypt")
            return

        # Decode the message using base64
        decode_message = message.encode('ascii')
        base64_bytes = base64.b64decode(decode_message)  # Correct base64 decoding
        decoded_message = base64_bytes.decode('ascii')  # Decode back to ASCII
        
        decode_message = decoded_message.encode('ascii')
        base64_bytes = base64.b64decode(decode_message)  # Correct base64 decoding
        decoded_message = base64_bytes.decode('ascii')  # Decode back to ASCII
        
        decode_message = decoded_message.encode('ascii')
        base64_bytes = base64.b64decode(decode_message)  # Correct base64 decoding
        decoded_message = base64_bytes.decode('ascii')  # Decode back to ASCII

        # Add a label and text box to show the decrypted message
        Label(window2, text="Decrypted Message", font='arial', bg='#18ba33', fg='#FFFFFF').place(x=10, y=0)
        text2 = Text(window2, font='Roboto 12', bg='#FFFFFF', relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10, y=40, width=380, height=150)
        text2.insert(END, decoded_message)

        # Close button for decryption window
        Button(window2, text="Close", height=2, width=15, bg='#e5eb98', fg='#000000', bd=0, command=window2.destroy).place(x=140, y=220)

    # Error handling for empty or incorrect password
    elif password == '':
        messagebox.showerror("Error", "Please enter a password")
    elif password != '1234':
        messagebox.showerror("Invalid Password", "Please enter valid password")

# Function to handle encryption
def encrypt():
    password = code.get()  # Get the entered password

    # Check if the password is correct
    if password == '1234':
        # Create a new window for encryption
        window1 = Toplevel(window)
        window1.title("Encryption")
        window1.geometry("400x300")
        window1.configure(bg="#d43131")

        # Get the message to be encrypted
        message = text1.get(1.0, END).strip()  # Strip any extra spaces or newlines
        if not message:  # Show error if no text is provided
            messagebox.showerror("Error", "No text to encrypt")
            return

        # Encode the message using base64
        encode_message = message.encode('ascii')
        base64_bytes = base64.b64encode(encode_message)
        encoded_message = base64_bytes.decode('ascii') # Convert bytes to string
        
        encode_message = encoded_message.encode('ascii')
        base64_bytes = base64.b64encode(encode_message)
        encoded_message = base64_bytes.decode('ascii')  # Convert bytes to string
        
        encode_message = encoded_message.encode('ascii')
        base64_bytes = base64.b64encode(encode_message)
        encoded_message = base64_bytes.decode('ascii')  # Convert bytes to string

        # Add a label and text box to show the encrypted message
        Label(window1, text="Encrypted Message", font='arial', bg='#d43131', fg='#FFFFFF').place(x=10, y=0)
        text2 = Text(window1, font='Roboto 12', bg='#FFFFFF', relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10, y=40, width=380, height=150)
        text2.insert(END, encoded_message)

        # Close button for encryption window
        Button(window1, text="Close", height=2, width=15, bg='#e5eb98', fg='#000000', bd=0, command=window1.destroy).place(x=140, y=220)

    # Error handling for empty or incorrect password
    elif password == '':
        messagebox.showerror("Error", "Please enter a password")
    elif password != '1234':
        messagebox.showerror("Invalid Password", "Please enter valid password")


# Function to set up the main screen of the application
def main_screen():
    global window
    global code
    global text1
    window = Tk()
    window.geometry("400x350")  # Increased size to fit all widgets
    window.resizable(False, False)  # Disable resizing

    # Icon setup (optional)
    try:
        image_icon = PhotoImage(file='keys.png')
        window.iconphoto(False, image_icon)
    except Exception as e:
        print("Error loading icon:", e)  # Handle icon loading error

    window.title("Encrypt and Decrypt Message")

    # Function to reset the input fields
    def reset():
        code.set('')  # Clear the password entry
        text1.delete(1.0, END)  # Clear the message text area

    # Widgets for the main screen
    Label(text='Enter text for encryption and decryption:', fg='black', font=('calibri', 12)).place(x=10, y=10)

    # Text box to input the message
    text1 = Text(window, font=('Roboto', 12), bg='white', relief=GROOVE, wrap=WORD, bd=1)
    text1.place(x=10, y=40, width=380, height=100)

    # Label for the password entry
    Label(window, text='Enter secret key for encryption and decryption:', fg='black', font=('calibri', 12)).place(x=10, y=150)

    # Entry field for the password (hidden input)
    code = StringVar()
    Entry(window, textvariable=code, width=20, bd=1, font=('arial', 14), show='*').place(x=10, y=180)

    # Encrypt button
    Button(window, text='ENCRYPT', height=2, width=15, bg='#ed3833', fg='#FFFFFF', bd=0, command=encrypt).place(x=20, y=250)

    # Decrypt button
    Button(window, text='DECRYPT', height=2, width=15, bg='#00bd56', fg='#FFFFFF', bd=0, command=decrypt).place(x=265, y=250)

    # Reset button
    Button(window, text='Reset', height=2, width=50, bg='#1089ff', fg='#FFFFFF', bd=0, command=reset).place(x=20, y=300)

    # Start the main window loop
    window.mainloop()

# Run the application
main_screen()
