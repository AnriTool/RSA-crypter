from random import randrange, getrandbits
import re
from tkinter import *
from tkinter import messagebox
from tkinter.ttk import Style
from tkinter.ttk import Notebook
from tkinter.ttk import Combobox
from tkinter import filedialog

P = int()
Q = int()
D = int()
MODULUS = int()

PUBLIC_KEY = int()
PRIVATE_KEY = int()
PUBLIC_EXP = int()
MODULUS_F = int()


ORIGINAL_TEXT = ""
CRYPTED_TEXT = ""


def is_prime(n, k=128):
    """ Test if a number is prime
        Args:
            n -- int -- the number to test
            k -- int -- the number of tests to do
        return True if n is prime
    """
    # Test if n is not even.
    # But care, 2 is prime !
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # find r and s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    # do k tests
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True


def generate_prime_candidate(length):
    """ Generate an odd integer randomly
        Args:
            length -- int -- the length of the number to generate, in bits
        return a integer
    """
    # generate random bits
    p = getrandbits(length)
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p


def generate_prime_number(length):
    """ Generate a prime
        Args:
            length -- int -- length of the prime to generate, in          bits
        return a prime
    """
    p = 4
    # keep generating while the primality test fail
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x


def genPQ():
    global P
    global Q
    global MODULUS
    k = int(cb_bit_select.get())
    P = generate_prime_number(k)
    Q = generate_prime_number(k)
    cb_open_e.configure(state="readonly")
    btn_open_e.configure(state="active")

    btn_file_save.configure(state="disable")
    MODULUS = P*Q

def openECheck():
    global P
    global Q
    global D
    global MODULUS
    global PUBLIC_EXP

    el_func = (P - 1) * (Q - 1)
    m, a, D = extended_gcd(el_func, int(cb_open_e.get()))

    if m != 1:
        btn_file_save.configure(state="disable")
        messagebox.showerror(title="ERROR", message="Select a different number of Fermat!")
    else:
        PUBLIC_EXP = cb_open_e.get()
        btn_file_save.configure(state="active")

def selectKeysSavePath():
    folder_selected = filedialog.askdirectory()
    text_choose_folder.configure(state="normal")
    text_choose_folder.delete(0,END)
    text_choose_folder.insert(0,folder_selected)
    text_choose_folder.configure(state="readonly")

def saveKeys():
    global P
    global Q
    global D
    global MODULUS
    global PUBLIC_EXP
    if text_choose_folder.get() == "":
        messagebox.showerror(title="ERROR", message="Select save path!")
    elif text_file_name.get() == "":
        messagebox.showerror(title="ERROR", message="Select key's name!")
    else:
        public_key = "RSAPublicKey ::= SEQUENCE {\n\t modulus " + str(MODULUS) + \
                     ",\n\t publicExponent " + str(PUBLIC_EXP) + "\n}"

        private_key = "RSAPrivateKey ::= SEQUENCE { \n\t modulus " + str(MODULUS) + \
                      ",\n\t publicExponent " + str(PUBLIC_EXP) + \
                      ",\n\t privateExponent " + str(D) + \
                      ",\n\t prime1 " + str(P) + \
                      ",\n\t prime2 " + str(Q) + ",\n}"

        with open(text_choose_folder.get()+"/"+text_file_name.get()+".pubkey", 'w') as fp:
            fp.write(public_key)

        with open(text_choose_folder.get() + "/" + text_file_name.get() + ".privkey", 'w') as fp:
            fp.write(private_key)

        messagebox.showinfo(title="SUCCES", message="Keys created!")

def selectPubKey():
    global PUBLIC_KEY
    global PUBLIC_EXP
    filetypes = (
        ('text files', '*.pubkey'),
        ('All files', '*.*')
    )
    pubkey = filedialog.askopenfilename(filetypes=filetypes)
    text_pubkey_path.configure(state="normal")
    text_pubkey_path.delete(0, END)
    text_pubkey_path.insert(0, pubkey)
    text_pubkey_path.configure(state="readonly")
    with open(pubkey, 'r') as fp:
        lines = fp.readlines()
        PUBLIC_KEY = int(re.findall("\d+",lines[1])[0])
        PUBLIC_EXP = int(re.findall("\d+", lines[2])[0])
    print(PUBLIC_KEY)
    print(PUBLIC_EXP)

def encrypt():
    if text_pubkey_path.get() == "":
        messagebox.showerror(title="ERROR", message="Select public key!")
    elif crypt_file_name.get() == "":
        messagebox.showerror(title="ERROR", message="Input encrypted file name!")
    else:
        global ORIGINAL_TEXT
        global PUBLIC_EXP
        global PUBLIC_KEY
        keyLen = len(str(PUBLIC_KEY))
        lst = list()
        for i in ORIGINAL_TEXT:
            lst.append(ord(i))

        crypt = ""
        for i in lst:
            cryptCh = str(pow(i, PUBLIC_EXP, PUBLIC_KEY))
            nulls = keyLen - len(cryptCh)
            crypt = crypt + ("0" * nulls + cryptCh)

        encrypted = "EncryptedData :: = SEQUENCE {\n"+ \
                    "\t\tcontentType TEXT\n" + \
                    "\t\tcontentEncryptionAlgorithmIdentifier rsaEncryption\n"+\
                    "encryptedContent " + str(crypt) + "\n}"
        print(encrypted)

        folder_selected = filedialog.askdirectory()
        with open(folder_selected+"/"+crypt_file_name.get()+".encrypted", 'w') as fp:
            fp.write(encrypted)
        messagebox.showinfo(title="SUCCES", message="File encrypted!")

def selectOrigFile():
    global ORIGINAL_TEXT
    filetypes = (
        ('text files', '*.txt'),
        ('All files', '*.*')
    )
    file = filedialog.askopenfilename(filetypes=filetypes)
    text_path.configure(state="normal")
    text_path.delete(0, END)
    text_path.insert(0, file)
    text_path.configure(state="readonly")
    with open(file, 'r') as fp:
        ORIGINAL_TEXT = fp.read()

def selectPrKey():
    global PUBLIC_KEY
    global PRIVATE_KEY
    filetypes = (
        ('text files', '*.privkey'),
        ('All files', '*.*')
    )
    pubkey = filedialog.askopenfilename(filetypes=filetypes)
    text_prkey_path.configure(state="normal")
    text_prkey_path.delete(0, END)
    text_prkey_path.insert(0, pubkey)
    text_prkey_path.configure(state="readonly")
    with open(pubkey, 'r') as fp:
        lines = fp.readlines()
        PUBLIC_KEY = int(re.findall("\d+", lines[1])[0])
        PRIVATE_KEY = int(re.findall("\d+", lines[3])[0])
        if '-' in lines[3]:
            PRIVATE_KEY = 0 - PRIVATE_KEY
    print(PUBLIC_KEY)
    print(PRIVATE_KEY)

def selectCryptFile():
    global CRYPTED_TEXT
    filetypes = (
        ('text files', '*.encrypted'),
        ('All files', '*.*')
    )
    file = filedialog.askopenfilename(filetypes=filetypes)
    enc_text_path.configure(state="normal")
    enc_text_path.delete(0, END)
    enc_text_path.insert(0, file)
    enc_text_path.configure(state="readonly")
    with open(file, 'r') as fp:
        lines = fp.readlines()
        CRYPTED_TEXT =re.findall("\d+", lines[3])[0]
        print(CRYPTED_TEXT)


def decrypt():
    if text_prkey_path.get() == "":
        messagebox.showerror(title="ERROR", message="Select private key!")
    elif enc_text_path.get() == "":
        messagebox.showerror(title="ERROR", message="Select encrypted file!")
    elif decrypt_file_name.get() == "":
        messagebox.showerror(title="ERROR", message="Input decrypted file name!")
    else:
        global PUBLIC_KEY
        global PRIVATE_KEY
        global CRYPTED_TEXT
        keyLen = len(str(PUBLIC_KEY))
        decrypt = list()
        for i in range(keyLen, len(CRYPTED_TEXT) + keyLen, keyLen):
            decrypt.append(int(CRYPTED_TEXT[i - keyLen:i]))

        decrypted_text = ""
        for i in decrypt:
            decrypted_text = decrypted_text + chr(pow(i, PRIVATE_KEY, PUBLIC_KEY))
        print(decrypted_text)

        folder_selected = filedialog.askdirectory()
        with open(folder_selected + "/" + decrypt_file_name.get() + ".decrypted.txt", 'w') as fp:
            fp.write(decrypted_text)
        messagebox.showinfo(title="SUCCES", message="File Decrypted!")


# Combo boxes
bits = [
    16, 32, 64,
    128, 256, 512,
    1024, 2048
]
open_e = [3, 5, 17, 257, 65537]


# ------Tkinter window creation------
root = Tk()
root.geometry('550x310')
root.title('RSA Encrypt')
root.resizable(False, False)

# ------Tab creation------
style = Style(root)
style.configure('lefttab.TNotebook', tabposition='wn')
notebook = Notebook(root, style='lefttab.TNotebook')
notebook.pack(pady=10, expand=True)

# ------Generate tab------
frame_gen = Frame(notebook, width=450, height=450)
Label(frame_gen, text="Generate keys").pack(side=TOP)

# --------------Bits selection--------------
fr_bit_select = LabelFrame(frame_gen, text="Bits selection", width=420, height=140)
Label(fr_bit_select, text="Bit count: ").pack(side=LEFT, padx= 30)

cb_bit_select = Combobox(fr_bit_select, values=bits, state="readonly")
cb_bit_select.set(16)
cb_bit_select.pack(side=LEFT, padx=30)

btn_bit_select = Button(fr_bit_select, text="Submit", command=genPQ)
btn_bit_select.pack(side=LEFT, padx=30, pady=5)
fr_bit_select.pack(fill="both",side=TOP)
# ---------------------------------------------

# ------------Firma number selection-----------
fr_open_e = LabelFrame(frame_gen, text="Fermat number", width=420, height=140)
Label(fr_open_e, text="Bit count: ").pack(side=LEFT, padx= 30)

cb_open_e = Combobox(fr_open_e, values=open_e, state="disable")
cb_open_e.set(3)
cb_open_e.pack(side=LEFT, padx=30)

btn_open_e = Button(fr_open_e, text="Submit", state="disable", command=openECheck)
btn_open_e.pack(side=LEFT, padx=30, pady=5)
fr_open_e.pack(fill="both",side=TOP)
# ---------------------------------------------

# ----------------Saving keys------------------
fr_save_keys = LabelFrame(frame_gen, text="Saving keys", width=420, height=140)

# ----------------------Saving path----------------------
fr_save_path = Frame(fr_save_keys, width=420, height=140)
Label(fr_save_path, text="Save path: ").grid(row=0, column=0, padx=30)

text_choose_folder = Entry(fr_save_path, width=50, state="readonly")
text_choose_folder.grid(row=0, column=1, padx=30)

btn_choose_folder = Button(fr_save_path,text="Select path", width=11, command=selectKeysSavePath)
btn_choose_folder.grid(row=1, column=1,  pady=5)

fr_save_path.pack(side=TOP)
# ----------------------------------------------------------

# -----------------------Name select------------------------
fr_file_name = Frame(fr_save_keys, width=420, height=140)
Label(fr_file_name, text="Key's name:").grid(row=0, column=0, padx=28)
text_file_name = Entry(fr_file_name, width=50, )
text_file_name.grid(row=0, column=1, padx=30)
btn_file_save = Button(fr_file_name, text="Save keys", width=11, state="disable", command=saveKeys)
btn_file_save.grid(row=1, column=1, pady=5)
fr_file_name.pack(side=TOP)
# ----------------------------------------------------------

fr_save_keys.pack(fill="both",side=TOP)
# ---------------------------------------------

frame_gen.pack(side=TOP)
# -------------------------------




# ------Crypt tab------
frame_crypt = Frame(notebook, width=450, height=450)
Label(frame_crypt, text="Encrypt text").pack(side=TOP)

# ------------Files select------------
fr_pub_key_select = LabelFrame(frame_crypt, text="Files selection", width=420, height=140)

Label(fr_pub_key_select, text="Public key:").grid(row=0, column=0, padx=30)

text_pubkey_path = Entry(fr_pub_key_select, width=50, state="readonly")
text_pubkey_path.grid(row=0, column=1, padx=30)

btn_choose_pubkey = Button(fr_pub_key_select,text="Select key", width=11, command=selectPubKey)
btn_choose_pubkey.grid(row=1, column=1,  pady=5)

Label(fr_pub_key_select, text="Text file:").grid(row=2, column=0, padx=30)

text_path = Entry(fr_pub_key_select, width=50, state="readonly")
text_path.grid(row=2, column=1, padx=30)

btn_choose_text = Button(fr_pub_key_select,text="Select text file", width=11, command=selectOrigFile)
btn_choose_text.grid(row=3, column=1,  pady=5)

fr_pub_key_select.pack(fill="both",side=TOP)
# ------------------------------------

# ----------------------Saving path----------------------
fr_save_crypted = Frame(frame_crypt, width=420, height=140)
btn_encrypt = Button(fr_save_crypted, text="Encrypt data", width=11, command=encrypt)
btn_encrypt.grid(row=1, column=2,padx=10 , pady=5)

Label(fr_save_crypted, text="Encrypted name:").grid(row=1, column=0)
crypt_file_name = Entry(fr_save_crypted, width=22)
crypt_file_name.grid(row=1, column=1,)

fr_save_crypted.pack(side=TOP)
# ----------------------------------------------------------

frame_crypt.pack(side=TOP)
# ---------------------


# ------Decrypt tab------
frame_decrypt = Frame(notebook, width=450, height=450)

Label(frame_decrypt, text="Encrypt text").pack(side=TOP)

# ------------Files select------------
fr_pr_key_select = LabelFrame(frame_decrypt, text="Files selection", width=420, height=140)

Label(fr_pr_key_select, text="Prvate key:").grid(row=0, column=0, padx=30)

text_prkey_path = Entry(fr_pr_key_select, width=50, state="readonly")
text_prkey_path.grid(row=0, column=1, padx=30)

btn_choose_prkey = Button(fr_pr_key_select,text="Select key", width=11, command=selectPrKey)
btn_choose_prkey.grid(row=1, column=1,  pady=5)

Label(fr_pr_key_select, text="Encrypted file:").grid(row=2, column=0, padx=20)

enc_text_path = Entry(fr_pr_key_select, width=50, state="readonly")
enc_text_path.grid(row=2, column=1, padx=30)

btn_choose_crypted = Button(fr_pr_key_select,text="Select data", width=11, command=selectCryptFile)
btn_choose_crypted.grid(row=3, column=1,  pady=5)

fr_pr_key_select.pack(fill="both",side=TOP)
# ------------------------------------

# ----------------------Saving path----------------------
fr_save_decrypted = Frame(frame_decrypt, width=420, height=140)
btn_decrypt = Button(fr_save_decrypted, text="Decrypt data", width=11, command=decrypt)
btn_decrypt.grid(row=1, column=2,padx=10 , pady=5)

Label(fr_save_decrypted, text="Decrypted name:").grid(row=1, column=0)
decrypt_file_name = Entry(fr_save_decrypted, width=22, )
decrypt_file_name.grid(row=1, column=1,)

fr_save_decrypted.pack(side=TOP)
# ----------------------------------------------------------






















frame_decrypt.pack(side=TOP)


notebook.add(frame_gen, text='Generate')
notebook.add(frame_crypt, text='Encrypt')
notebook.add(frame_decrypt, text='Decrypt')


root.mainloop()













