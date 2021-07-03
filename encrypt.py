import os
import os.path
from os import listdir
from os.path import isfile, join
from numpy import byte
import streamlit as st
from Crypto.Cipher import AES
from Crypto import Random
import base64

class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size = 256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)


st.title("File Encryptor")
menu = ["Home", "Encryptor", "Decryptor", "About"]
st.sidebar.header("Select Menu From Here")
choice = st.sidebar.radio("Menu", menu)

if choice == "Home":
    definition = st.beta_container() 
    types = st.beta_container()
    aes = st.beta_container()
    with definition:
        st.markdown("## **Encryption**")
        st.markdown("**Encryption** is the method by which information is converted into secret "  
                "code that hides the information's true meaning. The science of encrypting" 
                "and decrypting information is called **cryptography**. In computing," 
                " unencrypted data is also known as **plaintext**, and encrypted data is called " 
                "ciphertext. The formulas used to encode and decode messages are called " 
                "**encryption algorithms**, or **ciphers**.")
        st.markdown("To be effective, a cipher includes a variable as part of the algorithm. " 
                "The variable, which is called a **key**, is what makes a cipher's output unique. " 
                "When an encrypted message is intercepted by an unauthorized entity, the "
                "intruder has to guess which cipher the sender used to encrypt the message, "
                "as well as what keys were used as variables. The time and difficulty of "
                "guessing this information is what makes encryption such a valuable security tool.")        
        st.markdown("**Encryption** has been a longstanding way for sensitive information to be protected. " 
                " Historically, it was used by militaries and governments.  In modern times, encryption is"
                " used to protect data stored on computers and storage devices, as well as data in transit over networks. ")

    with types:
        st.markdown("## __Symmetric ciphers__")
        st.markdown("There are two types of symmetric ciphers:")
        st.markdown(" - **Stream ciphers** : the most natural kind of ciphers: they encrypt data one byte at a time. " 
                "See [ChaCha20 and XChaCha20](https://www.pycryptodome.org/en/latest/src/cipher/chacha20.html) and "
                "[Salsa20](https://www.pycryptodome.org/en/latest/src/cipher/salsa20.html). \n"  
                "- **Block ciphers**: ciphers that can only operate on a fixed amount of data. The most important "
                "block cipher is [AES](https://www.pycryptodome.org/en/latest/src/cipher/aes.html), which has a block size of 128 bits (16 bytes).")
        st.markdown("The widespread consensus is that ciphers that provide only confidentiality, without any form of "
                "authentication, are undesirable. Instead, primitives have been defined to integrate "
                "symmetric encryption and authentication (MAC). For instance:")
        st.markdown("- [Modern modes of operation](https://www.pycryptodome.org/en/latest/src/cipher/modern.html) "
                "for block ciphers (like GCM).\n - Stream ciphers paired with a MAC function, "
                "like [ChaCha20-Poly1305 and XChaCha20-Poly1305](https://www.pycryptodome.org/en/latest/src/cipher/chacha20_poly1305.html).")

    with aes:
        st.markdown(" ## **AES**")
        st.markdown(" **AES (Advanced Encryption Standard)** is a symmetric block cipher standardized by **NIST** ." 
                "It has a fixed data block size of **16 bytes**. Its keys can be **128**, **192**, or **256 bits** long. "
                "AES is very fast and secure, and it is the ***de facto*** standard for **symmetric encryption**.")   
        st.markdown("AES’s results are so successful that many entities and agencies have approved it and utilize "
        "it for encrypting sensitive information. The National Security Agency (NSA), as well as other governmental "
        "bodies, utilize AES encryption and keys to protect classified or other sensitive information. Furthermore, "
        "AES is often included in commercial based products, including but limited to:\n - Wi-Fi (can be used as part of WPA2)\n "
        "- Mobile apps (such as WhatsApp and LastPass)\n -Native Processor Support\n - Libraries in many software development languages"
        "\n - VPN Implementations\n - Operating system components such as file systems.")

    
elif choice == 'Encryptor':
    st.header("Encrypt File")
    file = st.file_uploader("Upload File To Encrypt",type=[])
    if file is not None: 
        st.write('You selected `%s`' % file.name)
        file_detail = {"File Name":file.name,"File Type":file.type,"File Size":file.size}
        st.write(file_detail)
        st.write(type(file))
        with open(os.path.join("tempDir",file.name),"wb") as f: 
            f.write(file.getbuffer()) 
        
        key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'
        enc = Encryptor(key)

        file_name = str(os.path.join("tempDir",file.name))

        enc.encrypt_file(file_name)
        st.success("Done.")
        file_name = file_name+'.enc'
        with open(file_name, 'rb') as f:
            data = f.read()
        b64 = base64.b64encode(data).decode()
         
        file_name = file_name.split("\\")[1]
        href = f'<a href="data:application/octet-stream;base64,{b64}" download="{file_name}">Download {file_name}</a>'
        st.markdown(href,unsafe_allow_html=True)

elif choice == "Decryptor":    
    st.header("Decrypt File")
    file = st.file_uploader("Upload File To Decrypt",type=[])
    #filename = file.name
    
    if file is not None: 
        st.write('You selected `%s`' % file.name)
        file_detail = {"File Name":file.name,"File Type":file.type,"File Size":file.size}
        st.write(file_detail)
        st.write(type(file))
        with open(os.path.join("tempDir",file.name),"wb") as f: 
            f.write(file.getbuffer()) 
        
        key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'
        enc = Encryptor(key)
        file_name = str(os.path.join("tempDir",file.name))
        enc.decrypt_file(file_name)
        st.success("Done.")
        file_name = file_name[:-4]
        with open(file_name, 'rb') as f:
            data = f.read()
        b64 = base64.b64encode(data).decode()         
        file_name = file_name.split("\\")[1]
        href = f'<a href="data:application/octet-stream;base64,{b64}" download="{file_name}">Download {file_name}</a>'
        st.markdown(href,unsafe_allow_html=True)
    
elif choice == "About":
    st.header("About")
    st.header("About")
    st.markdown("This Python Project is based on ***AES Encryption And Decryption*** Made by **Johar Ali** Student of **Digital Forensics And Cyber Security**.")
    st.info("Roll no: fa-19/bsdfcs/045")    
    st.info("Course: Python Programming 4th Semester")
    st.info(" Email Id : 'joharali225@hotmail.com'")
