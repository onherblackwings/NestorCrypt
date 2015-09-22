#!/usr/bin/python
# -*- coding: iso-8859-1 -*-
#============================================================================================================================================================#
#Substitution cypher code taken from: http://inventwithpython.com/
#encryption and decryption code taken from: http://www.codekoala.com/posts/aes-encryption-python-using-pycrypto/ and https://gist.github.com/sekondus/4322469
#Tkinter GUI taken from: http://sebsauvage.net/python/gui/
#Some guides and tips gleaned from: www.tutorialspoint.com

#============================================================================================================================================================#

import Tkinter
import tkMessageBox
import binascii
import base64
#import string
import os
from random import shuffle
from random import randint
from Crypto.Cipher import AES

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
BLOCK_SIZE=32
PADDING='{'
pad=lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

def is_hex(s):
     hex_digits = set(string.hexdigits)
     # if s is long, then it is faster to check against a set
     return all(c in hex_digits for c in s)

def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False



def encode(plaintext_message):
   
    z=''
    myKey=list(LETTERS)
    x=randint(2,(len(LETTERS)**2))
    c=1
        
    secret=os.urandom(BLOCK_SIZE)

    while c!=x:
        myKey=list(myKey)
        shuffle(myKey)
        myKey=''.join(myKey)
        #print myKey
        c+=1
    
    
    y=''
    EncodeAES=lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    cipher=AES.new(secret)

    plaintext_message=plaintext_message.upper()

    for i in plaintext_message:
        if i in LETTERS:
            num=LETTERS.find(i)
            y=y+myKey[num]
        else:
            y=y+i
    
    encoded=EncodeAES(cipher, y)
    #print "The Final Encrypted Message is: ", encoded

    a = open("cache.txt", "wb")
    a.write(myKey)
    a.close()
    b = open("cache.txt", "ab+")
    b.write(secret.encode('hex'))
    b.close()
    c = open("cache.txt", "ab+")
    c.write(encoded)
    c.close()

    d=open("cache.txt", "r")
    encoded=d.readline()
    d.close()

    return encoded



def decode(encrypted_message):
    y=''
    
    '''e=open("cache.txt", "w")
    e.write(encrypted_message)
    e.close()

    f=open("cache.txt", "r")
    myKey=f.read(26)
    secret=f.read(64)
    message=f.readline()
    f.close()'''
    myKey=encrypted_message[0:26] 
    secret=encrypted_message[26:90]
    message=encrypted_message[90:]

    if secret=='':
        y=''
        return y
    else:
        DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
        secret=binascii.unhexlify(secret)
        cipher=AES.new(secret)
        decoded=DecodeAES(cipher, message)
        for i in decoded:
            if i in myKey:
                num=myKey.find(i)
                y=y+LETTERS[num]
            else:
                y=y+i
        #print "Final Decrypted Message: ", y
        return y



class simpleapp_tk(Tkinter.Tk):
    def __init__(self,parent):
        Tkinter.Tk.__init__(self,parent)
        self.parent = parent
        self.initialize()

    def initialize(self):
        self.grid()

        self.entryVariable=Tkinter.StringVar() #input variable
        self.entry = Tkinter.Entry(self,textvariable=self.entryVariable)
        self.entry.grid(column=0,row=0,sticky='EW')
        self.entry.bind("<Return>", self.OnPressEnter)
        #self.entryVariable.set(u"Enter message here.")

        button = Tkinter.Button(self,text=u" ENCRYPT  !",command=self.OnButtonClickEncrypt)
        button.grid(column=1,row=0)
        button1 = Tkinter.Button(self,text=u" DECRYPT !",command=self.OnButtonClickDecrypt)
        button1.grid(column=2,row=0)
        button2 = Tkinter.Button(self,text=u"Clear Cache",command=self.OnButtonClickClear)
        button2.grid(column=2,row=1)

        self.labelVariable=Tkinter.StringVar()
        #self.labelVariable1=Tkinter.StringVar()
        label = Tkinter.Label(self,anchor="w",fg="white",bg="blue", textvariable=self.labelVariable)
        label.grid(column=0,row=1,columnspan=2,sticky='EW')
        #label1 = Tkinter.Label(self,anchor="w",fg="white",bg="blue", textvariable=self.labelVariable1)
        #label1.grid(column=0,row=3,columnspan=3,sticky='EW')
        self.labelVariable.set(u"ENTER YOUR MESSAGE AND CHOOSE ENCRYPT OR DECRYPT")
        #self.labelVariable1.set(u"ENTER FILENAME TO DECRYPT")

        self.grid_columnconfigure(0, weight=1) #resize
        self.resizable(False,False)
        self.update()
        self.geometry(self.geometry()) #to make window size constant
        self.entry.focus_set()
        self.entry.selection_range(0, Tkinter.END)

    def OnButtonClickEncrypt(self):
        if len(self.entryVariable.get())== 0:
            tkMessageBox.showinfo("No Entry Alert!", "Please Enter Data!")
            self.labelVariable.set("No Data found. Please enter Data.")
            self.entry.focus_set()
            self.entry.selection_range(0,Tkinter.END)
        else:
            plaintext_message=self.entryVariable.get()
            self.labelVariable.set("Encrypted Mesage saved to CACHE.TXT")
            tkMessageBox.showinfo("Encrypted Message", encode(plaintext_message))
            self.entry.focus_set()
            self.entry.selection_range(0,Tkinter.END)

        
    def OnButtonClickDecrypt(self):
        if len(self.entryVariable.get())== 0:
            tkMessageBox.showinfo("No Entry Alert!", "Please Enter Data!")
            self.labelVariable.set("No Data found. Please enter Data.")
            self.entry.focus_set()
            self.entry.selection_range(0,Tkinter.END)

        else:
             test_val=self.entryVariable.get()[26:90]
            
             if is_hex(test_val)==False:
                 tkMessageBox.showinfo("Wrong Message Alert!", "Data already in plain text!")
                 self.labelVariable.set("Wrong Data found. Please enter Ecnrypted Data.")
                 self.entry.focus_set()
                 self.entry.selection_range(0,Tkinter.END)
             else:
                encrypted_message=self.entryVariable.get()    
                #self.labelVariable.set("Decrypted Message saved to CACHE.TXT")
                tkMessageBox.showinfo("Decrypted Message", decode(encrypted_message))
                if tkMessageBox.askyesno("SAVE", "Save your message?"):
                     g=open("cache.txt", "w")
                     g.write("The Message is: "+decode(encrypted_message))
                     g.close()
                     tkMessageBox.showinfo("Message Saved!", "Message saved to CACHE.TXT")
                     self.labelVariable.set("Decrypted Message saved to CACHE.TXT")
                else:
                     tkMessageBox.showinfo("Message Not Saved!", "Message Deleted!")
                     self.labelVariable.set("Decrypted Message not saved to CACHE.TXT")

                self.entry.focus_set()
                self.entry.selection_range(0,Tkinter.END)
              
                

    def OnButtonClickClear(self):
        if os.path.isfile("cache.txt"):
            os.remove("cache.txt")
            tkMessageBox.showinfo("CACHE CLEARED!!!", "All data has been purged!")
            self.labelVariable.set("CACHE CLEARED!!!")
            self.entry.focus_set()
            self.entry.selection_range(0,Tkinter.END)
        else:
            tkMessageBox.showinfo("ALERT!", "Cache not found or already deleted!")
            self.labelVariable.set("CACHE NOT FOUND!")
            self.entry.focus_set()
            self.entry.selection_range(0,Tkinter.END)


    def OnPressEnter(self, event):
        if len(self.entryVariable.get())== 0:
            tkMessageBox.showinfo("No Entry Alert!", "Please Enter Data!")
            self.labelVariable.set("No Data found. Please enter Data.")
            self.entry.focus_set()
            self.entry.selection_range(0,Tkinter.END)
        else:
            test_val=self.entryVariable.get()[26:90]
            if is_hex(test_val)==True:
                encrypted_message=self.entryVariable.get()
                tkMessageBox.showinfo("Decrypted Message", decode(encrypted_message))
                if tkMessageBox.askyesno("SAVE", "Save your message?"):
                     g=open("cache.txt", "w")
                     g.write("The Message is: "+decode(encrypted_message))
                     g.close()
                     tkMessageBox.showinfo("Message Saved!", "Message saved to CACHE.TXT")
                     self.labelVariable.set("Decrypted Message saved to CACHE.TXT")
                else:
                     tkMessageBox.showinfo("Message Not Saved!", "Message Deleted!")
                     self.labelVariable.set("Decrypted Message not saved to CACHE.TXT")

                self.entry.focus_set()
                self.entry.selection_range(0,Tkinter.END)
     
                     
                '''self.labelVariable.set("Decrypted Message saved to CACHE.TXT")
                tkMessageBox.showinfo("Decrypted Message", x)
                self.entry.focus_set()
                self.entry.selection_range(0,Tkinter.END)'''
            else:
                plaintext_message=self.entryVariable.get()
                self.labelVariable.set("Encrypted Mesage saved to CACHE.TXT")
                tkMessageBox.showinfo("Encrypted Message", encode(plaintext_message))
                self.entry.focus_set()
                self.entry.selection_range(0,Tkinter.END)
                
            
            
           
        
        


if __name__ == "__main__":
    app = simpleapp_tk(None)
    app.title("Nestor's Encryption/Decryption App" )
    app.mainloop()
