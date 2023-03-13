from __future__ import print_function
import shutil
from flask import Flask, Response, request, session, url_for, redirect,send_file
import requests
import socket
import time
import json
import sys
from flask import Flask, render_template
from flask import Flask
#from tkinter import filedialog
from random import randrange, getrandbits
from threading import Thread
import random
import cv2
import os,io
import numpy as np
import numpy
import matplotlib
matplotlib.use('Agg')
from matplotlib import pyplot as plt
from random import randrange, getrandbits
import re
from sympy import isprime, gcd
from werkzeug.utils import secure_filename
import base64
#from kafka import KafkaProducer
from PIL import Image

import math
from math import sqrt
import hashlib
from hashlib import sha1


import sys
import logging
import pysftp as sftp
cnopts = sftp.CnOpts()
cnopts.hostkeys = None


#Library Database
from flask import Flask,render_template, request
from flask_mysqldb import MySQL
from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re

#logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
app = Flask(__name__)
#t = threading.Thread(target=your_func)
#t.setDaemon(True)
#t.start()


#database
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'security_image'
app.config['SECRET_KEY'] = 'some random string'
mysql = MySQL(app)



Image.MAX_IMAGE_PIXELS=None
UPLOAD_FOLDER="static/image_to_encrypt/"
app.config['UPLOAD_FOLDER']=UPLOAD_FOLDER



def generatePrime():
    p = random.randrange(16,64)
    while (not(isprime(p))):
        p = random.randrange(16,64)

    q = random.randrange(16,64)
    while (p == q or not(isprime(q))):
        q = random.randrange(16,64)
    return p,q

#Function Login, Register, Logout
@app.route('/form')
def form():
    return render_template('form.html')

@app.route('/register', methods = ['POST', 'GET'])
def register():
    if request.method == 'GET':
        #return "Login via the login Form"
        return render_template('form.html')
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        print(username)
        print(name)
        password = request.form['password']
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(''' INSERT INTO account VALUES(NULL,%s,%s,%s,%s)''',(username,name,password,email))
        mysql.connection.commit()
        cursor.close()
        return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM account WHERE username = %s AND password = %s', (username, password,))
        # Fetch one record and return result
        account = cursor.fetchone()
        # If account exists in accounts table in out database
        if account:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            # Redirect to home page
            return render_template('index.html')
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect Account OR Create Your Account '
            
    # Show the login form with message (if any)
    return render_template('login.html', msg=msg)
@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))
@app.route('/')
def home():
    if 'loggedin' in session:
        return render_template('index.html',username=session['username'])
    return render_template('login.html')


@app.route('/index')
def index():
    if 'loggedin' in session:
        return render_template('index.html',username=session['username'])
    return render_template('login.html')
@app.route('/about')
def about():
    if 'loggedin' in session:
        return render_template('about.html')
    return render_template('login.html')
@app.route('/encryption')
def encryption():
    if 'loggedin' in session:
        return render_template('encryption.html')
    return render_template('login.html')

@app.route('/keyauthenticationexchange')
def keyauthenticationexchange():
    if 'loggedin' in session:
        HOST = "10.8.109.70"
        #PORT = 12345
        PORT = 65432
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print ("Failed to Create Socket")
            sys.exit()
        print("Socket Created")
        try:
            remote_ip = socket.gethostbyname(HOST)
        except socket.gaierror:
            print("Hostname coult not be resolve. Exiting")
            sys.exit()
        s.connect((HOST, PORT))
        print ('Socket Connected to ' + HOST)
        
        #Authentication Process
        #Receive Challenge Response
        data = s.recv(1024)
        print(data)
        data = json.loads(data.decode())
        receive=data.get("a")
        print("Data Challenge Response: ",receive)
        print("A: ",receive[0])
        print("B: ",receive[1])
        print("C: ",receive[2])
        a=receive[0]
        b=receive[1]
        c=receive[2]
        #Send Challenge Response to Server
        nilai_challenge_response=a|b*c
        #nilai_challenge_response=100
        dump_nilai_CR=json.dumps({"a":nilai_challenge_response})
        s.send(dump_nilai_CR.encode())
        print("Nilai Challenge Response to Server: ",nilai_challenge_response)
        #Response From Server for Challenge Response
        response = s.recv(2048)
        response = json.loads(response.decode())
        receive=response.get("a")
        #receive=response.decode()
        print("Receive: ",receive)

        status="OK"
        sendrespon=json.dumps({"c":status})
        s.send(sendrespon.encode())

        if receive == 0:
            print("Authentication Failure")
            respon="Authentication Failure"
            data=[a,b,c,nilai_challenge_response,respon]
            return render_template('keyauthenticationexchange.html',data=data)
            s.close()
        else:
            print("Authentication Success")
            data = s.recv(2048)
            data = json.loads(data.decode())
            PublicKey=data.get("b")
            print("Receive Public Key (E, N): ",PublicKey)
            print("E: ",PublicKey[0])
            print("N: ",PublicKey[1])
            e=PublicKey[0]
            n=PublicKey[1]
            #data=[a,b,c,nilai_challenge_response,PublicKey]
            data=[a,b,c,nilai_challenge_response,e,n]
            #return redirect(url_for("image",data=data))
            s.close()
        account_id=session['id']
        puk_n_receiver=PublicKey[1]
        puk_e_receiver=PublicKey[0]
        ori_image=''
        size_image=''
        resolution=''
        encrypt_image=''
        path_original=''
        prk_d_sender=''
        puk_e_sender=''
        puk_n_sender=''
        message_digest=''
        signature=''
        en_execution_time=''
        value_npcr=''
        value_uaci=''
        entropy=''
        status=''


        #hash PrivateKey
        e=PublicKey[0]
        string_e=str(e)
        hash_e=hashlib.md5(string_e.encode())
        e_hash=hash_e.hexdigest()
        print("hash E: ",e_hash)

        n=PublicKey[1]
        string_n=str(n)
        hash_n=hashlib.md5(string_n.encode())
        n_hash=hash_n.hexdigest()
        print("hash N: ",n_hash)

        hash_PublicKey=[e_hash,n_hash]
        print("hash PublicKey E,N: ",PublicKey)


        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(''' INSERT INTO logging_sender VALUES(NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',(account_id,
            puk_n_receiver,puk_e_receiver,ori_image,size_image,resolution,encrypt_image,
            path_original,prk_d_sender,puk_e_sender,puk_n_sender,message_digest,signature,en_execution_time,value_npcr,value_uaci,entropy,status))
        cursor.execute('SELECT LAST_INSERT_ID()')
        id_logging=cursor.fetchone()
        mysql.connection.commit()
        cursor.close()
        data=[a,b,c,nilai_challenge_response,PublicKey,id_logging]
        
        return render_template('keyauthenticationexchange.html',hash_PublicKey=hash_PublicKey,data=data,id_logging=id_logging)
        s.close()
    return redirect(url_for('login'))
def power(a,d,n):
  ans=1;
  while d!=0:
    if d%2==1:
      ans=((ans%n)*(a%n))%n
    a=((a%n)*(a%n))%n
    d>>=1
  return ans;
def power1(x,y,m):
    ans=1
    while(y>0):
        if(y%2==1):
            ans=(ans*x)%m
        y=y//2
        x=(x*x)%m
    return ans


@app.route("/image/<data>", methods=['POST'])
def image(data):
    if 'loggedin' in session:
        #start_time=time.time()
        data=re.findall('[0-9]+',data)
        image=request.files['file']
        filename=secure_filename(image.filename)
        print("Filename: ",filename)
        image.save(app.config['UPLOAD_FOLDER']+filename)
        print("sukses")
        #old=app.config['UPLOAD_FOLDER']+filename
        #new=app.config['UPLOAD_FOLDER'],'original.png'
        #os.rename(old,new)
        #my_img=cv2.imread(app.config['UPLOAD_FOLDER']+filename)
        my_img=Image.open(app.config['UPLOAD_FOLDER']+filename)
        rows,cols=my_img.size
        print("ROWS: ",rows)
        print("COLS: ",cols)
        pixels=my_img.load()
        print("PIXELS: ",pixels)
        #ukuran gambar
        path_file=app.config['UPLOAD_FOLDER']
        input_file=filename
        size=os.stat(path_file+input_file).st_size
        def convert_bytes(size):
            for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
                if size < 1024.0:
                    return "%3.1f %s" % (size, x)
                size /= 1024.0
            return size
        image_size=convert_bytes(size)
        print("Image Size:",image_size)
        E=int(data[4])
        print("E: ",E)
        N=int(data[5])
        print("N: ",N)
        
        #original = [[0 for x in range(rows)] for y in range(cols)]
        #for i in range(cols):
        #    for j in range(rows):
        #        r,g,b = pixels[j,i]
        #        r2=r
        #        g2=g
        #        b2=b
        #        original[i][j]=[r2,g2,b2]
        start_time=time.time()
        enc = [[0 for x in range(rows)] for y in range(cols)]
        for i in range(cols):
            for j in range(rows):
                r,g,b=pixels[j,i] 
                r1=power1(r,E,N)
                g1=power1(g,E,N)
                b1=power1(b,E,N)
                enc[i][j]=[r1,g1,b1]
        #print("Matrix Enc:",enc)
        #Waktu Eksekusi
        end_time=time.time()
        interval=end_time-start_time
        execution_time=interval/60
        print("Execution Time:",execution_time)
        image_resolution=[rows,cols]
        #=== Save Matrix to File ===#
        #pathtxto=os.path.join(app.config['UPLOAD_FOLDER'],'original.txt')
        #print("file original txt: ",pathtxto)
        #file = open(pathtxto, "w+")
        #content = str(original)
        #file.write(content)
        #file.close()
        
        #=== Save Matrix to File ===#
        pathtxt=os.path.join(app.config['UPLOAD_FOLDER'],'encrypt.txt')
        print("file encrypt txt: ",pathtxt)
        file = open(pathtxt, "w+")
        content = str(enc)
        file.write(content)
        file.close()
        #=== CONVERT encrypt.txt TO Base64 ===#
        def converter():
            path_file=os.path.join(app.config['UPLOAD_FOLDER'],'encrypt.txt')
            with open(path_file, "rb") as img_file:
                encoded_data=base64.b64encode(img_file.read())
            encoded=encoded_data.decode('utf-8')
            pathtxt=os.path.join(app.config['UPLOAD_FOLDER'],'encrypt_encode.txt')
            file = open(pathtxt, "w+")
            content = str(encoded)
            file.write(content)
            file.close()
        converter()

        #Compres image
        original = os.path.join(app.config['UPLOAD_FOLDER'],'original.png')
        original_file=app.config['UPLOAD_FOLDER']+filename
        picture = Image.open(original_file)
        dim = picture.size
        picture.save(original,optimize=True,quality=100)
        ori='original.png'
        new_original=app.config['UPLOAD_FOLDER']+ori


        #=== Proses Save Matrik Enkripsi ke Image RGB ===#
        img = numpy.array(enc,dtype = numpy.uint8)
        img1 = Image.fromarray(img,"RGB")
        #img1.save('Encrypt.bmp')
        img1.save(os.path.join(app.config['UPLOAD_FOLDER'],'image_encrypt.jpg'))
        #nama File
        file_name="image_encrypt.jpg"
        #ukuran gambar enkripsi
        path_file_e=app.config['UPLOAD_FOLDER']
        input_file_e=file_name
        size_e=os.stat(path_file_e+input_file_e).st_size
        def convert_bytes_e(size_e):
            for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
                if size_e < 1024.0:
                    return "%3.1f %s" % (size_e, x)
                size_e /= 1024.0
            return size_e
        image_size_e=convert_bytes_e(size_e)
        print("Image size enkripsi: ",image_size_e)
        #resolusi gambar
        encrypt_file=os.path.join(app.config['UPLOAD_FOLDER'],'image_encrypt.jpg')
        encrypted_img= Image.open(encrypt_file)
        width,height=encrypted_img.size
        image_resolution_e=[height,width]
        #Waktu Eksekusi
        #end_time=time.time()
        #interval=end_time-start_time
        #execution_time=interval/60
        #description_original=[image_resolution,image_size]
        description_encrypt=[file_name,image_size_e,execution_time]




        def rateofchange(height,width,pixel1,pixel2,matrix,i):
            for y in range(0,height):
                for x in range(0,width):
                    #print(x,y)
                    if pixel1[x,y][i] == pixel2[x,y][i]:
                        matrix[x,y]=0
                    else:
                        matrix[x,y]=1
            return matrix
        def sumofpixel(height,width,pixel1,pixel2,ematrix,i):
            matrix=rateofchange(height,width,pixel1,pixel2,ematrix,i)
            psum=0
            for y in range(0,height):
                for x in range(0,width):
                    psum=matrix[x,y]+psum
            return psum
        def npcrv(loc1,loc2):
            c1 = Image.open(loc1)
            c2 = Image.open(loc2)
            width, height = c1.size
            pixel1 = c1.load()
            pixel2 = c2.load()
            ematrix = np.empty([width, height])
            per=(((sumofpixel(height,width,pixel1,pixel2,ematrix,0)/(height*width))*100)+((sumofpixel(height,width,pixel1,pixel2,ematrix,1)/(height*width))*100)+((sumofpixel(height,width,pixel1,pixel2,ematrix,2)/(height*width))*100))/3
            return per
        npcr=npcrv(new_original,encrypt_file)
        print("NPCR:",npcr)
        def uaciv(loc1,loc2):
            image1 = Image.open(loc1)
            image2 = Image.open(loc2)
            pixel1=image1.load()
            pixel2=image2.load()
            width,height=image1.size
            value=0.0
            for y in range(0,height):
                for x in range(0,width):
                    value=(abs(pixel1[x,y][0]-pixel2[x,y][0])/255)+value

            value=(value/(width*height))*100
            return value
        uaci=uaciv(new_original,encrypt_file)
        print("UACI:",uaci)
        value_of_x=0
        value_of_y=0

        encrypt="image_encrypt.jpg"
        path_original=app.config['UPLOAD_FOLDER']+filename
        id_table=data[6]
        ori_image=filename
        print(id_table)
        print(ori_image)
        size_image=image_size
        resoulution=str(image_resolution)
        print("resolusi",resoulution)
        encrypt_image=encrypt
        path_original=path_original
        en_execution_time=execution_time
        value_npcr=npcr
        value_uaci=uaci

        #Nilai Entropy 
        def calcEntropy():
            entropy = []
            encrypt="image_encrypt.jpg"
            path_enc=app.config['UPLOAD_FOLDER']+encrypt
            
            image=cv2.imread(path_enc,cv2.IMREAD_GRAYSCALE)
            hist = cv2.calcHist([image], [0], None, [256], [0, 255])
            #total_pixel = img.shape[0] * img.shape[1]
            img1 = Image.open(path_enc)
            width,height=img1.size
            total_pixel= width * height
            print("total_pixel:",total_pixel)
            for item in hist:
                probability = item / total_pixel
                if probability == 0:
                    en = 0
                else:
                    en = -1 * probability * (np.log(probability) / np.log(2))
                entropy.append(en)
            sum_en = np.sum(entropy)
            return sum_en
        #image=cv2.imread(path_enc)
        value_entropy = calcEntropy()
        print("Nilai Entropy: ",value_entropy)
        entropy=value_entropy
        #Nilai Entropy 
        p, q = generatePrime()
        print("Prime Number P dan Q, Different P and Q values")
        print("Nilai P: ",p)
        print("Nilai Q: ",q)
         

        #=== Value N=P*Q and Euler Totient = (P-1)(Q-1) ===#
        n = p*q
        m = (p-1)*(q-1)
        #e = random.randrange(1,m)
        e = random.choice([3,5])
        while (gcd(e,m) != 1):
            #e = random.randrange(1,m)
            e = random.choice([3,5])
        k = 1
        while ((1+m*k) % e != 0):
            k += 1
        d = int((1+m*k)/e)
        
        print("Nilai D: ",d)
        print("Nilai E: ",e)
        print("Nilai N: ",n)
        prk_d_sender=d
        puk_e_sender=e
        puk_n_sender=n

        private=(d,n)
        public=(e,n)
        def encrypt(privatek, plaintext):
            #Unpack the key into it's components
            e
            key, n = privatek

            #Convert each letter in the plaintext to numbers based on the character using a^b mod m
                    
            numberRepr = [ord(char) for char in plaintext]
            #print("Number representation before encryption: ", numberRepr)
            cipher = [pow(ord(char),key,n) for char in plaintext]
            
            #Return the array of bytes
            return cipher


        def decrypt(publick, ciphertext):
            #Unpack the key into its components
            key, n = publick
               
            #Generate the plaintext based on the ciphertext and key using a^b mod m
            numberRepr = [pow(char, key, n) for char in ciphertext]
            plain = [chr(pow(char, key, n)) for char in ciphertext]
            #print("Decrypted number representation is: ", numberRepr)
            #Return the array of bytes as a string
            return ''.join(plain)

        
        #Message Digest 1
        MD1= sha1(open(encrypt_file, 'rb').read()).hexdigest()
        print("MD1: ",MD1)

        #Digital Signature
        #Enkript MD1 with Private Key
        DS=encrypt(private,MD1)
        print("Digital Signature: ",''.join(map(lambda x: str(x), DS)))
        
        message_digest=str(MD1)
        signature_digital=str(''.join(map(lambda x: str(x), DS)))
        signature=str(DS)
        
        account_id=session['id']
        print("account_id_sender:",account_id)
        id_table_logging=int(id_table)
        print("id_table_logging:",id_table_logging)
        infosignature=[e,n,rows,cols,account_id,id_table_logging]


        #=== Save Resolution to File ===#
        pathresolution=os.path.join(app.config['UPLOAD_FOLDER'],'resolution.txt')
        print("file encrypt txt: ",pathresolution)
        file = open(pathresolution, "w+")
        resolution = str(infosignature)
        print("Resolution Image:",resolution)
        file.write(resolution)
        file.close()

        #=== Save Signature to File ===#
        pathsignature=os.path.join(app.config['UPLOAD_FOLDER'],'signature.txt')
        print("signature: ",pathsignature)
        file = open(pathsignature, "w+")
        signature_image = str(DS)
        print("signature :",signature_image)
        file.write(signature_image)
        file.close()


        def sftpexample():
            try:
                server=sftp.Connection(host="localhost",username='TeknikKomputer',password="TeknikKomputer",cnopts=cnopts)
                localpath1="D:/APPLICATION/static/image_to_encrypt/resolution.txt"
                remotepath1="D:/APPLICATION_B/static/image_to_decrypt/resolution.txt"

                localpath2="D:/APPLICATION/static/image_to_encrypt/encrypt_encode.txt"
                remotepath2="D:/APPLICATION_B/static/image_to_decrypt/encrypt_encode.txt"

                #localpath3="D:/APPLICATION/static/image_to_encrypt/original.txt"
                #remotepath3="D:/APPLICATION_B/static/image_to_decrypt/original.txt"


                localpath4="D:/APPLICATION/static/image_to_encrypt/signature.txt"
                remotepath4="D:/APPLICATION_B/static/image_to_decrypt/signature.txt"

                server.put(localpath1,remotepath1)
                server.put(localpath2,remotepath2)
                #server.put(localpath3,remotepath3)
                server.put(localpath4,remotepath4)
            except Exception as e:
                print (str(e))
        sftpexample()
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("UPDATE logging_sender SET ori_image=%s, size_image=%s, resoulution=%s, encrypt_image=%s, path_original=%s, prk_d_sender=%s, puk_e_sender=%s, puk_n_sender=%s, message_digest=%s, signature=%s, en_execution_time= %s, value_npcr= %s, value_uaci=%s, entropy=%s WHERE id= %s",(ori_image,size_image,resoulution,encrypt_image,path_original,prk_d_sender,puk_e_sender,puk_n_sender,message_digest,signature,en_execution_time,value_npcr,value_uaci,entropy,id_table,))
        mysql.connection.commit()
        cursor.close()

        #Histogram
        def original():
            original="original.png"
            path_original=app.config['UPLOAD_FOLDER']+original
            img_ori=cv2.imread(path_original)
            histogram_original=cv2.calcHist([img_ori],[0],None,[256],[0,256])
            plt.plot(histogram_original)
            plt.savefig(os.path.join(app.config['UPLOAD_FOLDER'],'histogram_original.jpg'))
        def encrypt():
            encrypt="image_encrypt.jpg"
            path_encrypt=app.config['UPLOAD_FOLDER']+encrypt
            img_enc=cv2.imread(path_encrypt)
            histogram_encrypt=cv2.calcHist([img_enc],[0],None,[256],[0,256])
            plt.plot(histogram_encrypt)
            plt.savefig(os.path.join(app.config['UPLOAD_FOLDER'],'histogram_encrypt.jpg'))
        #original()
        #print("succes")
        #encrypt()
        #Histogram
        return render_template("Encryption.html",id_table=id_table,filename=filename,image_resolution=image_resolution,image_size=image_size,
            description_encrypt=description_encrypt,image_resolution_e=image_resolution_e,npcr=npcr,uaci=uaci,message_digest=message_digest,signature_digital=signature_digital)
    return render_template('login.html')

@app.route('/view/<id_table>')
def view(id_table):
    id_table=id_table
    print(id_table)
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    logging=cursor.execute('SELECT * from logging_sender WHERE id=%s',(id_table,))
    logging=cursor.fetchall()
    
    mysql.connection.commit()
    cursor.close()
   
    return render_template('view.html',logging=logging)
@app.route('/display_original/<filename>')
def display_image_original(filename):
    print('display_image_original filename: ' + filename)
    return redirect(url_for('static', filename='image_to_encrypt/'+filename), code=301)
@app.route('/histogram')
def histogram():
    def original():
        original="original.png"
        path_original=app.config['UPLOAD_FOLDER']+original
        img_ori=cv2.imread(path_original)
        histogram_original=cv2.calcHist([img_ori],[0],None,[256],[0,256])
        fig=plt.plot(histogram_original)
        fig=plt.savefig(os.path.join(app.config['UPLOAD_FOLDER'],'histogram_original.jpg'))
        fig=plt.close()
    def encrypt():
        encrypt="image_encrypt.jpg"
        path_encrypt=app.config['UPLOAD_FOLDER']+encrypt
        img_enc=cv2.imread(path_encrypt)
        histogram_encrypt=cv2.calcHist([img_enc],[0],None,[256],[0,256])
        fig=plt.plot(histogram_encrypt)
        fig=plt.savefig(os.path.join(app.config['UPLOAD_FOLDER'],'histogram_encrypt.jpg'))
        fig=plt.close()
    original()
    time.sleep(3)
    encrypt()
    return render_template("Histogram.html")

@app.route('/download_file_enc')
def download_file_enc():
    #path = "html2pdf.pdf"
    #path = "info.xlsx"
    path = os.path.join(app.config['UPLOAD_FOLDER'],'image_encrypt.jpg')
    #path = "sample.txt"
    return send_file(path, as_attachment=True)