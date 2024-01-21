from django.shortcuts import render,redirect,HttpResponse,Http404
from django.contrib.auth.models import User
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.forms import UserCreationForm
from django.views import generic
from datetime import datetime
from home.models import Contact
from home.models import Fileadmin
from django.contrib import messages
import os
import Main.settings as settings
from django.http import FileResponse
from django.http import JsonResponse
import os

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image

#başka bir seçenek
#data_train["labels"] = [ "No Hate and Offensive" if each ==0  else "Offensive Language" for each in data_train["malignant"]]



def home(request):
    print(request.user)
    if request.user.is_anonymous:
        return redirect("/login") 
    return render(request,'index.html')
def loginuser(request):
    if request.method=="POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        print(username, password)
        user = authenticate(username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect("/")

        else:
            return render(request, 'login.html')

    return render(request,'login.html')
def logoutuser(request):
    logout(request)
    return redirect("/login")

def index(request):
    print(request.user)
    if request.user.is_anonymous:
        return redirect("/login") 
    return render(request,'index.html')
def contactus(request):
    if request.method == "POST":
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        desc = request.POST.get('desc')
        contact = Contact(name=name, email=email, phone=phone, desc=desc, date = datetime.today())
        contact.save()
    return render(request,'contactus.html')
def signup(request):
    return render(request,'signup.html')

def signup(request):
    if request.method=="POST":
        username=request.POST['username']
        email=request.POST['email']
        fname=request.POST['fname']
        lname=request.POST['lname']
        password=request.POST['password']
        password2=request.POST['password2']
        myuser = User.objects.create_user(username, email, password)
        myuser.first_name= fname
        myuser.last_name= lname
        myuser.save()
        return redirect('/login')
    return render(request,'signup.html')
def price(request):
    print(request.user)
    if request.user.is_anonymous:
        return redirect("/login") 
    return render(request,'price.html')

def about(request):
    print(request.user)
    if request.user.is_anonymous:
        return redirect("/login") 
    return render(request,'about.html')

def service(request):
    print(request.user)
    if request.user.is_anonymous:
        return redirect("/login") 
    return render(request,'service.html')
def contact(request):
    print(request.user)
    if request.user.is_anonymous:
        return redirect("/login") 
    return render(request,'contact.html')
def upload_file(request):
    if request.method == 'POST' and request.FILES['file']:
        uploaded_file = request.FILES['file']
        with open('media/' + uploaded_file.name, 'wb+') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)
        # Example usage
        # key = get_random_bytes(16)
        key=b'j\xf8\xb5%s{\xf8\x96\xad-,J\x0f\x95s\x1a'

        message = request.POST.get('text_input', '')
        

        # Encrypt the message using AES
        encrypted_message = encrypt_message(message, key)

        # Hide the encrypted message within an image
        hide_message_in_image(encrypted_message, 'media/' + uploaded_file.name, 'output_image_with_hidden_message.png')
       



        # audio_file= open('media/' + uploaded_file.name, "rb")
        
        context= {'variable_value': f'{key}'}
        
        
        

        return JsonResponse(context)

# AES Encryption functions
def upload_file1(request):
    if request.method == 'POST' and request.FILES['file']:
        uploaded_file = request.FILES['file']
        with open('media/' + uploaded_file.name, 'wb+') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)
        
        
        
        key=b'j\xf8\xb5%s{\xf8\x96\xad-,J\x0f\x95s\x1a'
        # print(key)

        # key=b'\xc5#\xc4h\x9b\rAzp\x17\xe0Q\xdcM\xae:' 
        extracted_message = extract_message_from_image('media/' + 'output_image_with_hidden_message.png')
        decrypted_message = decrypt_message(extracted_message[16:], key, extracted_message[:16])
        context= {'variable_value': decrypted_message}
        os.remove('media/' + 'output_image_with_hidden_message.png')
        return JsonResponse(context)

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext
def decrypt_message(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)  # IV is already in bytes, no need to encode
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode('utf-8')


# Steganography functions
def hide_message_in_image(message, image_path, output_path):
    image = Image.open(image_path)
    pixels = list(image.getdata())

    binary_message = ''.join(format(byte, '08b') for byte in message)
    binary_message += '1111111111111110'  # Add delimiter to mark the end of the message

    index = 0
    for i in range(len(pixels)):
        pixel = list(pixels[i])
        for j in range(3):  # Loop through RGB channels
            if index < len(binary_message):
                pixel[j] = pixel[j] & ~1 | int(binary_message[index])
                index += 1
        pixels[i] = tuple(pixel)

    new_image = Image.new(image.mode, image.size)
    new_image.putdata(pixels)
    new_image.save('media/'+output_path)

def extract_message_from_image(image_path):
    image = Image.open(image_path)
    pixels = list(image.getdata())

    binary_message = ''
    for pixel in pixels:
        for i in range(3):  # Loop through RGB channels
            binary_message += str(pixel[i] & 1)

    # Extract the message until the delimiter is found
    index = binary_message.find('1111111111111110')
    extracted_message = binary_message[:index]

    # Convert binary message to bytes
    bytes_message = [int(extracted_message[i:i+8], 2) for i in range(0, len(extracted_message), 8)]
    return bytes(bytes_message)

# # Example usage
# key = get_random_bytes(16)

# message = "This is a secret message!"

# # Encrypt the message using AES
# encrypted_message = encrypt_message(message, key)

# # Hide the encrypted message within an image
# hide_message_in_image(encrypted_message, 'original_image.jpg', 'output_image_with_hidden_message.png')

# # Extract the hidden message from the image
# extracted_message = extract_message_from_image('output_image_with_hidden_message.png')

# # Decrypt the extracted message using AES
# decrypted_message = decrypt_message(extracted_message[16:], key, extracted_message[:16])

# print("Original Message:", message)
# print("Decrypted Message:", decrypted_message)