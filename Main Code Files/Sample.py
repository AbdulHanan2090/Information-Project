from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image

# AES Encryption functions
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
    new_image.save(output_path)

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

# Example usage
key = get_random_bytes(16)

message = "This is a secret message!"

# Encrypt the message using AES
encrypted_message = encrypt_message(message, key)

# Hide the encrypted message within an image
hide_message_in_image(encrypted_message, 'original_image.jpg', 'output_image_with_hidden_message.png')

# Extract the hidden message from the image
extracted_message = extract_message_from_image('output_image_with_hidden_message.png')

# Decrypt the extracted message using AES
decrypted_message = decrypt_message(extracted_message[16:], key, extracted_message[:16])

print("Original Message:", message)
print("Decrypted Message:", decrypted_message)
print(key)