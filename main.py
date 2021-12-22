import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generation(path):
    # сериализация ключа симмеричного алгоритма в файл
    print("Длина ключа от 5 до 16 байт")
    key_len = int(input('Введите желаемую длину ключа: '))
    while key_len < 5 or key_len > 16:
        key_len = int(input('Введите желаемую длину ключа: '))
    key = os.urandom(key_len)
    # генерация пары ключей для асимметричного алгоритма шифрования
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    from cryptography.hazmat.primitives.asymmetric import padding
    c_key = public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None))
    with open(path + "\\symmetric.txt", 'wb') as key_file:
        key_file.write(c_key)
    # сериализация открытого ключа в файл
    with open(path + "\\public.pem", 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    # сериализация закрытого ключа в файл
    with open(path + "\\private.pem", 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))


def encryption(file, key_direct, encrypt_file):
    with open(key_direct + "\\private.pem", 'rb') as pem_in:
        private_bytes = pem_in.read()
    private_key = load_pem_private_key(private_bytes, password=None, )
    with open(key_direct + "\\symmetric.txt", 'rb') as key:
        symmetric_bytes = key.read()
    from cryptography.hazmat.primitives.asymmetric import padding
    d_key = private_key.decrypt(symmetric_bytes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None))
    with open(file, 'rb') as o_text:
        text = o_text.read()
    from cryptography.hazmat.primitives import padding
    pad = padding.ANSIX923(64).padder()
    padded_text = pad.update(text) + pad.finalize()
    # случайное значение для инициализации блочного режима, должно быть размером с блок и каждый раз новым
    iv = os.urandom(8)
    with open(key_direct + "\\vec.txt", 'wb') as iv_file:
        iv_file.write(iv)
    cipher = Cipher(algorithms.CAST5(d_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text) + encryptor.finalize()
    with open(encrypt_file, 'wb') as encrypt:
        encrypt.write(c_text)


def decryption(encrypt_file, key_direct, decrypt_file):
    with open(key_direct + "\\private.pem", 'rb') as pem_in:
        private_bytes = pem_in.read()
    private_key = load_pem_private_key(private_bytes, password=None, )
    with open(key_direct + "\\symmetric.txt", 'rb') as key:
        symmetric_bytes = key.read()
    from cryptography.hazmat.primitives.asymmetric import padding
    d_key = private_key.decrypt(symmetric_bytes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    with open(encrypt_file, 'rb') as e_text:
        text = e_text.read()
    # дешифрование и депаддинг текста симметричным алгоритмом
    with open(key_direct + "\\vec.txt", 'rb') as iv_file:
        iv = iv_file.read()
    cipher = Cipher(algorithms.CAST5(d_key), modes.CBC(iv))
    decrypter = cipher.decryptor()
    from cryptography.hazmat.primitives import padding
    unpadded = padding.ANSIX923(64).unpadder()
    d_text = unpadded.update(decrypter.update(text) + decrypter.finalize()) + unpadded.finalize()
    with open(decrypt_file, 'w', encoding='UTF-8') as decrypt:
        decrypt.write(d_text.decode('UTF-8'))


while (True):
    print("1 - генерация ключей; 2 - шифрование данных; 3 - дешифрование данных ; 4 - выход")
    num = int(input())
    if num == 1:
        print('Генерация ключей гибридной системы')
        print("Введите директорию, в которой будут сохранены ключи: ")
        key_direct = input()
        print("Введите длину ключа: ")
        generation(key_direct)
    elif num == 2:
        print('Шифрование данных гибридной системой')
        print("Введите путь к тексту, который нужно зашифровать: ")
        file = input()
        print("Введите директорию, в которой сохранены ключи: ")
        key_direct = input()
        print("\nВведите путь, в который хотите сохранить зашифрованный текст: ")
        encrypt_file = input()
        encryption(file, key_direct, encrypt_file)
    elif num == 3:
        print('Дешифрование данных гибридной системой')
        print("Введите директорию, в которой сохранены ключи: ")
        key_direct = input()
        print("\nВведите путь, в который сохранен зашифрованный текст: ")
        encrypt_file = input()
        print("\nВведите путь, в который хотите сохранить расшифрованный текст: ")
        decrypt_file = input()
        decryption(encrypt_file, key_direct, decrypt_file)
    elif 4:
        break
