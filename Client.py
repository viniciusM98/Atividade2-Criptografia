#! /usr/bin/env python

import socket
import sys
import time
import threading
import select
import traceback
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
import warnings

warnings.filterwarnings("ignore")

class Server(threading.Thread):
    def initialise(self, receive):
        self.receive = receive

    def generate_key(self): # Função responsável por gerar variaveis de armazenamento de chaves e controle de código
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

        self.public_key_bytes = self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

        self.public_key_extern = None
        self.public_key_extern_bytes = None

        self.key_symmetric = None
        self.signature_message = None

        self.flag_public_key_sent = False
        self.flag_signature_message = False
        self.flag_signed_message = False

    def run(self):
        lis = []
        lis.append(self.receive)
        while 1:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    s = item.recv(1024)
                    if s != '':
                        chunk = s # sempre que envio a chave ao server, o chunk é atualizado
                        decoding_chunk_value = chunk.decode('unicode_escape') # decodificação do formato da chave
                        key_start = '-----BEGIN PUBLIC KEY-----'
                        if decoding_chunk_value.startswith(key_start) and self.public_key_extern_bytes is None:
                            # condição que verifica se a chave pública foi recebida do outro cliente
                            self.public_key_extern_bytes = chunk
                            self.public_key_extern = load_pem_public_key(self.public_key_extern_bytes)

                        elif not decoding_chunk_value.startswith(key_start) and self.key_symmetric is None:
                            # verifica se a chave simétrica ainda não foi obtida, em caso verdadeiro, então é realizado a decriptografia dela
                            self.key_symmetric = self.private_key.decrypt(chunk, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

                        elif not self.flag_signed_message and self.key_symmetric is not None and self.public_key_extern is not None:
                            try:
                                chunk_split = decoding_chunk_value.split("----") # separa os dados (assinatura e mensagem) decodificados através do separador "----" definido, transformando em um array
                                chunk_sign = base64.b64decode(chunk_split[0].encode()) # decodifica a posição zero (assinatura) do array split a partir da decodificação base 64
                                chunk_msg = base64.b64decode(chunk_split[1].encode()) # decodifica a posição um (mensagem) do array split a partir da decodificação base 64

                                # É realizado uma comparação da assinatura que foi recebida em relação a chave simétrica decriptada
                                self.public_key_extern.verify(chunk_sign, self.key_symmetric, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

                                f = Fernet(self.key_symmetric)
                                print(f.decrypt(chunk_msg).decode() + "\n>>")
                                self.key_symmetric = None
                                self.flag_signed_message = False
                            except InvalidSignature:
                                print('Assinatura da chave simétrica inválida!')
                                break
                except:
                    traceback.print_exc(file=sys.stdout)
                    break

class Client(threading.Thread):
    def connect(self, host, port):
        self.sock.connect((host, port))

    def client(self, host, port, msg, srv):
        if not srv.flag_public_key_sent and srv.public_key_extern_bytes is not None:
            # função que envia a chave pública gerada de um cliente para outro
            # o objetivo dela é tentar enviar essa chave até que o valor da flag da chave pública mude
            self.sock.send(srv.public_key_bytes)
            srv.flag_public_key_sent = True
            time.sleep(0.5)
        elif srv.flag_public_key_sent and srv.public_key_extern:
            # verificação do envio da chave pública do cliente em relação ao recebimento do outro, ou seja, se já foi enviada e recebida
            key = Fernet.generate_key()
            f = Fernet(key)
            encrypt_key = srv.public_key_extern.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            self.sock.send(encrypt_key) # envia a chave simétrica por um meio não seguro (seguro), porém com a chave encriptada por meio da chave pública do outro cliente
            time.sleep(0.5)
            sign = srv.private_key.sign(key, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()) # assina a chave simétrica (decriptada) e armazena em uma variável denominada sign

            # criptografa a mensagem através da chave simétrica
            msg_encrypt = f.encrypt(msg)
            str_msg_sign = base64.b64encode(sign).decode() + "----" + base64.b64encode(msg_encrypt).decode() # concatena a assinatura com a mensagem, ambas decodificadas através da codificação base64 e separadas através do limitador "----" definido

            self.sock.send(str_msg_sign.encode()) # envia a concatenação codificada
            time.sleep(0.5)

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        host = '127.0.0.1'
        port = 5535

        print("Connecting\n")
        s = ''
        self.connect(host, port)
        print("Connected\n")
        user_name = input("Enter the User Name to be Used\n>>")
        receive = self.sock
        time.sleep(1)
        srv = Server()
        srv.initialise(receive)
        srv.daemon = True
        print("Starting service")
        srv.generate_key()
        srv.start()
        self.sock.send(srv.public_key_bytes)
        time.sleep(0.5)
        while not srv.flag_public_key_sent:
            time.sleep(0.5)
            self.client(host, port, b'', srv)
        while 1:
            # print "Waiting for message\n"
            msg = input('>>')
            if msg == 'exit':
                break
            if msg == '':
                continue
            # print "Sending\n"
            msg = user_name + ': ' + msg
            data = msg.encode()
            self.client(host, port, data, srv)

        return (1)

if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()