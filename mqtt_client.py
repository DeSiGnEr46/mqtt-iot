import paho.mqtt.client as mqtt

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.serialization import(Encoding, PublicFormat, PrivateFormat, NoEncryption)
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# 1. Iot -> S : publish "register" Pu_IoT_DH
# 2. S -> FF :  publish "pu_S" Pu_S_DH
# 3. S, IoT : Generate K_s
# 4. IoT: Generate Code = Random (6 digitos)
# 5. IoT: Show Code
# 6. IoT - S : publish "auth" E_K_S(Code)
# 7. S : Verify Code received = Code shown

import time

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("Pu_IoT_DH")
    client.subscribe("K_Exc")
    client.subscribe("Cypher")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic+" "+str(msg.payload.decode()))
    if msg.topic == "Pu_IoT_DH":
        #El mensaje recibido deben ser los números para crear la clave derivada
        try:
            numbers = str(msg.payload.decode()).split(",")
            p = int(numbers[0])
            g = int(numbers[1])

            pn = dh.DHParameterNumbers(p, g)
            parameters = pn.parameters(default_backend())

            #Si tiene éxito derivamos la clave pública y privada propia
            global private_key, public_key
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            #Clave pública serializada (bytes)
            public_by = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            #La convertimos correctamente a string para enviarla por el canal
            public_str = str(public_by, 'utf-8')
            #La publicamos por el topic correspondiente
            client.publish("K_Exc", public_str, 1)
        except:
            print("Error al generar los parámetros")

    if msg.topic == "K_Exc":
        #El servidor nos ha enviado su clave pública, por lo que podemos derivar la clave común
        if(str(msg.payload.decode()) != public_str): #Comprobamos que no hemos recibido nuestra propia clave
            peer_public_by = bytes(msg.payload, 'utf-8')
            peer_public = load_pem_public_key(peer_public_by, backend=default_backend())

            #Derivamos la clave común
            global shared_key, private_key
            shared_key = private_key.exchange(peer_public)

    if msg.topic == "Cypher":
        #Desencriptamos el mensaje recibido
        global shared_key
        #Obtenemos el mensaje cifrado y el encrypt_and_digest
        ciphertext, tag = str(msg.payload.decode()).split(",")
        cipher = AES.new(shared_key, AES.MODE_EAX, cipher.nonce)
        #Usamos bytes.fromhex para obtener los bytes originales a partir del str hexadecimal
        data = cipher.decrypt_and_verify(bytes.fromhex(ciphertext), bytes.fromhex(tag))
        data = str(data, "utf-8")
        print(data)

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.username_pw_set("try","try")

client.connect("broker.shiftr.io", 1883, 60)

# Si quiero que esté escuchando para siempre:
client.loop_forever()
# http://www.steves-internet-guide.com/loop-python-mqtt-client/

# Inicia una nueva hebra
client.loop_start()

private_key, public_key, shared_key = None

while 1:
    time.sleep(1)

# También se puede conectar y enviar en una linea https://www.eclipse.org/paho/clients/python/docs/#single

# Y conectar y bloquear para leer una sola vez en una sola linea https://www.eclipse.org/paho/clients/python/docs/#simple
