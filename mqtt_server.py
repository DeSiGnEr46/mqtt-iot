import paho.mqtt.client as mqtt

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
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
def on_register(client, userdata, msg):
    print(msg.topic+" "+str(msg.payload))

def on_message(client, userdata, msg):
    if msg.topic == "K_Exc": #Alguien ha recibido nuestros parámetros y nos ha enviado su clave pública, por tanto enviamos la nuestra
        #Enviamos nuestra clave
        global public_by
        public_str = str(public_by, 'utf-8')
        client.publish("K_Exc", public_str, 1)

        #Utilizamos la recibida por el cliente para generar la clave común
        if(str(msg.payload.decode()) != public_str): #Comprobamos que no hemos recibido nuestra propia clave
            peer_public_by = bytes(msg.payload, 'utf-8')
            peer_public = load_pem_public_key(peer_public_by, backend=default_backend())

            #Derivamos la clave común
            global shared_key, private_key
            shared_key = private_key.exchange(peer_public)

            #Enviamos un mensaje cifrado al cliente
            data = bytes("Mensaje secreto!",'utf-8')
            cipher = AES.new(shared_key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            #Es necesario convertir a hex (str) para enviarlo, junto al tag
            payload = ciphertext.hex() + "," + tag.hex()
            client.publish("Cypher", payload, 1)

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
client.on_register = on_register
client.on_message = on_message

client.username_pw_set("try","try")

client.connect("broker.shiftr.io", 1883, 60)

# Si quiero que esté escuchando para siempre:
# client.loop_forever()
# http://www.steves-internet-guide.com/loop-python-mqtt-client/

# Inicia una nueva hebra
client.loop_start()

print("*" * 80)
print("Generando parámetros...")
print("*" * 80)
parameters = dh.generate_parameters(generator=2, key_size=2048,
                                    backend=default_backend())

#Genera su clave privada y pública
print("*" * 80)
print("Generando claves...")
print("*" * 80)
private_key = parameters.generate_private_key()
public_key = private_key.public_key()
#Clave pública serializada (bytes)
public_by = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
shared_key = None #Se generará más tarde


p = parameters.parameter_numbers().p
g = parameters.parameter_numbers().g
numbers = str(p) + "," + str(g)

while 1:
    # Publish a message every second
    # client.publish("Pu_IoT_DH", "Hello Jackeline", 1)
    #Envía los números primos generados cada segundo al topic Pu_IoT_DH
    print("*" * 80)
    print("Publicando números")
    print("*" * 80)
    client.publish("Pu_IoT_DH", numbers, 1)
    time.sleep(5)

# También se puede conectar y enviar en una linea https://www.eclipse.org/paho/clients/python/docs/#single

# Y conectar y bloquear para leer una sola vez en una sola linea https://www.eclipse.org/paho/clients/python/docs/#simple
