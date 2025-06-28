#
# Copyright (c) 2018-2025, NVIDIA Corporation.  All Rights Reserved.
#
# NVIDIA Corporation and its licensors retain all intellectual property
# and proprietary rights in and to this software, related documentation
# and any modifications thereto.  Any use, reproduction, disclosure or
# distribution of this software and related documentation without an express
# license agreement from NVIDIA Corporation is strictly prohibited.
#
from tegrasign_v3_util import *
import hashlib
import pkcs11
from pkcs11.util.rsa import encode_rsa_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import ctypes
import os

'''
@Description
The purpose of this file is to supply a list of API hooks and reference implementations
that may be useful for running with an HSM server.
As such, the API hooks are identified as required, and will be denoted with [REQUIRE]
tag below in the individual comment's @note section, whereas reference implementations
will be denoted as [REFERENCE].

@Rationale
The API hooks are required because they are used in the tegrasign_v3 scripts and OEMs
can optionally replace with their implementation. This decision is purely based on OEMs.
The reference implementations are used in the API hooks to mimic HSM operations, but
how the actual HSM servers will handle such the operations are HSM-specific.

@Note
The API hooks are secure boot operation related, yet not all are required for an OEM to
overwrite. The actual list is dependent on which secure boot scheme is chosen by the OEM.

Below is a list of API hooks in this file:
    do_hmac_sha256_hsm
    do_random_hsm
    do_aes_gcm_hsm
    do_rsa_pss_hsm
    *do_ed25519_hsm - Not supported
    get_rsa_mod_hsm
    get_rsa_mod_from_pubkey_hsm
    get_rsa_mont_hsm
    get_rsa_mont_from_pubkey_hsm
    *get_ed25519_pub_hsm - Not supported
    oem_hsm_kdf
    oem_hsm_aes_gcm
    oem_hsm_hmacsha

Below is a list of reference implementations in this file:
    *get_key_file_hsm - Not supported
    get_key_content
    hsm_server_store_derived_key_to_key_database
    hsm_server_search_key_database
    nist_sp800_108_kdf
    get_fskpkey_hsm_server
    get_sbk_hsm_server
    send_to_hsm_server_kdf
    hsm_server_aes_gcm
    send_to_hsm_server_aes_gcm
    send_to_hsm_server_hmacsha

Below is a simple partial breakdown for clarity:

hsm.py        -->  HSM/some secure host       -->  HSM server
(API hook)         (Reference API)                 (Reference API)
==============     ===========================     =================================================
oem_hsm_kdf()      send_to_hsm_server_kdf()        hsm_server_search_key_database() + key derivation
oem_hsm_aes_gc()   send_to_hsm_server_aes_gcm()    hsm_server_search_key_database() + encryption
oem_hsm_hmacsh()   send_to_hsm_server_hmacsha()    hsm_server_search_key_database() + hmac-sha

Below is a simple flow to illustrate how to enable SoftHSM for image signing/encryption:

1. install softhsm package
2. install pkcs11 python module
3. configure softhsm
4. create token with defining user pin
5. enroll keys
6. set is_softhsm_on=True in tegrasign_v3_softhsm.py
Then refers to README for mode details.

Below is a sample of environment setting for HSM (based on SoftHSM solution):

hsm_token_label = "HSM" # The token name which is in SoftHSM to store keys.
hsm_lib_path = "/usr/lib/softhsm/libsofthsm2.so" # The library path of SoftHSM.
hsm_user_pin = "1234" # The user pin number to access the token and the keys.

'''

# This is a configuration file that defines NV debug keys
NV_DEBUG_YAML = 'tegrasign_v3_debug.yaml'


# These are env setup variables for SoftHSM connection
hsm_token_label = "HSM"
hsm_lib_path = "/usr/lib/softhsm/libsofthsm2.so"
hsm_user_pin = "1234"

# Crypto function
def aes_gcm_hsm(key_label, iv, aad, plaintext):
    # Load the PKCS#11 library
    pkcs11 = ctypes.CDLL(hsm_lib_path)

    # Define constants
    CKR_OK = 0
    CKF_SERIAL_SESSION = 0x00000004
    CKF_RW_SESSION = 0x00000002
    CKU_USER = 1
    CKK_AES = 0x0000001F
    CKO_SECRET_KEY = 0x00000004
    CKM_AES_GCM = 0x00001087

    class CK_SESSION_HANDLE(ctypes.Structure):
        _fields_ = [("handle", ctypes.c_ulong)]

    class CK_MECHANISM(ctypes.Structure):
        _fields_ = [("mechanism", ctypes.c_ulong), ("pParameter", ctypes.c_void_p), ("ulParameterLen", ctypes.c_ulong)]

    class CK_GCM_PARAMS(ctypes.Structure):
        _fields_ = [("pIv", ctypes.POINTER(ctypes.c_ubyte)), ("ulIvLen", ctypes.c_ulong), ("ulIvBits", ctypes.c_ulong),
                    ("pAAD", ctypes.POINTER(ctypes.c_ubyte)), ("ulAADLen", ctypes.c_ulong), ("ulTagBits", ctypes.c_ulong)]

    class CK_ATTRIBUTE(ctypes.Structure):
        _fields_ = [("type", ctypes.c_ulong), ("pValue", ctypes.c_void_p), ("ulValueLen", ctypes.c_ulong)]

    class CK_TOKEN_INFO(ctypes.Structure):
        _fields_ = [
            ("label", ctypes.c_char * 32),
            ("manufacturerID", ctypes.c_char * 32),
            ("model", ctypes.c_char * 16),
            ("serialNumber", ctypes.c_char * 16),
            ("flags", ctypes.c_ulong),
            ("ulMaxSessionCount", ctypes.c_ulong),
            ("ulSessionCount", ctypes.c_ulong),
            ("ulMaxRwSessionCount", ctypes.c_ulong),
            ("ulRwSessionCount", ctypes.c_ulong),
            ("ulMaxPinLen", ctypes.c_ulong),
            ("ulMinPinLen", ctypes.c_ulong),
            ("ulTotalPublicMemory", ctypes.c_ulong),
            ("ulFreePublicMemory", ctypes.c_ulong),
            ("ulTotalPrivateMemory", ctypes.c_ulong),
            ("ulFreePrivateMemory", ctypes.c_ulong),
            ("hardwareVersion", ctypes.c_ubyte * 2),
            ("firmwareVersion", ctypes.c_ubyte * 2),
            ("utcTime", ctypes.c_char * 16)
        ]

    # Initialize the library
    pkcs11.C_Initialize(None)

    # Find key slot with token name
    slot_list = (ctypes.c_ulong * 256)() # Assume there are at most 256 slots
    slot_count = ctypes.c_ulong(len(slot_list))
    pkcs11.C_GetSlotList(True, slot_list, ctypes.byref(slot_count))

    # Search key slot by token name
    token_name = hsm_token_label
    for slot in slot_list[:slot_count.value]:
        token_info = CK_TOKEN_INFO()
        pkcs11.C_GetTokenInfo(slot, ctypes.byref(token_info))
        if token_info.label.decode('utf-8').strip() == token_name:
            slot_num = slot
            break

    # Open a session with the token
    session = CK_SESSION_HANDLE()
    ret = pkcs11.C_OpenSession(slot_num, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(session))
    if ret != CKR_OK:
        raise RuntimeError(f"Failed to open session: {ret}")

    # Login to the session
    ret = pkcs11.C_Login(session, CKU_USER, bytes(hsm_user_pin, 'utf-8'), len(bytes(hsm_user_pin, 'utf-8')))
    if ret != CKR_OK:
        raise RuntimeError(f"Failed to login: {ret}")

    # Prepare the search template
    label = bytes(key_label, 'utf-8')
    label_attr = CK_ATTRIBUTE(
        type=0x00000003,  # CKA_LABEL
        pValue=ctypes.cast(ctypes.create_string_buffer(label), ctypes.c_void_p),
        ulValueLen=len(label)
    )

    key = ctypes.c_ulong()

    # Find the AES key
    ret = pkcs11.C_FindObjectsInit(session, ctypes.byref(label_attr), 1)
    if ret != CKR_OK:
        raise RuntimeError(f"Failed to find object init: {ret}")
    ret = pkcs11.C_FindObjects(session, ctypes.byref(key), 1, ctypes.byref(ctypes.c_ulong(1)))
    if ret != CKR_OK:
        raise RuntimeError(f"Failed to find object: {ret}")
    ret = pkcs11.C_FindObjectsFinal(session)
    if ret != CKR_OK:
        raise RuntimeError(f"Failed to find object final: {ret}")

    # Debug code to get key value **************
    CKA_VALUE = 0x00000011  # CKA_VALUE constant

    # Prepare the attribute to hold the value
    value_len = ctypes.c_ulong(0)

    # First, get the size of the key value
    value_attr = CK_ATTRIBUTE(type=CKA_VALUE, pValue=None, ulValueLen=0)
    ret = pkcs11.C_GetAttributeValue(session, key, ctypes.byref(value_attr), 1)
    if ret != CKR_OK:
        raise RuntimeError(f"Failed to get attribute size: {ret}")

    # Allocate buffer to hold the key value
    buffer = ctypes.create_string_buffer(value_attr.ulValueLen)

    # Set the attribute to retrieve the key value
    value_attr.pValue = ctypes.cast(buffer, ctypes.c_void_p)
    value_attr.ulValueLen = len(buffer)

    # Get the key value
    ret = pkcs11.C_GetAttributeValue(session, key, ctypes.byref(value_attr), 1)
    if ret != CKR_OK:
        raise RuntimeError(f"Failed to get key value: {ret}")

    # Prepare GCM parameters
    iv_len = int(len(iv)/2)
    aad_len = int(len(aad)/2)
    iv_buffer = (ctypes.c_ubyte * iv_len).from_buffer_copy(bytes.fromhex(iv))
    aad_buffer = (ctypes.c_ubyte * aad_len).from_buffer_copy(bytes.fromhex(aad))
    gcm_params = CK_GCM_PARAMS(
        pIv=ctypes.cast(iv_buffer, ctypes.POINTER(ctypes.c_ubyte)),
        ulIvLen=iv_len,
        ulIvBits=iv_len * 8,
        pAAD=ctypes.cast(aad_buffer, ctypes.POINTER(ctypes.c_ubyte)),
        ulAADLen=aad_len,
        ulTagBits=128
    )

    mechanism = CK_MECHANISM(CKM_AES_GCM, ctypes.cast(ctypes.byref(gcm_params), ctypes.c_void_p), ctypes.sizeof(gcm_params))

    # Perform AES-GCM encryption
    ciphertext_len = ctypes.c_ulong()

    ret = pkcs11.C_EncryptInit(session, ctypes.byref(mechanism), key)
    if ret != CKR_OK:
        raise RuntimeError(f"EncryptionInit failed with code: {ret}")

    # Get ciphertext length
    ret = pkcs11.C_Encrypt(session, bytes(plaintext), len(plaintext), None, ctypes.byref(ciphertext_len))
    if ret != CKR_OK:
        raise RuntimeError(f"Encryption failed with code: {ret}")

    ciphertext = ctypes.create_string_buffer(ciphertext_len.value)

    # Performa AES GCM encryption
    ret = pkcs11.C_Encrypt(session, bytes(plaintext), len(plaintext), ciphertext, ctypes.byref(ciphertext_len))
    if ret != CKR_OK:
        raise RuntimeError(f"Encryption failed with code: {ret}")

    # Extract the tag from the end of ciphertext
    tag = ciphertext.raw[-16:]
    encrypted_content = ciphertext.raw[:-16]

    # Logout and close the session
    pkcs11.C_Logout(session)
    pkcs11.C_CloseSession(session)
    return encrypted_content, tag.hex()


'''
@brief The routine that calculate montgomery value from rsa public key

@param[in] public_key Public key of PKC extractd from HSM
@param[in] rsa_byte_count It should 384 bytes

@retval mont_buf The buffer after operation
'''
def rsa_montgomery(public_key, rsa_byte_count):
    # Extract modulus (n)
    modulus = public_key.public_numbers().n
    modulus_bytes = modulus.to_bytes(rsa_byte_count, byteorder='big')

    # Create a context for big integer operations
    # Prepare R = 2^(rsa_byte_count * 8)
    R = 1 << (rsa_byte_count * 8)

    # Convert modulus to a big integer
    n = int.from_bytes(modulus_bytes, byteorder='big')

    # Compute R^2 mod n
    R2 = (R * R) % n

    # Compute the modular inverse of R modulo n
    try:
        Ri = pow(R, -1, n)  # R inverse mod n
    except ValueError:
        # If inverse does not exist, return failure
        return None

    # Shift Ri left by rsa_byte_count * 8 bits
    Ri <<= (rsa_byte_count * 8)

    # Subtract 1 from Ri
    Ri -= 1

    # Ni = (R * Ri - 1) / n
    Ni = (Ri) // n

    # Convert Ni and R^2 back to byte arrays
    mprime = Ni.to_bytes(rsa_byte_count, byteorder='little')
    rsquare = R2.to_bytes(rsa_byte_count, byteorder='little')

    mont_buf = mprime + rsquare
    return mont_buf

'''
@brief The routine that maps the key file to key type
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] p_key SignKey class which has info needed: filename, type
@Note: There are three ways to mimic HSM code path:
1) use tegrasign_v3_debug.yaml, which is NV approach to mimic HSM behavior.
   The file format is of the following:
    {"HSM":
        {
            "SBK_KEY"     : "/media/automotive/sbk_hsm.key",
            "KEK0_KEY"    : "/media/automotive/kek0_hsm.key",
            "FSKP_AK_KEY" : "/media/automotive/fskp_ak_hsm.key",
            "FSKP_EK_KEY" : "/media/automotive/fskp_ek_hsm.key",
            "FSKP_KDK_KEY": "/media/automotive/fskp_kdk_hsm.key",
            "FSKP_KEY"    : "/media/automotive/fskp_hsm.key",
            "PKC_KEY"     : "/media/automotive/pkc_hsm.key",
            "PKC_PUBKEY"  : "/media/automotive/pkc_hsm.pubkey",
            "ED25519_KEY" : "/media/automotive/ed25519_hsm.key"
        }
    }
2) specify key path via --key <file_name>
3) ovewrite p_key.filename = p_key.filename in the following routine

@retval key file path
'''
def get_key_file_hsm(p_key, is_priv_key=True):
    if (p_key.hsm.is_algo_only()):
        return p_key.filename

    key_type = p_key.hsm.get_type()

    # First check if the file is 'None', if so no need to modify
    if (p_key.filename == 'None'):
        return p_key.filename

    # Next check if NV debug file is present
    yaml_path = search_file(NV_DEBUG_YAML)
    if os.path.isfile(yaml_path):
        try:
            import yaml
            with open(yaml_path) as f:
                params = yaml.safe_load(f)
                if (key_type == KeyType.SBK):
                    p_key.filename = params['HSM']['SBK_KEY']
                elif (key_type == KeyType.KEK0):
                    p_key.filename = params['HSM']['KEK0_KEY']
                elif (key_type == KeyType.FSKP_AK):
                    p_key.filename = params['HSM']['FSKP_AK_KEY']
                elif (key_type == KeyType.FSKP_EK):
                    p_key.filename = params['HSM']['FSKP_EK_KEY']
                elif (key_type == KeyType.FSKP_KDK):
                    p_key.filename = params['HSM']['FSKP_KDK_KEY']
                elif (key_type == KeyType.FSKP):
                    p_key.filename = params['HSM']['FSKP_KEY']
                elif (key_type == KeyType.PKC):
                    if is_priv_key:
                        p_key.filename = params['HSM']['PKC_KEY']
                    else:
                        p_key.filename = params['HSM']['PKC_PUBKEY']
                elif (key_type == KeyType.ED25519):
                    p_key.filename = params['HSM']['ED25519_KEY']
                elif (key_type == KeyType.PV_ENC_KEY):
                    p_key.filename = params['HSM']['PV_ENC_KEY']
        except Exception as e:
            raise tegrasign_exception('Please check file content for ' + key_type + ' define in ' + NV_DEBUG_YAML)
    else:
        if (key_type == KeyType.SBK):
            p_key.filename = p_key.filename
        elif (key_type == KeyType.KEK0):
            p_key.filename = p_key.filename
        elif (key_type == KeyType.FSKP_AK):
            p_key.filename = p_key.filename
        elif (key_type == KeyType.FSKP_EK):
            p_key.filename = p_key.filename
        elif (key_type == KeyType.FSKP_KDK):
            p_key.filename = p_key.filename
        elif (key_type == KeyType.FSKP):
            p_key.filename = p_key.filename
        elif (key_type == KeyType.PKC):
            if is_priv_key:
                p_key.filename = p_key.filename
            else:
                p_key.filename = p_key.filename
        elif (key_type == KeyType.ED25519):
            p_key.filename = p_key.filename
    if (p_key.filename == None):
        raise tegrasign_exception('[HSM] ERROR: ' + key_type
            + ' does not have key path specified. Please either specify --key <filename>, or define in get_key_file_hsm(), or in '
            +  NV_DEBUG_YAML)

'''
@brief The routine that reads the sbk/kek0/fskp key content
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] key_file The file to be read

@retval key The buffer that is read in string format
'''
def get_key_content(p_key):
    try:
        # to connect to SoftHSM
        lib = pkcs11.lib(hsm_lib_path)
        token = lib.get_token(token_label=hsm_token_label)
        with token.open(user_pin=hsm_user_pin) as session:
            key = session.get_key(label=p_key.hsm.get_type(), key_type=pkcs11.KeyType.AES)
            key_value = key[pkcs11.Attribute.VALUE]
            key_value_hex = key_value.hex()

        return key_value_hex

    except Exception as e:
        info_print('[HSM] Error to extract content from %s: %s' %(p_key.hsm.get_type(), str(e)))
        return None

'''
@brief The routine that invokes hmacsha on the buffer

@param[in] buf Buffer to be operated on
@param[in] p_key SignKey class which has info needed: filename, mode

@param[in] use_der_key Boolean flag indicating if reading the key from the file path defined for HSM,
           or use the key value from SignKey
           The true flag indicates taking the key value from the SignKey as this value is previously
           derived from an operation
           The false flag indicates reading the key from the file path defined for HSM operation

@retval hmac The buffer after operation
'''
def do_hmac_sha256_hsm(buf, p_key, use_der_key = False):
    if (use_der_key == True):
        key = hex_to_str(p_key.key.aeskey)
    else:
        key_type = p_key.hsm.get_type()
        key = get_key_content(p_key)

    try:
        # to connect to SoftHSM
        lib = pkcs11.lib(hsm_lib_path)
        token = lib.get_token(token_label=hsm_token_label)
        # To create a key from "key" variable for hmac sha256 usage
        # Because SBK key didn't have "sign" attribute,
        # need to import it with sign attribute into HSM
        # This is a temporary key, so no need to set Attribute.TOKEN
        with token.open(user_pin=hsm_user_pin) as session:
            hsm_hmac_label = 'HMAC_KEY'
            key_content = bytes.fromhex(key)
            key = session.create_object({
                pkcs11.Attribute.CLASS: pkcs11.constants.ObjectClass.SECRET_KEY,
                pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.GENERIC_SECRET,
                pkcs11.Attribute.VALUE: key_content,
                pkcs11.Attribute.LABEL: hsm_hmac_label,
                pkcs11.Attribute.SENSITIVE: True,
                pkcs11.Attribute.EXTRACTABLE: True,
                pkcs11.Attribute.SIGN: True
            })
            hmac_key = session.get_key(label=hsm_hmac_label, \
                                       key_type=pkcs11.KeyType.GENERIC_SECRET)
            hmac = hmac_key.sign(buf, mechanism=pkcs11.Mechanism.SHA256_HMAC)
        return hmac

    except Exception as e:
        info_print('[HSM] Error in calculating hmac sha256: %s' %(str(e)))
        return None

'''
@brief The routine that invokes random string generation

@param[in] p_key SignKey class which has info needed: ran.size, ran.count
@note
   size = byte size of the random string
   count = number of random strings to be generated

@param[out] p_key.ran.buf This holds the random hex arrays of ran.size length by ran.count:

@retval None
'''
def do_random_hsm(p_key, is_random = True):
    p_key.ran.buf = bytearray(p_key.ran.size * p_key.ran.count)

    try:
        # to connect to SoftHSM
        lib = pkcs11.lib(hsm_lib_path)
        token = lib.get_token(token_label=hsm_token_label)
        for i in range(p_key.ran.count):
            if is_random is True:
                with token.open(user_pin=hsm_user_pin) as session:
                    buf = session.generate_random(p_key.ran.size * 8) # length in bits
            else:
                buf = bytearray(p_key.ran.size) # zero byte array
            start = i * p_key.ran.size
            p_key.ran.buf[start:start+p_key.ran.size] = buf[:]
    except Exception as e:
        info_print('[HSM] Error in generating random number: %s' %(str(e)))

'''
@brief The routine that invokes aes-gcm on the buffer
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] buf Buffer to be operated on
@param[in] p_key SignKey class which has info needed: filename, mode, iv, aad, tag, verify
@note
   iv field is expected to be the random value
   tag field should be filled with the generated value

@param[in] use_der_key Boolean flag indicating if reading the key from the file path defined for HSM,
           or use the key value from SignKey
           The true flag indicates taking the key value from the SignKey as this value is previously
           derived from an operation
           The false flag indicates reading the key from the file path defined for HSM operation

@retval buf_enc The buffer after operation
'''
def do_aes_gcm_hsm(buf, p_key, iv, aad):
    key_id = p_key.hsm.get_type()
    if (use_der_key == True):
        # Use user derived key as aes gcm encryption key
        # Send the key to HSM for later encryption operation
        key_id = 'USER_DER_KEY'
        hsm_server_store_derived_key_to_key_database(key_id, p_key.key.aeskey)

    buff_sig, tag = aes_gcm_hsm(key_id, iv, aad, bytes(buf))

    p_key.kdf.tag.set_buf(str_to_hex(tag))
    return buff_sig

'''
@brief The routine that invokes aescbc on the buffer

@param[in] buf Buffer to be operated on
@param[in] iv The existing iv
@param[in] p_key SignKey class which has info needed: filename, mode

@retval cmac The buffer after operation
'''
def do_aes_cbc_hsm(buf, iv, p_key):
    try:
        # to connect to SoftHSM
        lib = pkcs11.lib(hsm_lib_path)
        token = lib.get_token(token_label=hsm_token_label)
        key_label = p_key.hsm.get_type()
        with token.open(user_pin=hsm_user_pin) as session:
            # Create zero key for cmac calculation if key content is zero
            if is_zero_aes(p_key):
                key_label = 'ZERO_KEY'
                key_length = len(binascii.hexlify(p_key.key.aeskey))
                key_content = '0' * key_length
                aes_key_value = bytes.fromhex(key_content)
                cmac_key = session.create_object({
                    pkcs11.Attribute.CLASS: pkcs11.constants.ObjectClass.SECRET_KEY,
                    pkcs11.Attribute.KEY_TYPE: KeyType.AES,
                    pkcs11.Attribute.VALUE: aes_key_value,
                    pkcs11.Attribute.LABEL: key_label,
                    pkcs11.Attribute.SENSITIVE: False,
                    pkcs11.Attribute.EXTRACTABLE: True,
                    pkcs11.Attribute.SIGN: True
                })
            key = session.get_key(label=key_label, key_type=pkcs11.KeyType.AES)
            cbc = key.encrypt(buf, mechanism=pkcs11.Mechanism.AES_CBC, mechanism_param=iv)
        return cbc

    except Exception as e:
        info_print('[HSM] Error in do_aes_cbc_hsm: %s' %(str(e)))
        return None

'''
@brief The routine that invokes aescmac on the buffer

@param[in] buf Buffer to be operated on
@param[in] p_key SignKey class which has info needed: filename, mode

@retval cmac The buffer after operation
'''
def do_aes_cmac_hsm(buf, p_key):
    # TODO: to add an interface to import key or get key label from p_key
    # Now it's "sbk" inside HSM
    try:
        # to connect to SoftHSM
        lib = pkcs11.lib(hsm_lib_path)
        token = lib.get_token(token_label=hsm_token_label)
        with token.open(user_pin=hsm_user_pin) as session:
            key = session.get_key(label=p_key.hsm.get_type(), key_type=pkcs11.KeyType.AES)
            cmac = key.sign(buf, mechanism=pkcs11.Mechanism.AES_CMAC)
        return cmac

    except Exception as e:
        info_print('[HSM] Error in do_aes_cmac_hsm: %s' %(str(e)))
        return None

'''
@brief The routine that invokes rsa-pss on the buffer

@param[in] buf Buffer to be operated on
@param[in] p_key SignKey class which has info needed: filename, sha mode

@retval sig_data The buffer after operation
'''
def do_rsa_pss_hsm(buf, p_key):
    if (p_key.key.pkckey.Sha == Sha._256):
        sha_mechanism = pkcs11.Mechanism.SHA256
        sha_mfg = pkcs11.MGF.SHA256
    else:
        sha_mechanism = pkcs11.Mechanism.SHA512
        sha_mfg = pkcs11.MGF.SHA512

    try:
        lib = pkcs11.lib(hsm_lib_path)
        token = lib.get_token(token_label=hsm_token_label)
        with token.open(user_pin=hsm_user_pin) as session:
            hash_data = session.digest(buf, mechanism=sha_mechanism)
            private_key = session.get_key(label=p_key.hsm.get_type(), key_type=pkcs11.KeyType.RSA, \
                                          object_class=pkcs11.ObjectClass.PRIVATE_KEY)
            # Salt length is a fixed value - 32
            signature = private_key.sign(hash_data, mechanism=pkcs11.Mechanism.RSA_PKCS_PSS, \
                                         mechanism_param=(sha_mechanism, sha_mfg, 32))

        sig_data = swapbytes(bytearray(signature))
        return sig_data

    except Exception as e:
        info_print('[HSM] Error in rsa pss signing: %s' %(str(e)))
        return None

'''
@brief The routine that invokes ed25519 on the buffer
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] buf Buffer to be operated on
@param[in] p_key SignKey class which has info needed: filename

@retval sig_data The buffer after operation
'''
def do_ed25519_hsm(buf, p_key):
    info_print('[HSM] Error do_ed25519_hsm is not supported yet')
    return None

'''
@brief The routine that generates the public modulus for the RSA private key

@param[in] p_key SignKey class which has info needed: filename, and keysize is updated
@param[in] pub_modf RSA public key filename

@retval True for success, False otherwise
'''
def get_rsa_mod_hsm(p_key, pub_modf=None):
    try:
        # to connect to SoftHSM
        lib = pkcs11.lib(hsm_lib_path)
        token = lib.get_token(token_label=hsm_token_label)
        with token.open(user_pin=hsm_user_pin) as session:
            pub = session.get_key(label=p_key.hsm.get_type(), key_type=pkcs11.KeyType.RSA,
                               object_class=pkcs11.ObjectClass.PUBLIC_KEY)
            pub = encode_rsa_public_key(pub)
            public_key = serialization.load_der_public_key(pub, backend=default_backend())
            modulus = public_key.public_numbers().n
            modulus_hex = hex(modulus)[2:].upper()
            rsa_n_bin = swapbytes(bytearray(binascii.unhexlify(str(modulus_hex))))

            if pub_modf:
                with open_file(pub_modf, 'wb') as f:
                    write_file(f, rsa_n_bin)
            return True
    except Exception as e:
        info_print("[HSM] Error to get rsa key modulus: %s" %(str(e)))
        return False

'''
@brief The routine that generates the Montgomery values from the RSA key passed in
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] p_key SignKey class which has info needed: filename, and keysize is updated
@param[in] pub_montf RSA Montgomery filename

@retval True for success, False otherwise
'''
def get_rsa_mont_hsm(p_key, pub_montf):
    try:
        lib = pkcs11.lib(hsm_lib_path)
        token = lib.get_token(token_label=hsm_token_label)
        with token.open(user_pin=hsm_user_pin) as session:
            pub = session.get_key(label=p_key.hsm.get_type(),
                               key_type=pkcs11.KeyType.RSA,
                               object_class=pkcs11.ObjectClass.PUBLIC_KEY)
            rsa_key_bits = pub.key_length
            pub = encode_rsa_public_key(pub)
            public_key = serialization.load_der_public_key(pub, backend=default_backend())
            # Get rsa key length in byte
            rsa_byte_count = int(rsa_key_bits / 8)
            mont = rsa_montgomery(public_key, rsa_byte_count)

            if pub_montf:
                with open_file(pub_montf, 'wb') as f:
                    f.write(mont)
            return True

    except Exception as e:
        info_print("[HSM] Error to get rsa mont: %s" %(str(e)))
        return False

'''
@brief The routine that generates the public modulus for the RSA public key

@param[in] p_key SignKey class which has info needed: filename, and keysize is updated
@param[in] pub_modf RSA public key filename

@retval True for success, False otherwise
'''
def get_rsa_mod_from_pubkey_hsm(p_key, pub_modf=None):
    try:
        # to connect to SoftHSM
        lib = pkcs11.lib(hsm_lib_path)
        token = lib.get_token(token_label=hsm_token_label)
        with token.open(user_pin=hsm_user_pin) as session:
            pub = session.get_key(label=p_key.hsm.get_type(),
                               key_type=pkcs11.KeyType.RSA,
                               object_class=pkcs11.ObjectClass.PUBLIC_KEY)
            pub = encode_rsa_public_key(pub)
            public_key = serialization.load_der_public_key(pub, backend=default_backend())
            modulus = public_key.public_numbers().n
            modulus_hex = hex(modulus)[2:].upper()
            rsa_n_bin = swapbytes(bytearray(binascii.unhexlify(str(modulus_hex))))

            if pub_modf:
                with open_file(pub_modf, 'wb') as f:
                    write_file(f, rsa_n_bin)
            return True
    except Exception as e:
        info_print('[HSM] Error to get rsa public key modulus: %s' %(str(e)))
        return False

'''
@brief The routine that generates the Montgomery values from the RSA public key passed in
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] p_key SignKey class which has info needed: filename, and keysize is updated
@param[in] pub_montf RSA Montgomery filename

@retval True for success, False otherwise
'''
def get_rsa_mont_from_pubkey_hsm(p_key, pub_montf):
    try:
        # to connect to SoftHSM
        lib = pkcs11.lib(hsm_lib_path)
        token = lib.get_token(token_label=hsm_token_label)
        with token.open(user_pin=hsm_user_pin) as session:
            pub = session.get_key(label=p_key.hsm.get_type(),
                                key_type=pkcs11.KeyType.RSA,
                                object_class=pkcs11.ObjectClass.PUBLIC_KEY)
            rsa_key_bits = pub.key_length
            pub = encode_rsa_public_key(pub)
            public_key = serialization.load_der_public_key(pub, backend=default_backend())
            # Get rsa key length in byte
            rsa_byte_count = int(rsa_key_bits / 8)
            mont = rsa_montgomery(public_key, rsa_byte_count)

            if pub_montf:
                with open_file(pub_montf, 'wb') as f:
                    f.write(mont)
            return True

    except Exception as e:
        info_print("[HSM] Error to get rsa mont from public key: %s" %(str(e)))
        return False

'''
@brief The routine that generates the public key for the ED25519 key passed in
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] p_key SignKey class which has info needed: filename, and keysize is updated
@param[in] pub_keyf ED25519 public key filename

@retval True for success, False otherwise
'''
def get_ed25519_pub_hsm(p_key, pub_keyf):
    success = False
    info_print('[HSM] Error get_ed25519_pub_hsm is not supported yet')

    return success

'''
@brief The routine stores the [key, value] in the database
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] output_key_id The key to be stored in the database
@param[in] output_key_val The matching key value to be stored in the database

@retval True for success, False otherwise
'''
def hsm_server_store_derived_key_to_key_database(output_key_id, output_key_val):
    try:
        lib = pkcs11.lib(hsm_lib_path)
        token = lib.get_token(token_label=hsm_token_label)
        with token.open(rw=True, user_pin=hsm_user_pin) as session:
            # Delete the object if it already exists
            for obj in session.get_objects({pkcs11.Attribute.LABEL: output_key_id}):
                obj.destroy()

            key = session.create_object({
                pkcs11.Attribute.CLASS: pkcs11.constants.ObjectClass.SECRET_KEY,
                pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.GENERIC_SECRET,
                pkcs11.Attribute.VALUE: output_key_val,
                pkcs11.Attribute.LABEL: output_key_id,
                pkcs11.Attribute.TOKEN: True,
                pkcs11.Attribute.SENSITIVE: False,
                pkcs11.Attribute.EXTRACTABLE: True,
            })

    except Exception as e:
        info_print('[HSM] Error in database writing %s: %s\n' %(output_key_id, str(e)))
        return False

    return True

'''
@brief The routine searches through database for the requesting key

@param[in] in_key_id The key requests in the database

@retval in_key for success, None for not found
'''
def hsm_server_search_key_database(in_key_id):
    try:
        lib = pkcs11.lib(hsm_lib_path)
        token = lib.get_token(token_label=hsm_token_label)
        with token.open(user_pin=hsm_user_pin) as session:
            key = session.get_key(label=in_key_id)
            key_value = key[pkcs11.Attribute.VALUE]
            in_key = key_value.hex()
        return in_key

    except Exception as e:
        info_print('[HSM] Error in searching key %s: %s' %(in_key_id, str(e)))
        return None

'''
@brief The routine implement NIST SP800 108 KDF in counter mode with
# counter encoded as little-endian 32 bit counter
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] input_kdf_key The key value to be operated on
@param[in] in_label Label for the key
@param[in] in_context Context for the key

@retval output_key The finished value
'''
def nist_sp800_108_kdf(input_kdf_key, in_label, in_context):

    HexLabel = True
    HexContext = True
    msgStr = get_composed_msg(in_label, in_context, 256, HexLabel, HexContext)
    msg = str_to_hex(msgStr)

    backup = SignKey()
    backup.key.aeskey = str_to_hex(input_kdf_key)

    backup.keysize = len(backup.key.aeskey)
    output_key = do_hmac_sha256_hsm(msg, backup, True)

    return output_key

'''
@brief The routine obtains FSKP related key string from the HSM server
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] key_type The key type options are: FSKP_KDK, FSKP_EK, FSKP_AK

@retval fskp key in string format
'''
def get_fskpkey_hsm_server(key_type):
    p_key = SignKey()
    p_key.hsm.type = key_type

    return get_key_content(p_key)

'''
@brief The routine obtains SBK key string from the HSM server
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@retval SBK key in string format
'''
def get_sbk_hsm_server():
    p_key = SignKey()
    p_key.hsm.type = KeyType.SBK

    return get_key_content(p_key)

'''
@brief The routine obtains PV_KEY key string from the HSM server

@retval PV_KEY key in string format
'''
def get_pvenckey_hsm_server():
    p_key = SignKey()
    p_key.hsm.type = KeyType.PV_KEY

    return get_key_content(p_key)

'''
@brief The routine requests HSM server to search the key_id in the database
 If it is not found, then HSM server should perform kdf derivation
 and store the [key, value] pair in its database
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] in_key_id A string key ID and is to be used as input key for the KDF.
                     Type: string in ASCII.
                     Example: "SBK", "SBK_BCT_KDK_71f920fa275127a7b60fa4d4d41432a3"

@param[in] in_label The derivation label, to be used as input for the KDF.
                    Type: string of hex bytes.
                    Example: "00000000000000000000000000000000"

@param[in] in_context The derivation context, to be used as input for the KDF.
                      Type: string of hex bytes.
                      Example: "01010000", can be empty - ""

@param[in] output_key_id The string key ID of newly derived and stored inside OEM HSM key.
                         Type: string in ASCII.
                         Example: "SBK_BCT_DK_43c191bf6d6c3f263a8cd0efd4a058ab"
               About producing the output_key_id below:
               case 1) for in_key_id = SBK, FSKP_KDK, FSKP_EK, FSKP_AK, the stored value is fetched
               Note: due to the nature of the key, thus for FSKP_EK, FSKP_AK,
                     no further derivation is needed, while SBK and FSKP_KDK are
                     used for further derivation
               case 2) for other cases, derivation of in_key_id is performed

@retval True for success, False otherwise
'''
def send_to_hsm_server_kdf(in_key_id, in_label, in_context, output_key_id):
    found_cached_key_id = hsm_server_search_key_database(output_key_id)

    # if derived key found then return success
    if found_cached_key_id != None:
        return True

    # SBK - special case - it's imported/generated in OEM
    if in_key_id == KeyType.SBK:
        input_kdf_key = get_sbk_hsm_server() # load secret SBK root key in the HSM

    # Note: If --hsm fskp_kdk is specified, then we search the database for the derived
    # fskp_ek and fskp_ak entries, and creat them if not found. They are defined as:
    #fskp_ek_md5um(fskp_ek_<label>_) or fskp_ak_md5um(fskp_ak_<label>_)
    # Below is a mock up behavior to be implemented by OEMs based on their use case
    elif in_key_id == KeyType.FSKP_KDK:
        input_kdf_key = get_fskpkey_hsm_server(in_key_id) # load secret FSKP key in the HSM

    # If --hsm fskp_ek or --hsm fskp_ak is specified, then the matching entry is searched
    # first with the above naming style. Or if the entries are not found, then we default
    # to search the key file paths then the value is written to the database
    elif in_key_id == KeyType.FSKP_EK:
        output_derived_key = get_fskpkey_hsm_server(in_key_id) # load secret FSKP_EK key in the HSM
        output_derived_key = str_to_hex(output_derived_key)
        return hsm_server_store_derived_key_to_key_database(output_key_id, output_derived_key)
    elif in_key_id == KeyType.FSKP_AK:
        output_derived_key = get_fskpkey_hsm_server(in_key_id) # load secret FSKP key in the HSM
        output_derived_key = str_to_hex(output_derived_key)
        return hsm_server_store_derived_key_to_key_database(output_key_id, output_derived_key)
    else:
        input_kdf_key = hsm_server_search_key_database(in_key_id)
        if input_kdf_key == None: # if search failed - this is unexpected - return FAILURE
            return False # or raise an exception

    output_derived_key = nist_sp800_108_kdf(input_kdf_key, in_label, in_context)

    return hsm_server_store_derived_key_to_key_database(output_key_id, output_derived_key)

'''
@brief The routine requests HSM server to search the key_id in the database
 If it is not found, then HSM server should perform kdf derivation
 and store the {key, value} pair in its database
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation
 OEM HSM KDF must be implemented via NIST SP800 108 KDF in counter mode with
 counter encoded as little-endian 32 bit counter

@param[in] in_key_id A string key ID and is to be used as input key for the KDF.
                     Type: string in ASCII.
                     Example: "SBK", "SBK_BCT_KDK_71f920fa275127a7b60fa4d4d41432a3"

@param[in] in_label The derivation label, to be used as input for the KDF.
                    Type: string of hex bytes.
                    Example: "00000000000000000000000000000000"

@param[in] in_context The derivation context, to be used as input for the KDF.
                      Type: string of hex bytes.
                      Example: "01010000", can be empty - ""

@param[in] output_key_id The string key ID of newly derived and stored inside OEM HSM key.
                         Type: string in ASCII.
                         Example: "SBK_BCT_DK_43c191bf6d6c3f263a8cd0efd4a058ab"
@retval True for success, False otherwise
'''
def oem_hsm_kdf(in_key_id, in_label, in_context, output_key_id):
    # send to OEM HSM device/server
    result_from_hsm_server = send_to_hsm_server_kdf(in_key_id, in_label, in_context, output_key_id)
    return result_from_hsm_server

'''
@brief The routine performs aesgcm operation on the HSM server
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@retval buff_sig for the encrypted buffer
        tag Tag for the tag value
'''
def hsm_server_aes_gcm(plain_text_buf, iv, in_aad, key_id):
    buff_sig, tag = aes_gcm_hsm(key_id, iv, in_aad, plain_text_buf)
    return buff_sig, tag

'''
@brief The routine sends the aesgcm operation request to the HSM server
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] plain_text_buf The input plain text to be encrypted (AES GCM) in binary (byte array) format.
@param[in] in_iv The existing iv
@param[in] in_aad The additional authenticated data (AAD GCM) in binary (byte array) format.

@param[in] key_id The derived key string for this operation
                      Example: "SBK_BCT_DK_43c191bf6d6c3f263a8cd0efd4a058ab"

@retval
       True for success, False otherwise
       encrypted_buf The encrypted data or None
       iv Either it is generated by HSM server in string, or in_iv, or None
       tag The GCM tag, or None
'''
def send_to_hsm_server_aes_gcm(plain_text_buf, in_iv, in_aad, key_id):
    encrypted_buf, tag = hsm_server_aes_gcm(plain_text_buf, in_iv, in_aad, key_id)
    iv = in_iv

    return True, encrypted_buf, iv, tag

'''
@brief The routine requests HSM server to perform the aesgcm operation
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] plain_text_buf The input plain text to be encrypted (AES GCM) in binary (byte array) format.
@param[in] in_aad The additional authenticated data (AAD GCM) in binary (byte array) format.

@param[in] key_id The derived key string for this operation
                      Example: "SBK_BCT_DK_43c191bf6d6c3f263a8cd0efd4a058ab"
@param[in] rdm_iv The flag to indicate if iv will be randomly generated
                      Default to True so iv will be randomly generated

@param[in] in_iv The existing iv
                      Default to None so it's randomly generated later and returned as iv

@retval
       True for success, False otherwise
       encrypted_buf The encrypted data
       iv Either it is generated by HSM server in string, or in_iv
       tag The GCM tag
'''
def oem_hsm_aes_gcm(plain_text_buf, in_iv, in_aad, key_id):
    result, encrypted_buf, iv, tag = send_to_hsm_server_aes_gcm(plain_text_buf, in_iv, in_aad, key_id)
    return result, encrypted_buf, iv, tag

'''
@brief The routine mimics the hmacsha handling on the HSM server.
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] plain_text_buf The input plain text to be operated on in binary (byte array) format.

@param[in] key_id The derived key string for this operation
                      Example: "FSKP_AK_43c191bf6d6c3f263a8cd0efd4a058ab"

@retval
       True for success, False otherwise
       hmac_buf The finished data
'''
def send_to_hsm_server_hmacsha(plain_text_buf, key_id):
    # search for a cached/stored derived key in the HSM device/server key database by key_id
    hmac_key = hsm_server_search_key_database(key_id)
    if hmac_key == None: # if key not found:
        return False, None # return error

    temp_label = 'hmac_tempkey'
    try:
        # to connect to SoftHSM
        lib = pkcs11.lib(hsm_lib_path)
        token = lib.get_token(token_label=hsm_token_label)
        # to create a key from hmac_key value for hmacsha usage
        with token.open(user_pin=hsm_user_pin) as session:
            key_content = bytes.fromhex(hmac_key)
            key = session.create_object({
                pkcs11.Attribute.CLASS: pkcs11.constants.ObjectClass.SECRET_KEY,
                pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.GENERIC_SECRET,
                pkcs11.Attribute.VALUE: key_content,
                pkcs11.Attribute.LABEL: temp_label,
                pkcs11.Attribute.SENSITIVE: True,
                pkcs11.Attribute.EXTRACTABLE: True,
                pkcs11.Attribute.SIGN: True
            })
            hmac_sha_key = session.get_key(label=temp_label, \
                                           key_type=pkcs11.KeyType.GENERIC_SECRET)
            hmac = hmac_sha_key.sign(plain_text_buf, mechanism=pkcs11.Mechanism.SHA256_HMAC)

        return True, hmac

    except Exception as e:
        info_print('[HSM] Error in hmac sha calculation: %s' %(str(e)))
        return False, None

'''
@brief The routine sends the hmacsha request to the HSM server.
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] plain_text_buf The input plain text to be operated on in binary (byte array) format.

@param[in] key_id The derived key string for this operation
                      Example: "FSKP_AK_43c191bf6d6c3f263a8cd0efd4a058ab"

@retval
       hmac_buf The finished data or throws exception for failure
'''
def oem_hsm_hmacsha(plain_text_buf, key_id):
    result, hmac_buf = send_to_hsm_server_hmacsha(plain_text_buf, key_id)
    if result == False:
        raise tegrasign_exception('[HSM] Please check %s for % as hmac-sha operation did not complete' \
        %(TegraSign_v3_Keystore , key_id))
    return hmac_buf
