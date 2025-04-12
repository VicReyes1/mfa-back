from cryptography.fernet import Fernet
import os
import base64

# Obtener la clave del entorno
mfa_key = os.getenv("MFA_SECRET_KEY")

# Validar que exista y tenga el tamaño adecuado
if not mfa_key or len(mfa_key.encode()) < 32:
    raise ValueError("MFA_SECRET_KEY debe estar definida y tener al menos 32 caracteres")

# Crear clave compatible con Fernet
KEY = base64.urlsafe_b64encode(mfa_key[:32].encode())
fernet = Fernet(KEY)

def encrypt_secret(secret):
    return fernet.encrypt(secret.encode()).decode()

def decrypt_secret(token):
    return fernet.decrypt(token.encode()).decode()
