import pyotp
import jwt
import datetime
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from django.contrib.auth import get_user_model
import json
import os
from .serializers import RegisterSerializer
from rest_framework.response import Response
from rest_framework import status
import qrcode
import base64
from django.conf import settings
from io import BytesIO
from .models import CustomUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.core.cache import cache
from django.utils.timezone import now
from datetime import timedelta
from utils.crypto import decrypt_secret



# Obtener la clave secreta desde las variables de entorno
SECRET_KEY = os.getenv('SECRET_KEY')

if not SECRET_KEY:
    raise ValueError("La variable de entorno SECRET_KEY no está configurada.")

User = get_user_model()

def generate_jwt(payload, minutes=60):
    exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=minutes)
    payload['exp'] = int(exp.timestamp())  # aseguramos formato válido
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')



@api_view(['POST'])
@csrf_exempt
def login_view(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido'}, status=405)

    body = json.loads(request.body)
    username = body.get('username')
    password = body.get('password')

    cache_key = f'login_attempts_{username}'
    attempts_data = cache.get(cache_key, {'count': 0, 'blocked_until': None})

    # Si está bloqueado, devolver tiempo restante
    if attempts_data['blocked_until'] and now() < attempts_data['blocked_until']:
        time_left = int((attempts_data['blocked_until'] - now()).total_seconds())
        return JsonResponse({
            'error': f'Demasiados intentos. Intenta de nuevo en {time_left} segundos.',
            'blocked': True,
            'remaining_attempts': 0
        }, status=429)

    # Autenticación
    user = authenticate(username=username, password=password)

    if user is None:
        attempts_data['count'] += 1

        if attempts_data['count'] >= 3:
            attempts_data['blocked_until'] = now() + timedelta(minutes=5)
            cache.set(cache_key, attempts_data, timeout=300)  # 5 min
            return JsonResponse({
                "error": "Demasiados intentos. Bloqueado por 5 minutos.",
                "blocked": True,
                "remaining_attempts": 0
            }, status=429)

        # Guardar nuevo intento
        cache.set(cache_key, attempts_data, timeout=300)
        remaining_attempts = 3 - attempts_data['count']
        return JsonResponse({
            "error": "Credenciales inválidas",
            "blocked": False,
            "remaining_attempts": remaining_attempts
        }, status=401)

    # Login exitoso: limpiar intentos
    cache.delete(cache_key)

    # Crear tokens
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)

    response = JsonResponse({
        "message": "Login exitoso",
        "mfa": user.mfa_enabled
    })

    # Establecer cookie
    response.set_cookie(
        key='access_token',
        value=access_token,
        httponly=True,
        secure=False,  # ¡cambiar a True en producción!
        samesite='Lax',
        max_age=3600
    )

    return response

@api_view(['POST'])
def verify_mfa(request):
    user = request.user

    token = request.COOKIES.get('access_token')


    if not token:
        return Response({"error": "Token no encontrado en cookies."}, status=401)

    try:
        # Decodificar el token temporal
        decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user_id = decoded.get('user_id')  # Asegúrate de que el JWT incluya 'id' al generarse
        user = CustomUser.objects.get(id=user_id)
    except jwt.ExpiredSignatureError:
        return Response({"error": "Token temporal expirado."}, status=401)
    except jwt.InvalidTokenError:
        return Response({"error": "Token inválido."}, status=401)
    except CustomUser.DoesNotExist:
  
        return Response({"error": "Usuario no encontrado."}, status=404)

    code = request.data.get('code')
    if not code:
        return Response({"error": "Código MFA no proporcionado."}, status=400)

    secret = decrypt_secret(user.mfa_secret)

    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        final_token = jwt.encode({'id': user.id}, settings.SECRET_KEY, algorithm='HS256')
        return Response({"token": final_token}, status=200)
    else:
        return Response({"error": "Código MFA inválido."}, status=400)
    
    
@api_view(['POST'])
def register(request):
    if request.method == 'POST':
        serializer = RegisterSerializer(data=request.data)
        
        if serializer.is_valid():
            # Crea el usuario y lo guarda
            user = serializer.save()
            return Response({"message": "Usuario registrado exitosamente."}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

@api_view(['GET'])
def get_mfa_qr(request):
    user = request.user

    secret = decrypt_secret(user.mfa_secret)

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name="TuAppMFA")

    # Generar imagen QR
    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return Response({"qr": qr_base64})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def activate_mfa(request):

    user = request.user

    # Genera una nueva clave secreta para el usuario si no tiene
    if not user.mfa_secret:
        secret = pyotp.random_base32()
        user.mfa_secret = secret  # Guardamos la clave secreta para TOTP en el usuario

    user.mfa_enabled = True  # Marcamos que MFA está activado
    user.save()

    response = JsonResponse({"message": "MFA activado exitosamente"})

    return response
