from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from .models import CustomUser
import pyotp
from utils.crypto import encrypt_secret

CustomUser = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)  # Campo para confirmar la contraseña

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password', 'password2')
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        """
        Verifica que las contraseñas coincidan
        """
        if data['password'] != data['password2']:
            raise serializers.ValidationError({"password": "Las contraseñas no coinciden."})
        return data

    def create(self, validated_data):
        # Elimina el campo 'password2' porque no es necesario para crear el usuario
        validated_data.pop('password2')
        
        # Crea el usuario con la contraseña encriptada
        user = CustomUser.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']  # Django maneja el hash de la contraseña
        )

        # Genera y guarda la clave secreta para MFA

        secret = pyotp.random_base32()
        encrypted = encrypt_secret(secret)
        user.mfa_secret = encrypted
        user.save()
        
        return user
    
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        user = authenticate(username=data['username'], password=data['password'])
        if not user:
            raise serializers.ValidationError("Credenciales inválidas")
        data['user'] = user
        return data
