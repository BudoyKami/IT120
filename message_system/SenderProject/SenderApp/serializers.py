from rest_framework import serializers
from .models import SenderMessage
from CommonApp.models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['user_id', 'username', 'password']


class SenderMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = SenderMessage
        fields = '__all__'
