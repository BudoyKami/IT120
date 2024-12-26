from rest_framework import serializers
from .models import ReceiverMessage
from CommonApp.models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['user_id', 'username', 'password']

class ReceiverMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReceiverMessage
        fields = '__all__'
