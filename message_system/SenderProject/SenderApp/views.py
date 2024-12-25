from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import SenderMessage
from CommonApp.models import User
from .serializers import UserSerializer, SenderMessageSerializer
import requests
from cryptography.fernet import Fernet
from django.core.exceptions import ObjectDoesNotExist

# Encryption key (shared between SenderApp and ReceiverApp)
ENCRYPTION_KEY = b'k5PPyDG1cOCPwSP1KWeULwW3EoolbiRxL5OV391YeIk='
cipher = Fernet(ENCRYPTION_KEY)


class UserView(APIView):
    def post(self, request):
        """Create a new user."""
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        """List all users."""
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)


class SendMessageView(APIView):
    def post(self, request):
        """Send an encrypted message to the recipient and forward it to ReceiverApp."""
        try:
            # Validate request data
            required_fields = ["sender_username", "recipient_username", "message_content", "priority"]
            missing_fields = [field for field in required_fields if field not in request.data]
            if missing_fields:
                return Response({"error": f"Missing fields: {', '.join(missing_fields)}"}, status=400)

            # Validate sender and recipient
            sender = User.objects.get(username=request.data.get("sender_username"))
            recipient = User.objects.get(username=request.data.get("recipient_username"))

            # Encrypt the message
            encrypted_message = cipher.encrypt(request.data.get("message_content").encode()).decode()

            # Prepare and save the message
            message_data = {
                "sender": sender.user_id,
                "recipient_username": recipient.username,
                "priority": request.data.get("priority"),
                "encrypted_message": encrypted_message,
            }
            serializer = SenderMessageSerializer(data=message_data)
            if serializer.is_valid():
                message = serializer.save()

                # Forward the message to ReceiverApp
                receiver_url = "http://127.0.0.1:8001/api/receive_message/"
                response = requests.post(receiver_url, json={
                    "sender_username": sender.username,
                    "recipient_username": recipient.username,
                    "priority": request.data.get("priority"),
                    "decrypted_message": encrypted_message,
                    "timestamp": message.timestamp.isoformat(),
                })

                if response.status_code == 201:
                    return Response({
                        "success": "Message sent successfully and forwarded to ReceiverApp",
                        "message_id": message.id,
                        "recipient": recipient.username,
                    }, status=201)
                else:
                    return Response({
                        "error": f"Failed to forward message to ReceiverApp: {response.text}"
                    }, status=400)

            return Response(serializer.errors, status=400)

        except User.DoesNotExist as e:
            return Response({"error": f"User not found: {str(e)}"}, status=400)
        except requests.RequestException as e:
            return Response({"error": f"Failed to connect to ReceiverApp: {str(e)}"}, status=500)
        except Exception as e:
            return Response({"error": f"Unexpected error: {str(e)}"}, status=500)
