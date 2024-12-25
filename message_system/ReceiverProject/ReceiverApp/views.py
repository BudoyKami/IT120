from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import ReceiverMessage
from .serializers import ReceiverMessageSerializer, UserSerializer
from cryptography.fernet import Fernet
from CommonApp.models import User 

# Encryption key (ensure both apps share the same key)
ENCRYPTION_KEY = b'k5PPyDG1cOCPwSP1KWeULwW3EoolbiRxL5OV391YeIk='
cipher = Fernet(ENCRYPTION_KEY)

class UserView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

class ReceiveMessageView(APIView):
    def post(self, request):
        try:
            # Decrypt the message
            decrypted_message = cipher.decrypt(request.data.get("decrypted_message").encode()).decode()

            # Prepare the message data
            message_data = {
                "sender_username": request.data.get("sender_username"),
                "recipient_username": request.data.get("recipient_username"),
                "priority": request.data.get("priority"),
                "decrypted_message": decrypted_message,
                "timestamp": request.data.get("timestamp"),
            }

            # Serialize and validate the data
            serializer = ReceiverMessageSerializer(data=message_data)
            if serializer.is_valid():
                serializer.save()
                return Response({"success": "Message received and decrypted successfully"}, status=201)

            # If validation fails
            return Response(serializer.errors, status=400)

        except KeyError as e:
            # Handle missing fields in the request
            return Response({"error": f"Missing field: {str(e)}"}, status=400)

        except ValueError as e:
            # Handle decryption errors
            return Response({"error": "Invalid encrypted message or decryption failed"}, status=400)

        except Exception as e:
            # Handle unexpected errors
            return Response({"error": str(e)}, status=500)
