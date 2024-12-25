from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import SenderMessage
from CommonApp.models import User
from .serializers import UserSerializer, SenderMessageSerializer
from cryptography.fernet import Fernet
from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
import requests
import logging

# Logger configuration
logger = logging.getLogger('sending_application')

# Encryption key (shared between SenderApp and ReceiverApp)
ENCRYPTION_KEY = b'k5PPyDG1cOCPwSP1KWeULwW3EoolbiRxL5OV391YeIk='
cipher = Fernet(ENCRYPTION_KEY)


class UserView(APIView):
    def post(self, request):
        """Create a new user."""
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            logger.info("User created successfully: %s", serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        logger.error("User creation failed: %s", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        """List all users."""
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        logger.info("Retrieved %d users", len(users))
        return Response(serializer.data)


class SendMessageView(APIView):
    def post(self, request):
        """Send an encrypted message to the recipient and forward it to ReceiverApp."""
        try:
            # Validate request data
            required_fields = ["sender_username", "recipient_username", "message_content", "priority"]
            missing_fields = [field for field in required_fields if field not in request.data]
            if missing_fields:
                logger.error("Missing fields in request: %s", missing_fields)
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
                receiver_url = settings.RECEIVING_PROJECT_BASE_URL
                headers = {
                    "Authorization": f"Bearer {settings.RECEIVING_APP_TOKEN}",
                    "Content-Type": "application/json",
                }
                response = requests.post(receiver_url, json={
                    "sender_username": sender.username,
                    "recipient_username": recipient.username,
                    "priority": request.data.get("priority"),
                    "decrypted_message": encrypted_message,
                    "timestamp": message.timestamp.isoformat(),
                }, headers=headers)

                if response.status_code == 201:
                    logger.info("Message forwarded successfully to ReceiverApp")
                    return Response({
                        "success": "Message sent successfully and forwarded to ReceiverApp",
                        "message_id": message.id,
                        "recipient": recipient.username,
                    }, status=201)
                else:
                    logger.error("Failed to forward message to ReceiverApp: %s", response.text)
                    return Response({
                        "error": f"Failed to forward message to ReceiverApp: {response.text}"
                    }, status=400)

            logger.error("Message creation failed: %s", serializer.errors)
            return Response(serializer.errors, status=400)

        except User.DoesNotExist as e:
            logger.error("User validation error: %s", e)
            return Response({"error": f"User not found: {str(e)}"}, status=400)
        except requests.RequestException as e:
            logger.error("Connection error with ReceiverApp: %s", e)
            return Response({"error": f"Failed to connect to ReceiverApp: {str(e)}"}, status=500)
        except Exception as e:
            logger.critical("Unexpected error: %s", e, exc_info=True)
            return Response({"error": f"Unexpected error: {str(e)}"}, status=500)
