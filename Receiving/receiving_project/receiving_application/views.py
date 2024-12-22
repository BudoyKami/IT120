from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Message
from django.contrib.auth.models import User
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class ReceiveMessageView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Access the decrypted content
            decrypted_content = request.META.get('decrypted_content')
            original_body = request.META.get('original_body', {})

            if not decrypted_content:
                logger.error("Decrypted content is missing in the request.")
                return Response({'error': 'Decrypted content is missing.'}, status=400)

            logger.debug(f"Decrypted Content: {decrypted_content}")
            logger.debug(f"Original Request Body: {original_body}")

            # Extract required fields
            recipient_username = original_body.get('recipient')
            sender_username = original_body.get('sender')
            encrypted_content = original_body.get('content')
            content_hash = original_body.get('hash')
            priority = original_body.get('priority', 'normal')

            if not recipient_username or not sender_username:
                logger.error("Recipient or Sender username is missing in the original payload.")
                return Response({'error': 'Recipient or Sender username is missing.'}, status=400)

            # Validate existence of recipient and sender
            recipient = User.objects.filter(username=recipient_username).first()
            sender = User.objects.filter(username=sender_username).first()

            if not recipient:
                logger.error(f"Recipient with username '{recipient_username}' does not exist.")
                return Response({'error': f"Recipient with username '{recipient_username}' does not exist."}, status=400)

            if not sender:
                logger.error(f"Sender with username '{sender_username}' does not exist.")
                return Response({'error': f"Sender with username '{sender_username}' does not exist."}, status=400)

            logger.info(f"Message received for recipient '{recipient_username}' from sender '{sender_username}'.")

            # Save the message to the database
            Message.objects.create(
                recipient=recipient,
                sender=sender,
                encrypted_content=encrypted_content,
                decrypted_content=decrypted_content,
                content_hash=content_hash,
                priority=priority,
                time_received=datetime.now()
            )
            logger.info("Message saved to the database successfully.")

            return Response({'message': 'Message received and saved successfully', 'status': 'success'}, status=200)

        except Exception as e:
            logger.error(f"Error in ReceiveMessageView: {e}")
            return Response({'error': 'An error occurred while processing the message.'}, status=500)
