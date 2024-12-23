from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Message
from .serializers import MessageSerializer
import requests

class SendMessageView(APIView):
    def post(self, request):
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            # Save the message to the sender's message table
            sender_message = serializer.save()

            # Now send this message to the receiver application (via API)
            receiver_api_url = "http://localhost:8001/api/messages/receive/"  # URL of the receiver's endpoint
            receiver_message_data = {
                'sender': sender_message.sender.id,
                'recipient': sender_message.recipient.id,
                'encrypted_content': sender_message.encrypted_content,
                'status': sender_message.status,
            }

            # Send the message data to the receiver app (POST request)
            response = requests.post(receiver_api_url, data=receiver_message_data)

            if response.status_code == 201:
                return Response({'message': 'Message sent successfully'}, status=status.HTTP_201_CREATED)
            else:
                return Response({'error': 'Failed to send message to receiver'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
