from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import check_password
from CommonApp.models import User
from .models import ReceiverMessage
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import ReceiverMessageSerializer
from cryptography.fernet import Fernet
from functools import wraps
import logging

logger = logging.getLogger(__name__)

# Encryption key
ENCRYPTION_KEY = b'k5PPyDG1cOCPwSP1KWeULwW3EoolbiRxL5OV391YeIk='
cipher = Fernet(ENCRYPTION_KEY)


# Custom Login Required Decorator
def custom_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_id'):
            messages.error(request, 'You must be logged in to access this page.')
            return redirect('receiver_login')
        return view_func(request, *args, **kwargs)
    return wrapper


# Homepage View
def homepage(request):
    return render(request, 'receiver/homepage.html')


# Login View
def login_user(request):
    """Handle user login."""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            user = User.objects.get(username=username)

            if check_password(password, user.password):
                # Set session data for authenticated user
                request.session['user_id'] = user.user_id
                request.session['username'] = user.username
                messages.success(request, 'Login successful!')
                return redirect('receiver_homepage')
            else:
                messages.error(request, 'Invalid password.')

        except User.DoesNotExist:
            messages.error(request, 'Invalid username or password.')
        except Exception as e:
            logger.exception(f"Unexpected error during login: {e}")
            messages.error(request, 'An unexpected error occurred. Please try again.')

    return render(request, 'receiver/login.html')


# Logout View
def logout_user(request):
    """Handle user logout."""
    request.session.flush()
    messages.info(request, 'You have been logged out.')
    return redirect('receiver_homepage')


# View Messages
@custom_login_required
def view_messages(request):
    """Display received messages for the logged-in user with search, filter, sorting, and sender filter."""
    username = request.session.get('username')

    if not username:
        return redirect('receiver_login')

    # Fetch messages for the logged-in user
    messages_received = ReceiverMessage.objects.filter(recipient_username=username)

    # Filter unique senders for dropdown
    senders = messages_received.values('sender_username').distinct()

    # Search
    search_query = request.GET.get('search', '').strip()
    if search_query:
        messages_received = messages_received.filter(decrypted_message__icontains=search_query)

    # Filter by priority
    priority_filter = request.GET.get('priority', '')
    if priority_filter:
        messages_received = messages_received.filter(priority=priority_filter)

    # Filter by sender
    sender_filter = request.GET.get('sender', '')
    if sender_filter:
        messages_received = messages_received.filter(sender_username=sender_filter)

    # Sorting
    sort_option = request.GET.get('sort', '-timestamp')  # Default to newest first
    messages_received = messages_received.order_by(sort_option)

    return render(request, 'receiver/view_messages.html', {
        'messages': messages_received,
        'senders': senders,
    })

# Receive Message API
class ReceiveMessageView(APIView):
    def post(self, request):
        try:
            # Validate required fields
            required_fields = ["sender_username", "recipient_username", "priority", "decrypted_message", "timestamp"]
            for field in required_fields:
                if field not in request.data:
                    return Response({"error": f"Missing field: {field}"}, status=400)

            decrypted_message = cipher.decrypt(request.data.get('decrypted_message').encode()).decode()
            message_data = {
                "sender_username": request.data.get("sender_username"),
                "recipient_username": request.data.get("recipient_username"),
                "priority": request.data.get("priority"),
                "decrypted_message": decrypted_message,
                "timestamp": request.data.get("timestamp"),
            }

            serializer = ReceiverMessageSerializer(data=message_data)
            if serializer.is_valid():
                serializer.save()
                logger.info(f"Message saved successfully: {serializer.data}")
                return Response({"success": "Message received and decrypted successfully"}, status=201)

            logger.warning(f"Validation errors: {serializer.errors}")
            return Response(serializer.errors, status=400)

        except Exception as e:
            logger.exception(f"Error processing message: {e}")
            return Response({"error": str(e)}, status=500)
