from django.shortcuts import render, redirect
from django.contrib import messages
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import SenderMessage
from CommonApp.models import User as CommonUser
from .serializers import SenderMessageSerializer
import requests
from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.db import transaction
from functools import wraps
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Encryption key
ENCRYPTION_KEY = b'k5PPyDG1cOCPwSP1KWeULwW3EoolbiRxL5OV391YeIk='
cipher = Fernet(ENCRYPTION_KEY)
receiver_url = settings.RECEIVER_APP_URL

# Custom decorator to check login status
def custom_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_id'):
            messages.error(request, 'You must be logged in to access this page.')
            return redirect('sender_login')
        return view_func(request, *args, **kwargs)
    return wrapper

# Homepage View
def homepage(request):
    return render(request, 'sender/homepage.html')

# Login View
def login_user(request):
    """Handle user login."""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            user = CommonUser.objects.get(username=username)
            if check_password(password, user.password):
                request.session['user_id'] = user.user_id
                request.session['username'] = user.username
                messages.success(request, 'Login successful!')
                logger.info(f"User {username} logged in successfully.")
                return redirect('sender_send_message')
            else:
                messages.error(request, 'Invalid credentials.')
                logger.warning(f"Login failed for user {username}: Invalid credentials.")
        except CommonUser.DoesNotExist:
            messages.error(request, 'Invalid credentials.')
            logger.warning(f"Login failed for non-existent user {username}.")

    return render(request, 'sender/login.html')

# Logout View
def logout_user(request):
    """Handle user logout."""
    request.session.flush()
    messages.info(request, 'You have been logged out.')
    logger.info("User logged out.")
    return redirect('sender_homepage')

# Register View
def register_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        if CommonUser.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists. Please choose another.')
            logger.warning(f"Registration failed: Username {username} already exists.")
        else:
            CommonUser.objects.create(username=username, password=password)
            messages.success(request, 'Registration successful! You can now log in.')
            logger.info(f"User {username} registered successfully.")
            return redirect('sender_login')

    return render(request, 'sender/register.html')

# Send Message View
@custom_login_required
def send_message(request):
    """Handle sending encrypted messages."""
    if request.method == 'POST':
        recipient = request.POST.get('recipient')
        message_content = request.POST.get('message_content')
        priority = request.POST.get('priority')
        attachment = request.FILES.get('attachment')

        if not recipient or not message_content or not priority:
            messages.error(request, 'All fields are required.')
            return redirect('sender_send_message')

        if attachment and attachment.size > 5 * 1024 * 1024:  # 5 MB limit
            messages.error(request, 'Attachment size exceeds the 5 MB limit.')
            return redirect('sender_send_message')

        try:
            sender_user = CommonUser.objects.get(user_id=request.session.get('user_id'))
            recipient_user = CommonUser.objects.get(username=recipient)
            encrypted_message = cipher.encrypt(message_content.encode()).decode()

            with transaction.atomic():
                # Save the message locally with timestamp
                saved_message = SenderMessage.objects.create(
                    sender=sender_user,
                    recipient_username=recipient_user.username,
                    priority=priority,
                    encrypted_message=encrypted_message,
                    attachment=attachment,
                )

                # Prepare the payload to send to ReceiverApp
                data = {
                    "sender_username": sender_user.username,
                    "recipient_username": recipient_user.username,
                    "priority": priority,
                    "decrypted_message": encrypted_message,
                    "timestamp": saved_message.timestamp.isoformat(),  # Include the timestamp
                }

                # Handle file attachments
                files = {'attachment': attachment} if attachment else None

                # Forward to ReceiverApp
                response = requests.post(receiver_url, json=data, files=files)

                if response.status_code == 201:
                    messages.success(request, 'Message sent successfully!')
                else:
                    messages.error(request, f'Failed to send message to ReceiverApp: {response.text}')
                    saved_message.delete()  # Cleanup if forwarding fails

        except CommonUser.DoesNotExist:
            messages.error(request, 'Recipient not found.')
        except requests.RequestException as e:
            messages.error(request, f'Error connecting to ReceiverApp: {str(e)}')
        except Exception as e:
            messages.error(request, f'Unexpected error: {str(e)}')

    return render(request, 'sender/send_message.html')