from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.views import View
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib.auth.models import User
from .forms import RegistrationForm
import requests
import logging
from decouple import config
from tenacity import retry, stop_after_attempt, wait_fixed

# Logger setup
logger = logging.getLogger(__name__)

# Environment variables
RECEIVING_APP_TOKEN = config('RECEIVING_APP_TOKEN', default=None)
RECEIVING_PROJECT_BASE_URL = config('RECEIVING_PROJECT_BASE_URL', default='http://127.0.0.1:8001/receive-message/')

if not RECEIVING_APP_TOKEN:
    raise ValueError("RECEIVING_APP_TOKEN is not set in the environment variables.")

# Retry function for sending requests
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))  # Retry up to 3 times with a 2-second interval
def send_request(url, data, headers):
    try:
        response = requests.post(url, data=data, headers=headers, timeout=5)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx, 5xx)
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during request: {str(e)}")
        raise  # Rethrow exception to trigger retry

# Views
class HomeView(View):
    def get(self, request):
        return render(request, 'sending_application/home.html')

class APIHomeView(View):
    def get(self, request):
        return render(request, 'sending_application/api_home.html')

class CustomLogoutView(View):
    def post(self, request):
        logout(request)
        request.session.flush()
        return redirect('home')

class RegisterView(View):
    def get(self, request):
        form = RegistrationForm()
        return render(request, 'sending_application/register.html', {'form': form})

    def post(self, request):
        form = RegistrationForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            user = User.objects.create_user(username=username, password=password)
            login(request, user)
            return redirect('send-message')
        return render(request, 'sending_application/register.html', {'form': form})

class LoginView(View):
    def get(self, request):
        return render(request, 'sending_application/login.html')

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('send-message')
        return render(request, 'sending_application/login.html', {'error': 'Invalid credentials'})

@method_decorator(login_required, name='dispatch')
class SendMessageView(View):
    def get(self, request):
        # Render the form without sending any message
        return render(request, 'sending_application/send_message.html', {'success': False, 'error': None})

    def post(self, request):
        # File validation
        attachment = request.FILES.get('attachment')
        if attachment:
            if attachment.size > 5 * 1024 * 1024:  # 5 MB limit
                return render(request, 'sending_application/send_message.html', {
                    'success': False,
                    'error': 'File size must be less than 5MB.'
                })
            if not attachment.content_type in ['image/jpeg', 'image/png', 'application/pdf']:
                return render(request, 'sending_application/send_message.html', {
                    'success': False,
                    'error': 'Only JPG, PNG, and PDF files are allowed.'
                })

        recipient_username = request.POST.get('recipient')
        encrypted_content = request.POST.get('content')
        content_hash = request.POST.get('hash')
        priority = request.POST.get('priority', 'normal')

        # Validate required fields
        if not recipient_username or not encrypted_content or not content_hash:
            logger.error("Missing required fields: recipient, content, or hash")
            return render(request, 'sending_application/send_message.html', {
                'success': False,
                'error': 'Recipient, message content, and hash are required.',
            })

        try:
            # Validate the recipient exists
            recipient = User.objects.get(username=recipient_username)
        except User.DoesNotExist:
            logger.error(f"Recipient does not exist: {recipient_username}")
            return render(request, 'sending_application/send_message.html', {
                'success': False,
                'error': 'The recipient does not exist.',
            })

        payload = {
            'recipient_id': recipient.id,
            'content': encrypted_content,
            'hash': content_hash,
            'priority': priority,
            'sender_id': request.user.id,
        }

        try:
            # Log payload without exposing sensitive content
            logger.info(f"Attempting to send message to {recipient_username} (ID: {recipient.id}) with priority '{priority}'.")

            response = send_request(
                RECEIVING_PROJECT_BASE_URL,
                payload,
                {
                    'Authorization': f'Token {RECEIVING_APP_TOKEN}',
                }
            )

            if response.status_code == 200:
                logger.info(f"Message sent successfully to {recipient_username}.")
                # Redirect to avoid resubmission
                return redirect('send-message')
            elif response.status_code == 401:
                logger.error("Unauthorized access: Invalid token.")
                return render(request, 'sending_application/send_message.html', {
                    'success': False,
                    'error': 'Authentication failed. Please check your API token.',
                })
            else:
                logger.error(f"Failed to send message. Status Code: {response.status_code}.")
                return render(request, 'sending_application/send_message.html', {
                    'success': False,
                    'error': f"Failed to send the message. Error: {response.text}",
                })

        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {str(e)}")
            return render(request, 'sending_application/send_message.html', {
                'success': False,
                'error': 'An error occurred while sending the message. Please try again later.',
            })

