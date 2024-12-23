from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    email = models.EmailField(unique=True)
    port = models.PositiveIntegerField(null=True, blank=True, default=8001)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.username

# Message model for the receiver application
class Message(models.Model):
    STATUS_CHOICES = [
        ('sent', 'Sent'),
        ('delivered', 'Delivered'),
        ('read', 'Read'),
    ]

    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    encrypted_content = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='sent')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'receiver_messages'  # Name for the receiver message table

    def __str__(self):
        return f"Message from {self.sender.username} to {self.recipient.username}"

# Attachments model for the receiver application
class Attachment(models.Model):
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='attachments')
    file_path = models.TextField()
    file_type = models.CharField(max_length=50)
    file_size = models.PositiveIntegerField()  # Stored in bytes
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Attachment for Message ID {self.message.id}"

# Logs model for the receiver application
class Log(models.Model):
    ACTION_CHOICES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('message_received', 'Message Received'),
        ('attachment_uploaded', 'Attachment Uploaded'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='receiver_logs')
    action = models.CharField(max_length=255, choices=ACTION_CHOICES)
    details = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.action}"
