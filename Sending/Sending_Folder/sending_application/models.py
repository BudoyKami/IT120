from django.db import models
from django.contrib.auth.models import User

class Message(models.Model):
    id = models.AutoField(primary_key=True)  # Primary key for the message
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_messages")  # Explicit link to Django's auth_user table
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")  # Sender of the message
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_messages")  # Recipient of the message
    time_sent = models.DateTimeField(auto_now_add=True)  # Timestamp when the message was sent
    time_received = models.DateTimeField(null=True, blank=True)  # Timestamp when the message was received
    encrypted_content = models.TextField()  # Encrypted content of the message
    content_hash = models.CharField(max_length=64)  # BLAKE2 hash of the content
    priority = models.CharField(max_length=10, choices=[('low', 'Low'), ('normal', 'Normal'), ('high', 'High')], default='normal')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message {self.id} from {self.sender.username} to {self.recipient.username}"
