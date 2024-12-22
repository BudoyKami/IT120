from django.db import models
from django.contrib.auth.models import User

class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_messages")
    encrypted_content = models.TextField()
    decrypted_content = models.TextField(blank=True, null=True)  # Optional for debugging
    content_hash = models.CharField(max_length=64)
    priority = models.CharField(
        max_length=10,
        choices=[('low', 'Low'), ('normal', 'Normal'), ('high', 'High')],
        default='normal'
    )
    time_sent = models.DateTimeField(auto_now_add=True)
    time_received = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"Message from {self.sender.username} to {self.recipient.username}"
