from django.db import models
from CommonApp.models import User  # Import User model from CommonApp

class SenderMessage(models.Model):
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('normal', 'Normal'),
        ('high', 'High'),
    ]

    sender = models.ForeignKey(
        User,  # Use the imported User model directly
        on_delete=models.CASCADE,
        related_name='sent_messages'  # Related name for reverse relation
    )
    recipient_username = models.CharField(max_length=100)
    priority = models.CharField(
        max_length=20,
        choices=PRIORITY_CHOICES,
        default='normal'
    )
    attachment = models.FileField(
        upload_to='sender_attachments/',
        null=True,
        blank=True
    )
    encrypted_message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'senderapp_message'

    def __str__(self):
        return f"To: {self.recipient_username} - {self.priority} - {self.timestamp}"
