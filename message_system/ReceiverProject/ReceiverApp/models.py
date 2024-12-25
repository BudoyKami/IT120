from django.db import models

class ReceiverMessage(models.Model):
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('normal', 'Normal'),
        ('high', 'High'),
    ]

    sender_username = models.CharField(max_length=100)
    recipient_username = models.CharField(max_length=100)
    decrypted_message = models.TextField()
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='normal')
    attachment = models.FileField(upload_to='receiver_attachments/', null=True, blank=True)
    timestamp = models.DateTimeField()

    class Meta:
        db_table = 'receiverapp_message'

    def __str__(self):
        return f"From: {self.sender_username} - {self.priority} - {self.timestamp}"
