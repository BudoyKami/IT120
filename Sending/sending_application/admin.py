from django.contrib import admin
from .models import Message

# Register your models here.
@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'sender', 'recipient', 'priority', 'time_sent', 'time_received')
    search_fields = ('sender_username', 'recipient_username', 'encrypted_content')