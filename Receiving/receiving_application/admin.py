from django.contrib import admin
from .models import Message

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'sender', 'recipient', 'priority', 'time_sent', 'time_received')
    search_fields = ('sender__username', 'recipient__username', 'encrypted_content')
