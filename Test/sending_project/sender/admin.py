from django.contrib import admin
from .models import User, Message, Attachment, Log

# Custom admin for User model
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'is_active', 'created_at')
    search_fields = ('username', 'email')
    list_filter = ('is_active',)
    ordering = ('username',)

# Default admin for other models
@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'sender', 'recipient', 'status', 'created_at')
    search_fields = ('sender__username', 'recipient__username')
    list_filter = ('status', 'created_at')

@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
    list_display = ('id', 'message', 'file_type', 'file_size', 'uploaded_at')
    search_fields = ('message__id',)
    list_filter = ('file_type',)

@admin.register(Log)
class LogAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'action', 'created_at')
    search_fields = ('user__username', 'action')
    list_filter = ('action',)
