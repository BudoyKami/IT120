from django.urls import path
from .views import SendMessageView

urlpatterns = [
    path('api/messages/send/', SendMessageView.as_view(), name='send_message'),
]
