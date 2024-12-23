from django.urls import path
from .views import ReceiveMessageView

urlpatterns = [
    path('api/messages/receive/', ReceiveMessageView.as_view(), name='receive_message'),
]
