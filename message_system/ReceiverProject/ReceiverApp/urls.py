from django.urls import path
from .views import ReceiveMessageView

urlpatterns = [
    path('api/receive_message/', ReceiveMessageView.as_view(), name='receive_message'),
]
