from django.urls import path
from .views import ReceiveMessageView

urlpatterns = [
    path('receive-message/', ReceiveMessageView.as_view(), name='receive-message'),
]
