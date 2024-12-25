from django.urls import path
from .views import UserView, SendMessageView

urlpatterns = [
    path('api/users/', UserView.as_view(), name='users'),
    path('api/send_message/', SendMessageView.as_view(), name='send_message'),
]
