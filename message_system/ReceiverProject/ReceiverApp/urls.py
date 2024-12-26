from django.urls import path
from .views import homepage, login_user, logout_user, view_messages, ReceiveMessageView

urlpatterns = [
    path('', homepage, name='receiver_homepage'),
    path('login/', login_user, name='receiver_login'),
    path('logout/', logout_user, name='receiver_logout'),
    path('view-messages/', view_messages, name='receiver_view_messages'),
    path('api/receive_message/', ReceiveMessageView.as_view(), name='receive_message'),
]
