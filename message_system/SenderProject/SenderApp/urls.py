from django.urls import path
from . import views

urlpatterns = [
    path('', views.homepage, name='sender_homepage'),
    path('register/', views.register_user, name='sender_register'),
    path('login/', views.login_user, name='sender_login'),
    path('logout/', views.logout_user, name='sender_logout'),
    path('send_message/', views.send_message, name='sender_send_message'),
]
