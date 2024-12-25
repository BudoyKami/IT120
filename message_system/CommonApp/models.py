# CommonApp/models.py
from django.db import models
from django.contrib.auth.hashers import make_password

class User(models.Model):
    user_id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        if not self.pk:  # Hash the password only on creation
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    class Meta:
        db_table = 'users'  # Shared table name

    def __str__(self):
        return self.username
