# Generated by Django 5.1.3 on 2024-12-25 17:05

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('CommonApp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='SenderMessage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('recipient_username', models.CharField(max_length=100)),
                ('priority', models.CharField(choices=[('low', 'Low'), ('normal', 'Normal'), ('high', 'High')], default='normal', max_length=20)),
                ('attachment', models.FileField(blank=True, null=True, upload_to='sender_attachments/')),
                ('encrypted_message', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('sender', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sent_messages', to='CommonApp.user')),
            ],
            options={
                'db_table': 'senderapp_message',
            },
        ),
    ]
