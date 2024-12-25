# Generated by Django 5.1.4 on 2024-12-25 10:07

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('user_id', models.AutoField(primary_key=True, serialize=False)),
                ('username', models.CharField(max_length=100, unique=True)),
                ('password', models.CharField(max_length=255)),
            ],
            options={
                'db_table': 'users',
            },
        ),
    ]
