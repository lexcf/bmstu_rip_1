# Generated by Django 4.2.4 on 2024-09-30 16:14

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('monitoring', '0012_alter_request_created_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='request',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 9, 30, 16, 14, 35, 967914)),
        ),
    ]