# Generated by Django 4.2.4 on 2024-09-22 17:24

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('monitoring', '0008_alter_request_created_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='request',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 9, 22, 17, 24, 4, 841240)),
        ),
    ]