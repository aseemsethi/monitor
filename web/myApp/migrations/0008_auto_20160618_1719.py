# -*- coding: utf-8 -*-
# Generated by Django 1.9.5 on 2016-06-18 17:19
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myApp', '0007_auto_20160618_1715'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='cfg',
            name='ovProtocol',
        ),
        migrations.AddField(
            model_name='cfg',
            name='ovProto',
            field=models.CharField(choices=[('TCP', 'TCP'), ('UDP', 'UDP')], default='UDP', max_length=8),
        ),
    ]