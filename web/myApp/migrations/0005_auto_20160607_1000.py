# -*- coding: utf-8 -*-
# Generated by Django 1.9.5 on 2016-06-07 10:00
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('myApp', '0004_auto_20160606_0940'),
    ]

    operations = [
        migrations.RenameField(
            model_name='cfg',
            old_name='nriLen',
            new_name='nlriLen',
        ),
    ]
