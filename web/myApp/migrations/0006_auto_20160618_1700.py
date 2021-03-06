# -*- coding: utf-8 -*-
# Generated by Django 1.9.5 on 2016-06-18 17:00
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myApp', '0005_auto_20160607_1000'),
    ]

    operations = [
        migrations.AddField(
            model_name='cfg',
            name='ovTCP',
            field=models.BooleanField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='cfg',
            name='ovUDP',
            field=models.BooleanField(default=0),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='cfg',
            name='protocol',
            field=models.CharField(choices=[('BGP', 'BGP'), ('SSL', 'SSL'), ('SSL_PERF', 'SSL_PERF'), ('OPENVPN', 'OPENVPN')], default='BGP', max_length=8),
        ),
    ]
