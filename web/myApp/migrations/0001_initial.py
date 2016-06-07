# -*- coding: utf-8 -*-
# Generated by Django 1.9.5 on 2016-06-03 09:51
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='cfg',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('serverIP', models.GenericIPAddressField()),
                ('custID', models.IntegerField()),
                ('protocol', models.TextField()),
                ('slug', models.SlugField(unique=True)),
            ],
        ),
    ]