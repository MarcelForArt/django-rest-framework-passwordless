# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import drfpasswordless.models


class Migration(migrations.Migration):

    dependencies = [
        ('drfpasswordless', '0002_key'),
    ]

    operations = [
        migrations.AlterField(
            model_name='CallbackToken',
            name='to_alias',
            field=models.CharField(blank=True, max_length=254),
        ),
    ]

