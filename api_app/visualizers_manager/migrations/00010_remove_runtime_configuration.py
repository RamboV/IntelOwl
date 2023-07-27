# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# Generated by Django 3.2.18 on 2023-03-07 08:29

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("visualizers_manager", "0009_remove_parent_playbook"),
        ("api_app", "0023_runtime_config"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="visualizerreport", name="runtime_configuration"
        )
    ]
