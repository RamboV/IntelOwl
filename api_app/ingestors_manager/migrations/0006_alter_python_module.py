# Generated by Django 4.1.10 on 2023-08-22 12:36

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0039_remove_fields"),
        (
            "ingestors_manager",
            "0005_rename_ingestors_m_python__5c8ce0_idx_ingestors_m_python__b7a859_idx_and_more",
        ),
    ]

    operations = [
        migrations.RemoveField(
            model_name="ingestorconfig",
            name="python_module",
        ),
        migrations.RenameField(
            model_name="ingestorconfig",
            old_name="python_module2",
            new_name="python_module",
        ),
    ]
