# Generated by Django 4.1.9 on 2023-05-23 13:18

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("connectors_manager", "0016_alter_connectorconfig_name"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="connectorconfig",
            options={"ordering": ["name", "disabled"]},
        ),
    ]
