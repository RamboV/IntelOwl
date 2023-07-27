# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# Generated by Django 3.2.18 on 2023-02-22 13:53

import django.contrib.postgres.fields
import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models

import api_app.defaults
import api_app.validators


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("analyzers_manager", "0003_analyzerconfig"),
        ("connectors_manager", "0003_connectorconfig"),
        ("api_app", "0015_visualizer"),
    ]

    operations = [
        migrations.CreateModel(
            name="VisualizerConfig",
            fields=[
                (
                    "name",
                    models.CharField(
                        max_length=50, primary_key=True, serialize=False, unique=True
                    ),
                ),
                ("python_module", models.CharField(max_length=120)),
                ("description", models.TextField()),
                ("disabled", models.BooleanField(default=False)),
                (
                    "config",
                    models.JSONField(
                        default=api_app.defaults.config_default,
                        validators=[api_app.validators.validate_config],
                    ),
                ),
                (
                    "secrets",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        validators=[api_app.validators.validate_secrets],
                    ),
                ),
                (
                    "params",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        validators=[api_app.validators.validate_params],
                    ),
                ),
                (
                    "analyzers",
                    models.ManyToManyField(
                        related_name="visualizers",
                        to="analyzers_manager.AnalyzerConfig",
                        blank=True,
                    ),
                ),
                (
                    "connectors",
                    models.ManyToManyField(
                        related_name="visualizers",
                        to="connectors_manager.ConnectorConfig",
                        blank=True,
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="VisualizerReport",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=128)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("FAILED", "Failed"),
                            ("PENDING", "Pending"),
                            ("RUNNING", "Running"),
                            ("SUCCESS", "Success"),
                            ("KILLED", "Killed"),
                        ],
                        max_length=50,
                    ),
                ),
                ("report", models.JSONField(default=dict)),
                (
                    "errors",
                    django.contrib.postgres.fields.ArrayField(
                        base_field=models.CharField(max_length=512),
                        blank=True,
                        default=list,
                        size=None,
                    ),
                ),
                (
                    "runtime_configuration",
                    models.JSONField(blank=True, default=dict, null=True),
                ),
                ("start_time", models.DateTimeField(default=django.utils.timezone.now)),
                ("end_time", models.DateTimeField(default=django.utils.timezone.now)),
                ("task_id", models.UUIDField()),
                (
                    "parent_playbook",
                    models.CharField(blank=True, default="", max_length=128),
                ),
                (
                    "job",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="visualizer_reports",
                        to="api_app.job",
                    ),
                ),
            ],
            options={
                "unique_together": {("name", "job")},
            },
        ),
    ]
