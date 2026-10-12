from django.db import migrations, models


def refuse_populated_reverse(apps, schema_editor):
    # Explicit cold/stopped-writer operation. On PostgreSQL acquire all locks
    # before the provenance snapshot; SQLite migration transaction/schema lock
    # supplies serialization. MySQL nontransactional DDL requires stopped writers.
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute("SET LOCAL lock_timeout = '5s'")
        names = [apps.get_model("slack", name)._meta.db_table for name in
                 ("SharedSlackInstallation", "SharedSlackDelivery", "SlackMessage", "SharedSlackPagingSession")]
        schema_editor.execute("LOCK TABLE " + ",".join(schema_editor.quote_name(name) for name in names) + " IN ACCESS EXCLUSIVE MODE")
    for name in ("SharedSlackInstallation", "SharedSlackDelivery", "SlackMessage", "SharedSlackPagingSession"):
        if apps.get_model("slack", name).objects.using(schema_editor.connection.alias).filter(source_owner__isnull=False).exists():
            raise RuntimeError("Shared Slack source provenance requires explicit reconciliation before downgrade")
    if apps.get_model("slack", "SharedSlackPagingSession").objects.using(schema_editor.connection.alias).exclude(view_operation_phase="ready").exists():
        raise RuntimeError("Shared Slack view operation requires explicit reconciliation before downgrade")
    installation = apps.get_model("slack", "SharedSlackInstallation").objects.using(schema_editor.connection.alias)
    if installation.exclude(source_links={}).exists() or installation.exclude(source_links_revision=1).exists():
        raise RuntimeError("Shared Slack link provenance requires explicit reconciliation before downgrade")
    if apps.get_model("slack", "SharedSlackDelivery").objects.using(schema_editor.connection.alias).exclude(modal_owners={}).exists():
        raise RuntimeError("Shared Slack modal provenance requires explicit reconciliation before downgrade")


class Migration(migrations.Migration):
    dependencies = [("slack", "0017_shared_slack_paging_command")]
    operations = [
        migrations.AddField(model_name="sharedslackinstallation", name="source_owner", field=models.JSONField(null=True, default=None)),
        migrations.AddField(model_name="sharedslackinstallation", name="source_disconnected", field=models.BooleanField(default=False)),
        migrations.AddField(model_name="sharedslackdelivery", name="source_owner", field=models.JSONField(null=True, default=None)),
        migrations.AddField(model_name="slackmessage", name="source_owner", field=models.JSONField(null=True, default=None)),
        migrations.AddField(model_name="sharedslackpagingsession", name="source_owner", field=models.JSONField(null=True, default=None)),
        migrations.AddField(model_name="sharedslackinstallation", name="source_links", field=models.JSONField(default=dict)),
        migrations.AddField(model_name="sharedslackinstallation", name="source_links_revision", field=models.BigIntegerField(default=1)),
        migrations.AddField(model_name="sharedslackdelivery", name="modal_owners", field=models.JSONField(default=dict)),
        migrations.AddField(model_name="sharedslackpagingsession", name="view_operation_phase", field=models.CharField(max_length=16, default="ready")),
        migrations.AddConstraint(model_name="sharedslackinstallation", constraint=models.CheckConstraint(
            check=models.Q(source_links_revision__gte=1, source_links_revision__lte=2**63 - 1), name="slack_shared_links_revision")),
        migrations.AddConstraint(model_name="sharedslackinstallation", constraint=models.CheckConstraint(
            check=models.Q(source_disconnected=False) | models.Q(source_owner__isnull=False), name="slack_shared_disconnect_source")),
        migrations.AddConstraint(model_name="sharedslackpagingsession", constraint=models.CheckConstraint(
            check=models.Q(view_operation_phase__in=["ready", "posting", "uncertain"]), name="slack_shared_view_phase")),
        migrations.RunPython(migrations.RunPython.noop, refuse_populated_reverse),
    ]
