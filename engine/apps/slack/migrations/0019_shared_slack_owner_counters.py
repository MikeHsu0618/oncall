from django.db import migrations

# The connector's SourceOwner contract dropped these counters (IRM P4); installationIncarnation stays.
DROPPED = ("bindingRevision", "bindingDigest", "connectionGeneration", "credentialRevision")
MODELS = ("SharedSlackInstallation", "SharedSlackDelivery", "SlackMessage", "SharedSlackPagingSession")


def _strip(owner):
    if not isinstance(owner, dict):
        return owner
    return {key: value for key, value in owner.items() if key not in DROPPED}


def strip_owner_counters(apps, schema_editor):
    """Every stored owner is compared with ``==`` to the new projection, so none may keep an old key."""
    alias = schema_editor.connection.alias
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute("SET LOCAL lock_timeout = '5s'")
        names = [apps.get_model("slack", name)._meta.db_table for name in MODELS]
        schema_editor.execute("LOCK TABLE " + ",".join(schema_editor.quote_name(name) for name in names)
                              + " IN ACCESS EXCLUSIVE MODE")
    for name in MODELS:
        model = apps.get_model("slack", name)
        for row in model.objects.using(alias).filter(source_owner__isnull=False).iterator():
            row.source_owner = _strip(row.source_owner)
            row.save(update_fields=["source_owner"])
    deliveries = apps.get_model("slack", "SharedSlackDelivery").objects.using(alias)
    for row in deliveries.exclude(modal_owners={}).iterator():
        row.modal_owners = {view: ({**record, "sourceOwner": _strip(record.get("sourceOwner"))}
                                   if isinstance(record, dict) and "sourceOwner" in record else record)
                            for view, record in row.modal_owners.items()}
        row.save(update_fields=["modal_owners"])


def refuse_reverse(apps, schema_editor):
    for name in MODELS:
        if apps.get_model("slack", name).objects.using(schema_editor.connection.alias).filter(
                source_owner__isnull=False).exists():
            raise RuntimeError("Shared Slack owner provenance counters cannot be reconstructed; reconcile before downgrade")


class Migration(migrations.Migration):
    dependencies = [("slack", "0018_shared_slack_source_owner")]
    operations = [migrations.RunPython(strip_owner_counters, refuse_reverse)]
