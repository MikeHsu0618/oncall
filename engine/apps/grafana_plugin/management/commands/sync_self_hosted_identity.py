from django.conf import settings
from django.core.management.base import BaseCommand

from apps.metrics_exporter.tasks import calculate_and_cache_metrics, calculate_and_cache_user_was_notified_metric
from apps.user_management.models.organization import Organization


class Command(BaseCommand):
    help = "Synchronize the persisted self-hosted organization identity with runtime settings"

    def handle(self, *args, **options):
        configured = settings.SELF_HOSTED_SETTINGS
        organization = Organization.objects.filter(
            stack_id=configured["STACK_ID"],
            org_id=configured["ORG_ID"],
        ).first()

        if organization is None:
            self.stdout.write("No installed self-hosted organization; nothing to synchronize")
            return

        identity = {
            "stack_slug": configured["STACK_SLUG"],
            "org_slug": configured["ORG_SLUG"],
            "org_title": configured["ORG_TITLE"],
            "region_slug": configured["REGION_SLUG"],
            "cluster_slug": configured["CLUSTER_SLUG"],
        }
        changed_fields = []
        for field, value in identity.items():
            if getattr(organization, field) != value:
                setattr(organization, field, value)
                changed_fields.append(field)

        if not changed_fields:
            self.stdout.write("Self-hosted organization identity is already synchronized")
            return

        organization.save(update_fields=changed_fields)
        calculate_and_cache_metrics.run(organization.id)
        calculate_and_cache_user_was_notified_metric.run(organization.id)
        self.stdout.write(self.style.SUCCESS("Self-hosted organization identity synchronized"))
