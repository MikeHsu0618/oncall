from django.db import models


class SharedSlackDelivery(models.Model):
    """Fence native dispatch before side effects; retries cannot page twice."""

    key = models.CharField(max_length=64, primary_key=True)
    modal_owners = models.JSONField(default=dict)
    source_owner = models.JSONField(null=True, default=None)
    phase = models.CharField(max_length=16, default="dispatching")
    response_status = models.PositiveIntegerField(null=True)
    response_data = models.JSONField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
