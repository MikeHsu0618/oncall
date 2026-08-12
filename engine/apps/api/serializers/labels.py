from rest_framework import serializers

from apps.labels.models import (
    MAX_KEY_NAME_LENGTH,
    MAX_VALUE_NAME_LENGTH,
    AssociatedLabel,
    LabelKeyCache,
    LabelValueCache,
)
from apps.labels.utils import is_labels_feature_enabled


class LabelKeySerializer(serializers.ModelSerializer):
    id = serializers.CharField()
    prescribed = serializers.BooleanField(default=False)

    class Meta:
        model = LabelKeyCache
        fields = (
            "id",
            "name",
            "prescribed",
        )


class LabelValueSerializer(serializers.ModelSerializer):
    id = serializers.CharField()
    prescribed = serializers.BooleanField(default=False)

    class Meta:
        model = LabelValueCache
        fields = (
            "id",
            "name",
            "prescribed",
        )


class LabelPairSerializer(serializers.Serializer):
    key = LabelKeySerializer()
    value = LabelValueSerializer()


class AlertGroupLabelManagementSerializer(serializers.Serializer):
    """Name-based label pair used by IRM alert-group label mutations."""

    class LabelNameSerializer(serializers.Serializer):
        name = serializers.CharField()

    key = LabelNameSerializer()
    value = LabelNameSerializer()

    def validate(self, attrs):
        if len(attrs["key"]["name"]) > MAX_KEY_NAME_LENGTH:
            raise serializers.ValidationError({"key": {"name": "Label key is too long."}})
        if len(attrs["value"]["name"]) > MAX_VALUE_NAME_LENGTH:
            raise serializers.ValidationError({"value": {"name": "Label value is too long."}})
        return attrs


class LabelOptionSerializer(serializers.Serializer):
    key = LabelKeySerializer()
    values = LabelValueSerializer(many=True)


class ArchivedLabelPairSerializer(serializers.Serializer):
    key = serializers.CharField()
    value = serializers.CharField()


class LabelsDropdownContextSerializer(serializers.Serializer):
    label_options = LabelOptionSerializer(many=True)
    archived = ArchivedLabelPairSerializer(many=True)


class LabelReprSerializer(serializers.Serializer):
    name = serializers.CharField()


class LabelsSerializerMixin(serializers.Serializer):
    labels = LabelPairSerializer(many=True, required=False)

    def validate_labels(self, labels):
        if labels:
            keys = {label["key"]["id"] for label in labels}
            if len(keys) != len(labels):
                raise serializers.ValidationError(detail="Duplicate label key")
        return labels

    def update_labels_association_if_needed(self, labels, instance, organization):
        if labels is not None and is_labels_feature_enabled(organization):
            AssociatedLabel.update_association(labels, instance, organization)
