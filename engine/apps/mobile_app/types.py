import typing
from enum import StrEnum


class MessageType(StrEnum):
    DEFAULT = "oncall.message"
    IMPORTANT = "oncall.critical_message"
    INFO = "oncall.info"


class Platform(StrEnum):
    ANDROID = "android"
    IOS = "ios"


class NotificationSoundData(typing.TypedDict, total=False):
    """
    Per-user sound/volume/DND settings passed in the FCM data payload so the Android app can play the right sound at
    the right volume and decide whether to break through Do Not Disturb. All values must be strings (FCM requirement).
    Alert group and test pushes carry the default_* and important_* keys, info pushes carry the info_* keys.
    """

    default_notification_sound_name: str
    default_notification_volume_type: str
    default_notification_volume: str
    default_notification_volume_override: str
    default_notification_override_dnd: str
    important_notification_sound_name: str
    important_notification_volume_type: str
    important_notification_volume: str
    important_notification_volume_override: str
    important_notification_override_dnd: str
    info_notification_sound_name: str
    info_notification_volume_type: str
    info_notification_volume: str
    info_notification_volume_override: str
    info_notification_override_dnd: str


class FCMMessageData(NotificationSoundData, total=False):
    title: typing.Required[str]
    subtitle: str
    body: str
    orgId: str
    orgName: str
    alertGroupId: str
    status: str
    route: str
