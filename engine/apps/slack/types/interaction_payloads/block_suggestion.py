"""Slack external-select options-load payload."""

import typing

from apps.slack.types.common import BaseEvent, PayloadType
from apps.slack.types.views import ModalView


class BlockSuggestionPayload(BaseEvent):
    type: typing.Literal[PayloadType.BLOCK_SUGGESTION]
    action_id: str
    block_id: str
    value: str
    api_app_id: str
    view: ModalView
