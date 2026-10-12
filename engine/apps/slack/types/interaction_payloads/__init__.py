from .block_actions import BlockActionsPayload
from .block_suggestion import BlockSuggestionPayload
from .dialog_submission import DialogSubmissionPayload
from .interactive_messages import InteractiveMessagesPayload
from .shortcuts import MessageActionPayload
from .slash_command import SlashCommandPayload
from .view_submission import ViewSubmissionPayload

EventPayload = (
    BlockActionsPayload
    | BlockSuggestionPayload
    | DialogSubmissionPayload
    | InteractiveMessagesPayload
    | MessageActionPayload
    | SlashCommandPayload
    | ViewSubmissionPayload
)
