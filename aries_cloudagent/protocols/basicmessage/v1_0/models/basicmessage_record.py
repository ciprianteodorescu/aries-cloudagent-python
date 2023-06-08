"""Handle Basic Message information interface with non-secrets storage."""

from enum import Enum
from typing import Any, Optional, Union

from marshmallow import fields, validate

from .....core.profile import ProfileSession
from .....messaging.valid import UUIDFour

from .....messaging.models.base_record import BaseRecord, BaseRecordSchema
from .....storage.base import BaseStorage
from .....storage.record import StorageRecord
from .....storage.error import StorageNotFoundError


class BasicMessageRecord(BaseRecord):
    """Represents a single basic message"""

    class Meta:
        """BasicMessageRecord metadata"""

        schema_class = "BasicMessageRecordSchema"

    class Role(Enum):
        """Supported Protocols for Basic Message"""

        SENT = "sent"
        RECEIVED = "received"

        @classmethod
        def get(cls, label: Union[str, "BasicMessageRecord.Role"]):
            """Get role enum for label"""
            if isinstance(label, str):
                for role in BasicMessageRecord.Role:
                    if label == role:
                        return role
            elif isinstance(label, BasicMessageRecord.Role):
                return label
            return None

        def __eq__(self, other: Union[str, "BasicMessageRecord.Role"]) -> bool:
            """Comparison between roles"""
            return self is BasicMessageRecord.Role.get(other)

    class State(Enum):
        """
        RFC95

        This protocol doesn't really have states, as sending a message
        leaves both parties in the same state they were before.

        But State is defined in BaseRecord class, so it's needed if
        we want to store basic messages.

        TODO: Maybe delete Role, as it's redundant?
        """

        SENT = "sent"
        RECEIVED = "received"

        @classmethod
        def get(cls, label: Union[str, "BasicMessageRecord.State"]):
            """Get state enum for label"""
            if isinstance(label, str):
                for state in BasicMessageRecord.State:
                    if label == state:
                        return state
            elif isinstance(label, BasicMessageRecord.State):
                return label
            return None

        def __eq__(self, other: Union[str, "BasicMessageRecord.State"]) -> bool:
            """Comparison between roles"""
            return self is BasicMessageRecord.State.get(other)

    RECORD_ID_NAME = "basic_message_id"
    RECORD_TOPIC = "basicmessages"
    LOG_STATE_FLAG = "debug.basicmessages"
    TAG_NAMES = {
        "connection_id",
        "sent_time",
        "role",
        "content"
    }

    RECORD_TYPE = "basic_message"

    def __init__(
            self,
            *,
            basic_message_id: str = None,
            connection_id: str,
            sent_time: str = None,
            role: str = None,
            content,
            **kwargs,
    ):
        super().__init__(basic_message_id, **kwargs)
        self.connection_id = connection_id
        self.sent_time = sent_time
        self.role = role
        self.content = content

    @property
    def basic_message_id(self) -> str:
        """Accessor for the ID associated with this message's connection"""
        return self._id

    @property
    def record_value(self) -> dict:
        """Accessor to for the JSON record value properties for this basic message"""
        return {"content": self.content}

    async def post_save(self, session: ProfileSession, *args, **kwargs):
        """Perform post-save actions.

        Args:
            session: The active profile session
        """
        await super().post_save(session, *args, **kwargs)

        # # clear cache key set by connection manager
        # cache_key = f"connection_target::{self.connection_id}"
        # await self.clear_cached_key(session, cache_key)

    async def delete_record(self, session: ProfileSession):
        """Perform connection record deletion actions.

        Args:
            session (ProfileSession): session

        """
        await super().delete_record(session)
        #
        # # Delete metadata
        # if self.connection_id:
        #     storage = session.inject(BaseStorage)
        #     await storage.delete_all_records(
        #         self.RECORD_TYPE_METADATA,
        #         {"connection_id": self.connection_id},
        #     )


class BasicMessageRecordSchema(BaseRecordSchema):
    """Schema to allow serialization/deserialization of basic message records."""

    class Meta:
        """BasicMessageRecordSchema metadata"""

        model_class = BasicMessageRecord

    basic_message_id = fields.Str(
        required=False, description="Basic Message identifier", example=UUIDFour.EXAMPLE
    )

    connection_id = fields.Str(
        required=False, description="Connection identifier", example=UUIDFour.EXAMPLE
    )

    sent_time = fields.Str(
        required=False, description="time message was sent", example=UUIDFour.EXAMPLE
    )

    role = fields.Str(
        required=False, description="role of message: received/sent", example="sent"
    )

    content = fields.Str(
        required=False, description="Content of message", example="This is a message."
    )
