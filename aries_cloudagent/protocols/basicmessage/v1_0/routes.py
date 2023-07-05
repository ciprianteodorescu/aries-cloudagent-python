"""Basic message admin routes."""

from aiohttp import web
from aiohttp_apispec import docs, match_info_schema, request_schema, response_schema

from marshmallow import fields

from ....admin.request_context import AdminRequestContext
from ....connections.models.conn_record import ConnRecord
from ....messaging.models.openapi import OpenAPISchema
from ....messaging.valid import UUIDFour
from ....storage.error import StorageNotFoundError

from .message_types import SPEC_URI
from .messages.basicmessage import BasicMessage
from .models.basicmessage_record import BasicMessageRecord, BasicMessageRecordSchema

from ....messaging import util


class BasicMessageModuleResponseSchema(OpenAPISchema):
    """Response schema for Basic Message Module."""


class SendMessageSchema(OpenAPISchema):
    """Request schema for sending a message."""

    content = fields.Str(description="Message content", example="Hello")


class BasicConnIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking connection id."""

    conn_id = fields.Str(
        description="Connection identifier", required=True, example=UUIDFour.EXAMPLE
    )


class BasicConnIdDeleteMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking connection id, basic message id and delete all."""

    conn_id = fields.Str(
        description="Connection identifier", required=True, example=UUIDFour.EXAMPLE
    )

    basic_msg_id = fields.Str(
        description="Basic message identifier", required=False, example=UUIDFour.EXAMPLE
    )

    delete_all = fields.Str(
        description="Delete all messages", required=False, example=True
    )


class BasicMessageListSchema(OpenAPISchema):
    """Response schema for fetching all basic messages"""

    results = fields.List(
        fields.Nested(BasicMessageRecordSchema()),
        description="List of basic message record"
    )


class StoreBasicMessageSchema(OpenAPISchema):
    """Response schema for storing basic message"""

    result = fields.Str(description="Basic Message stored", example="true")


DOCS_TAG = "basicmessage"


def basic_message_sort_key(basic_message):
    """Get the sorting key for a particular basic message"""


@docs(tags=[DOCS_TAG], summary="Fetch all basic messages sent/received to/from connection")
@match_info_schema(BasicConnIdMatchInfoSchema())
@response_schema(BasicMessageListSchema(), 200, description="")
async def connection_fetch_basic_messages(request: web.BaseRequest):
    """
    Request handler for fetching all basic message record with a given connection id.

    Args:
        request: aiohttp request object
    """
    context: AdminRequestContext = request["context"]
    connection_id = request.match_info["conn_id"]
    # params = await request.json()

    tag_filter = {"connection_id": connection_id}

    try:
        async with context.profile.session() as session:
            records = await BasicMessageRecord.query(session, tag_filter=tag_filter)
        results = [record.serialize() for record in records]
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response({"results": results})


@docs(tags=[DOCS_TAG], summary="Store received basic message")
@match_info_schema(BasicConnIdMatchInfoSchema())
@request_schema(SendMessageSchema())
@response_schema(BasicMessageModuleResponseSchema())
async def store_basic_message(request: web.BaseRequest):
    """
    Request handler for storing a received basic message.

    Args:
        request: aiohttp request object
    """
    context: AdminRequestContext = request["context"]
    connection_id = request.match_info["conn_id"]
    params = await request.json()

    try:
        async with context.profile.session() as session:
            msg = BasicMessage(content=params["content"])
            role = params["state"] if "state" in params.keys() else ""
            sent_time = params["sent_time"] if "sent_time" in params.keys() else util.datetime_to_str(util.datetime_now())
            # Create basic message record
            record = BasicMessageRecord(
                connection_id=connection_id,
                sent_time=sent_time,
                role=role,
                content=msg.content
            )
            await record.save(session, reason="Save sent message")
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response({})


@docs(tags=[DOCS_TAG], summary="Fetch all basic messages sent/received to/from connection")
@match_info_schema(BasicConnIdDeleteMatchInfoSchema())
@response_schema(BasicMessageModuleResponseSchema(), 200, description="")
async def connection_delete_basic_message(request: web.BaseRequest):
    """
        Request handler for deleting one or all stored basic message.

        Args:
            request: aiohttp request object
        """
    context: AdminRequestContext = request["context"]
    connection_id = request.match_info["conn_id"]
    params = await request.json()

    basic_msg_id = params["basic_msg_id"] if "basic_msg_id" in params.keys() else None
    delete_all = params["delete_all"] if "delete_all" in params.keys() else False

    if basic_msg_id is None and delete_all is False:
        # either basic_msg_id should be provided or delete_all be True
        # otherwise,
        return web.HTTPUnprocessableEntity(reason="either basic_msg_id must be provided, or delete_all must be True")
    else:
        try:
            async with context.profile.session() as session:
                if delete_all:
                    tag_filter = {"connection_id": connection_id}
                    records = await BasicMessageRecord.query(session, tag_filter=tag_filter)
                elif basic_msg_id is not None:
                    tag_filter = {
                        "connection_id": connection_id,
                        "basic_message_id": basic_msg_id
                    }
                    records = await BasicMessageRecord.query(session, tag_filter=tag_filter)
                for record in records:
                    await record.delete_record(session)


        except StorageNotFoundError as err:
            raise web.HTTPNotFound(reason=err.roll_up) from err


@docs(tags=[DOCS_TAG], summary="Send a basic message to a connection")
@match_info_schema(BasicConnIdMatchInfoSchema())
@request_schema(SendMessageSchema())
@response_schema(BasicMessageModuleResponseSchema(), 200, description="")
async def connections_send_message(request: web.BaseRequest):
    """
    Request handler for sending a basic message to a connection.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]
    connection_id = request.match_info["conn_id"]
    outbound_handler = request["outbound_message_router"]
    params = await request.json()

    try:
        async with context.profile.session() as session:
            connection = await ConnRecord.retrieve_by_id(session, connection_id)

            if connection.is_ready:
                msg = BasicMessage(content=params["content"])
                await outbound_handler(msg, connection_id=connection_id)
                # Create basic message record
                record = BasicMessageRecord(
                    connection_id=connection.connection_id,
                    sent_time=util.datetime_to_str(util.datetime_now()),
                    role=BasicMessageRecord.Role.SENT.value,
                    content=msg.content
                )
                await record.save(session, reason="Save sent message")
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response({})


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.post("/connections/{conn_id}/send-message", connections_send_message),
            web.get("/connections/{conn_id}/basic-messages", connection_fetch_basic_messages, allow_head=False),
            web.post("/connections/{conn_id}/store-message", store_basic_message),
            web.post("/connections/{conn_id}/delete-messages", connection_delete_basic_message),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "basicmessage",
            "description": "Simple messaging",
            "externalDocs": {"description": "Specification", "url": SPEC_URI},
        }
    )
