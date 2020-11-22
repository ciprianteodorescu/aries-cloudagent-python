import json
import pytest

from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock

from .. import routes as test_module


class TestHolderRoutes(AsyncTestCase):
    def setUp(self):
        self.mock_request = async_mock.MagicMock(
            __getitem__=async_mock.Mock(
                side_effect={
                    "context": async_mock.MagicMock(),
                    "outbound_message_router": async_mock.CoroutineMock(),
                }.__getitem__
            ),
        )

    async def test_connections_send_ping(self):
        self.mock_request.json = async_mock.CoroutineMock(
            return_value={"comment": "some comment"}
        )
        self.mock_request.match_info = {"conn_id": "dummy"}

        with async_mock.patch.object(
            test_module.ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_retrieve, async_mock.patch.object(
            test_module, "Ping", async_mock.MagicMock()
        ) as mock_ping, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as json_response:
            mock_ping.return_value = async_mock.MagicMock(_thread_id="dummy")
            mock_retrieve.return_value = async_mock.MagicMock(is_ready=True)
            result = await test_module.connections_send_ping(self.mock_request)
            json_response.assert_called_once_with({"thread_id": "dummy"})
            assert result is json_response.return_value

    async def test_connections_send_ping_no_conn(self):
        self.mock_request.json = async_mock.CoroutineMock(
            return_value={"comment": "some comment"}
        )
        self.mock_request.match_info = {"conn_id": "dummy"}

        with async_mock.patch.object(
            test_module.ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_retrieve, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as json_response:
            mock_retrieve.side_effect = test_module.StorageNotFoundError()
            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.connections_send_ping(self.mock_request)

    async def test_connections_send_ping_not_ready(self):
        self.mock_request.json = async_mock.CoroutineMock(
            return_value={"comment": "some comment"}
        )
        self.mock_request.match_info = {"conn_id": "dummy"}

        with async_mock.patch.object(
            test_module.ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_retrieve, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as json_response:
            mock_retrieve.return_value = async_mock.MagicMock(is_ready=False)
            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.connections_send_ping(self.mock_request)

    async def test_register(self):
        mock_app = async_mock.MagicMock()
        mock_app.add_routes = async_mock.MagicMock()

        await test_module.register(mock_app)
        mock_app.add_routes.assert_called_once()

    async def test_post_process_routes(self):
        mock_app = async_mock.MagicMock(_state={"swagger_dict": {}})
        test_module.post_process_routes(mock_app)
        assert "tags" in mock_app._state["swagger_dict"]
