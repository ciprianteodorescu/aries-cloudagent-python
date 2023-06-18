import asyncio
import base64
import binascii
import json
import logging
import os
import sys
from urllib.parse import urlparse
import requests
import socket
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
)
from runners.support.utils import (  # noqa:E402
    check_requires,
    log_msg,
    log_status,
    log_timer,
    prompt,
    prompt_loop,
)

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)

LOCAL_SERVER_ADDRESS = os.getenv('LOCAL_SERVER_ADDRESS', '')
LOCAL_SERVER_HOSTNAME = os.getenv('LOCAL_SERVER_HOSTNAME', 'MacBook-Pro-6.local')
LOCAL_SERVER_PORT = os.getenv('LOCAL_SERVER_PORT', '5040')

AGENT_NAME = os.getenv('AGENT_NAME', 'alice.agent.test8')
USERNAME = os.getenv('USERNAME', 'cip')


class RaspberryAgent(AriesAgent):
    def __init__(
            self,
            ident: str,
            http_port: int,
            admin_port: int,
            no_auto: bool = False,
            aip: int = 20,
            endorser_role: str = None,
            external_host: str = None,
            **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Alice",
            no_auto=no_auto,
            seed=None,
            aip=aip,
            endorser_role=endorser_role,
            external_host=external_host,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()


# TODO: go back to reading from terminal
async def connect_local(agent_container):
    agent_container.agent._connection_ready = asyncio.Future()
    local_server_ip = get_local_server_address()
    details = json.dumps(
        requests.get(f"http://{local_server_ip}:{LOCAL_SERVER_PORT}/get-invitation").json().get('invitation', '')
    )
    if details:
        b64_invite = None
        try:
            url = urlparse(details)
            query = url.query
            if query and "c_i=" in query:
                pos = query.index("c_i=") + 4
                b64_invite = query[pos:]
            elif query and "oob=" in query:
                pos = query.index("oob=") + 4
                b64_invite = query[pos:]
            else:
                b64_invite = details
        except ValueError:
            b64_invite = details

        if b64_invite:
            try:
                padlen = 4 - len(b64_invite) % 4
                if padlen <= 2:
                    b64_invite += "=" * padlen
                invite_json = base64.urlsafe_b64decode(b64_invite)
                details = invite_json.decode("utf-8")
            except binascii.Error:
                pass
            except UnicodeDecodeError:
                pass

        if details:
            try:
                details = json.loads(details)
                # TODO: uncomment this # break
            except json.JSONDecodeError as e:
                log_msg("Invalid invitation:", str(e))

    with log_timer("Connect duration:"):
        await agent_container.input_invitation(details, wait=True)

    try:
        connection = await agent_container.agent.admin_GET(
            f"/connections/{agent_container.agent.connection_id}"
        )
        # add user metadata to the connection
        server_connection_id = requests.get(
            url=f"http://{local_server_ip}:{LOCAL_SERVER_PORT}/get-connection-from-did/{connection['my_did']}",
        ).json()["connection_id"]

        requests.post(
            url=f"http://{local_server_ip}:{LOCAL_SERVER_PORT}/set-connection-user/{server_connection_id}",
            json={"user": USERNAME},
        )
    except:
        log_msg("Could not update associated user.")

    print("Done!")


async def check_existent_connection(agent_container):
    try:
        connections = await agent_container.agent.admin_GET(f"/connections")
        agent_container.agent.connection_id = connections["results"][0]["connection_id"]
        return True
    except:
        return False


def get_local_server_address():
    global LOCAL_SERVER_HOSTNAME
    local_server_ip = ''
    try:
        regex_search = re.search('([0-9]{1,3}\\.){3}[0-9]{1,3}', LOCAL_SERVER_ADDRESS)
        if regex_search is not None and regex_search.group() == LOCAL_SERVER_ADDRESS:
            local_server_ip = LOCAL_SERVER_ADDRESS
        elif not LOCAL_SERVER_HOSTNAME.endswith('.local') and len(LOCAL_SERVER_HOSTNAME) > 0:
            LOCAL_SERVER_HOSTNAME += 'local'
            local_server_ip = socket.gethostbyname(LOCAL_SERVER_HOSTNAME)
        elif LOCAL_SERVER_HOSTNAME.endswith('.local') and len(LOCAL_SERVER_HOSTNAME) > len('.local'):
            local_server_ip = socket.gethostbyname(LOCAL_SERVER_HOSTNAME)
    except socket.gaierror:
        # server not found
        raise Exception(
            f"Address of hostname {LOCAL_SERVER_HOSTNAME} not found! Check if you are connected to the same network"
        )
    return local_server_ip


async def main(args):
    raspberry_agent = await create_agent_with_args(args, ident="alice")

    try:
        log_status(
            "#7 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {raspberry_agent.wallet_type})"
                if raspberry_agent.wallet_type
                else ""
            )
        )
        agent = RaspberryAgent(
            AGENT_NAME,
            raspberry_agent.start_port,
            raspberry_agent.start_port + 1,
            genesis_data=raspberry_agent.genesis_txns,
            no_auto=raspberry_agent.no_auto,
            tails_server_base_url=raspberry_agent.tails_server_base_url,
            revocation=raspberry_agent.revocation,
            timing=raspberry_agent.show_timing,
            mediation=raspberry_agent.mediation,
            wallet_type=raspberry_agent.wallet_type,
            aip=raspberry_agent.aip,
            endorser_role=raspberry_agent.endorser_role,
        )

        await raspberry_agent.initialize(the_agent=agent)

        log_status("#9 Input server_agent.py invitation details")
        is_already_connected = await check_existent_connection(raspberry_agent)
        if not is_already_connected:
            await connect_local(raspberry_agent)

        options = "    (3) Send Message\n"
        if raspberry_agent.endorser_role and raspberry_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"
        options += "    (X) Exit?\n[3/X] "
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option == "3":
                msg = await prompt("Enter message: ")
                if msg:
                    await raspberry_agent.agent.admin_POST(
                        f"/connections/{raspberry_agent.agent.connection_id}/send-message",
                        {"content": msg},
                    )

        if raspberry_agent.show_timing:
            timing = await raspberry_agent.agent.fetch_timing()
            if timing:
                for line in raspberry_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await raspberry_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


def runAgentAsModule():
    parser = arg_parser(ident="alice", port=8030)
    args = parser.parse_args()

    ENABLE_PYDEVD_PYCHARM = os.getenv("ENABLE_PYDEVD_PYCHARM", "").lower()
    ENABLE_PYDEVD_PYCHARM = ENABLE_PYDEVD_PYCHARM and ENABLE_PYDEVD_PYCHARM not in (
        "false",
        "0",
    )
    PYDEVD_PYCHARM_HOST = os.getenv("PYDEVD_PYCHARM_HOST", "localhost")
    PYDEVD_PYCHARM_CONTROLLER_PORT = int(
        os.getenv("PYDEVD_PYCHARM_CONTROLLER_PORT", 5001)
    )

    if ENABLE_PYDEVD_PYCHARM:
        try:
            import pydevd_pycharm

            print(
                "Alice remote debugging to "
                f"{PYDEVD_PYCHARM_HOST}:{PYDEVD_PYCHARM_CONTROLLER_PORT}"
            )
            pydevd_pycharm.settrace(
                host=PYDEVD_PYCHARM_HOST,
                port=PYDEVD_PYCHARM_CONTROLLER_PORT,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        except ImportError:
            print("pydevd_pycharm library was not found")

    check_requires(args)

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)


async def runAgent(ip):
    parser = arg_parser(ident="alice", port=8030)
    args = parser.parse_args()
    # check_requires(args)

    raspberry_agent = await create_agent_with_args(args, ident="alice")

    try:
        log_status(
            "#7 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {raspberry_agent.wallet_type})"
                if raspberry_agent.wallet_type
                else ""
            )
        )
        agent = RaspberryAgent(
            AGENT_NAME,
            raspberry_agent.start_port,
            raspberry_agent.start_port + 1,
            genesis_data=raspberry_agent.genesis_txns,
            no_auto=raspberry_agent.no_auto,
            tails_server_base_url=raspberry_agent.tails_server_base_url,
            revocation=raspberry_agent.revocation,
            timing=raspberry_agent.show_timing,
            mediation=raspberry_agent.mediation,
            wallet_type=raspberry_agent.wallet_type,
            aip=raspberry_agent.aip,
            endorser_role=raspberry_agent.endorser_role,
            external_host=ip
        )

        await raspberry_agent.initialize(the_agent=agent)

        is_already_connected = await check_existent_connection(raspberry_agent)
        if not is_already_connected:
            await connect_local(raspberry_agent)

        return raspberry_agent
    except:
        terminated = await raspberry_agent.terminate()


if __name__ == "__main__":
    runAgentAsModule()
