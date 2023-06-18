import asyncio
import json
import logging
import os
import sys
import time
import datetime

from aiohttp import ClientError

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
)
from runners.support.agent import (  # noqa:E402
    CRED_FORMAT_INDY,
    CRED_FORMAT_JSON_LD,
    SIG_TYPE_BLS,
)
from runners.support.utils import (  # noqa:E402
    log_msg,
    log_status,
    prompt,
    prompt_loop,
)

CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
SELF_ATTESTED = os.getenv("SELF_ATTESTED")
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class ServerAgent(AriesAgent):
    def __init__(
            self,
            ident: str,
            http_port: int,
            admin_port: int,
            no_auto: bool = False,
            endorser_role: str = None,
            revocation: bool = False,
            external_host: str = None,
            **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Faber",
            no_auto=no_auto,
            endorser_role=endorser_role,
            revocation=revocation,
            external_host=external_host,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        # TODO define a dict to hold credential attributes
        # based on cred_def_id
        self.cred_attrs = {}

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    def generate_credential_offer(self, aip, cred_type, cred_def_id, exchange_tracing):
        age = 24
        d = datetime.date.today()
        birth_date = datetime.date(d.year - age, d.month, d.day)
        birth_date_format = "%Y%m%d"
        if aip == 20:
            if cred_type == CRED_FORMAT_INDY:
                self.cred_attrs[cred_def_id] = {
                    "name": "Alice Smith",
                    "date": "2018-05-28",
                    "degree": "Maths",
                    "birthdate_dateint": birth_date.strftime(birth_date_format),
                    "timestamp": str(int(time.time())),
                }

                cred_preview = {
                    "@type": CRED_PREVIEW_TYPE,
                    "attributes": [
                        {"name": n, "value": v}
                        for (n, v) in self.cred_attrs[cred_def_id].items()
                    ],
                }
                offer_request = {
                    "connection_id": self.connection_id,
                    "comment": f"Offer on cred def id {cred_def_id}",
                    "auto_remove": False,
                    "credential_preview": cred_preview,
                    "filter": {"indy": {"cred_def_id": cred_def_id}},
                    "trace": exchange_tracing,
                }
                return offer_request

            elif cred_type == CRED_FORMAT_JSON_LD:
                offer_request = {
                    "connection_id": self.connection_id,
                    "filter": {
                        "ld_proof": {
                            "credential": {
                                "@context": [
                                    "https://www.w3.org/2018/credentials/v1",
                                    "https://w3id.org/citizenship/v1",
                                    "https://w3id.org/security/bbs/v1",
                                ],
                                "type": [
                                    "VerifiableCredential",
                                    "PermanentResident",
                                ],
                                "id": "https://credential.example.com/residents/1234567890",
                                "issuer": self.did,
                                "issuanceDate": "2020-01-01T12:00:00Z",
                                "credentialSubject": {
                                    "type": ["PermanentResident"],
                                    "givenName": "ALICE",
                                    "familyName": "SMITH",
                                    "gender": "Female",
                                    "birthCountry": "Bahamas",
                                    "birthDate": "1958-07-17",
                                },
                            },
                            "options": {"proofType": SIG_TYPE_BLS},
                        }
                    },
                }
                return offer_request

            else:
                raise Exception(f"Error invalid credential type: {self.cred_type}")

        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")

    def generate_proof_request_web_request(
            self, aip, cred_type, revocation, exchange_tracing, connectionless=False
    ):
        age = 18
        d = datetime.date.today()
        birth_date = datetime.date(d.year - age, d.month, d.day)
        birth_date_format = "%Y%m%d"

        if aip == 20:
            if cred_type == CRED_FORMAT_INDY:
                req_attrs = [
                    {
                        "name": "name",
                        "restrictions": [{"schema_name": "degree schema"}],
                    },
                    {
                        "name": "date",
                        "restrictions": [{"schema_name": "degree schema"}],
                    },
                ]
                if revocation:
                    req_attrs.append(
                        {
                            "name": "degree",
                            "restrictions": [{"schema_name": "degree schema"}],
                            "non_revoked": {"to": int(time.time() - 1)},
                        },
                    )
                else:
                    req_attrs.append(
                        {
                            "name": "degree",
                            "restrictions": [{"schema_name": "degree schema"}],
                        }
                    )
                if SELF_ATTESTED:
                    # test self-attested claims
                    req_attrs.append(
                        {"name": "self_attested_thing"},
                    )
                req_preds = [
                    # test zero-knowledge proofs
                    {
                        "name": "birthdate_dateint",
                        "p_type": "<=",
                        "p_value": int(birth_date.strftime(birth_date_format)),
                        "restrictions": [{"schema_name": "degree schema"}],
                    }
                ]
                indy_proof_request = {
                    "name": "Proof of Education",
                    "version": "1.0",
                    "requested_attributes": {
                        f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                    },
                    "requested_predicates": {
                        f"0_{req_pred['name']}_GE_uuid": req_pred
                        for req_pred in req_preds
                    },
                }

                if revocation:
                    indy_proof_request["non_revoked"] = {"to": int(time.time())}

                proof_request_web_request = {
                    "presentation_request": {"indy": indy_proof_request},
                    "trace": exchange_tracing,
                }
                if not connectionless:
                    proof_request_web_request["connection_id"] = self.connection_id
                return proof_request_web_request

            else:
                raise Exception(f"Error invalid credential type: {self.cred_type}")

        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")


async def main(args):
    server_agent = await create_agent_with_args(args, ident="faber")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {server_agent.wallet_type})"
                if server_agent.wallet_type
                else ""
            )
        )
        agent = ServerAgent(
            "faber.agent",
            server_agent.start_port,
            server_agent.start_port + 1,
            genesis_data=server_agent.genesis_txns,
            no_auto=server_agent.no_auto,
            tails_server_base_url=server_agent.tails_server_base_url,
            revocation=server_agent.revocation,
            timing=server_agent.show_timing,
            mediation=server_agent.mediation,
            wallet_type=server_agent.wallet_type,
            seed=server_agent.seed,
            aip=server_agent.aip,
            endorser_role=server_agent.endorser_role,
        )

        if server_agent.cred_type == CRED_FORMAT_INDY:
            server_agent.public_did = True
            await server_agent.initialize(
                the_agent=agent,
                create_endorser_agent=(server_agent.endorser_role == "author")
                if server_agent.endorser_role
                else False,
            )
        else:
            raise Exception("Invalid credential type:" + server_agent.cred_type)

        # generate an invitation for Alice
        await server_agent.generate_invitation(
            display_qr=True, reuse_connections=server_agent.reuse_connections, wait=True
        )

        exchange_tracing = False
        options = (
            "    (1) Send Message\n"
            "    (2) Create New Invitation\n"
        )
        if server_agent.revocation:
            options += "    (5) Revoke Credential\n" "    (6) Publish Revocations\n"
        if server_agent.endorser_role and server_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"
        options += "    (T) Toggle tracing on credential/proof exchange\n"
        options += "    (X) Exit?\n[1/2/3/4/{}T/X] ".format(
            "5/6/" if server_agent.revocation else "",
        )
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "tT":
                exchange_tracing = not exchange_tracing
                log_msg(
                    ">>> Credential/Proof Exchange Tracing is {}".format(
                        "ON" if exchange_tracing else "OFF"
                    )
                )

            elif option == "1":
                msg = await prompt("Enter message: ")
                await server_agent.agent.admin_POST(
                    f"/connections/{server_agent.agent.connection_id}/send-message",
                    {"content": msg},
                )

            elif option == "2":
                log_msg(
                    "Creating a new invitation, please receive "
                    "and accept this invitation using Alice agent"
                )
                await server_agent.generate_invitation(
                    display_qr=True,
                    reuse_connections=server_agent.reuse_connections,
                    wait=True,
                )

        if server_agent.show_timing:
            timing = await server_agent.agent.fetch_timing()
            if timing:
                for line in server_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await server_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


def runAgentAsModule():
    parser = arg_parser(ident="faber", port=8020)
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
                "Faber remote debugging to "
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

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)


async def runServerAgentForWebApp(ip):
    parser = arg_parser(ident="faber", port=8020)
    args = parser.parse_args()
    server_agent = await create_agent_with_args(args, ident="faber")
    server_agent.seed = "32100000000032100000003210000000"

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {server_agent.wallet_type})"
                if server_agent.wallet_type
                else ""
            )
        )
        agent = ServerAgent(
            "faber.agent2",
            server_agent.start_port,
            server_agent.start_port + 1,
            genesis_data=server_agent.genesis_txns,
            no_auto=server_agent.no_auto,
            tails_server_base_url=server_agent.tails_server_base_url,
            revocation=server_agent.revocation,
            timing=server_agent.show_timing,
            mediation=server_agent.mediation,
            wallet_type=server_agent.wallet_type,
            seed=server_agent.seed,
            aip=server_agent.aip,
            endorser_role=server_agent.endorser_role,
            external_host=ip,
        )

        if server_agent.cred_type == CRED_FORMAT_INDY:
            server_agent.public_did = True
            await server_agent.initialize(
                the_agent=agent,
                create_endorser_agent=(server_agent.endorser_role == "author")
                if server_agent.endorser_role
                else False,
            )
        else:
            raise Exception("Invalid credential type:" + server_agent.cred_type)

        # detect previous connection
        await check_existent_connection(server_agent)

        print("initialized faber agent")
        return server_agent
    except:
        terminated = await server_agent.terminate()


async def check_existent_connection(agent_container):
    connections = await agent_container.agent.admin_GET(f"/connections")
    if len(connections["results"]) > 0 and "connection_id" in connections["results"][0].keys():
        agent_container.agent.connection_id = connections["results"][0]["connection_id"]
    print(connections)


if __name__ == "__main__":
    runAgentAsModule()
