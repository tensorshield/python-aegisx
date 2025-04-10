from typing import Annotated

import httpx
import typer
from aegisx.core.const import AEGIS_KEYDIR
from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import TokenBuilder
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from aegisx.ext.iam.models import AuthorizedKeyToken


def setup(app: typer.Typer):
    app.add_typer(subparser)


subparser = typer.Typer(name='iam')


@subparser.command(
    name='authorize',
    help=(
        "Authorize a public key for use with a specific principal"
    )
)
def authorize(
    key: Annotated[str, typer.Argument()],
    id_token: Annotated[
        str,
        typer.Option(
            '--id-token',
            help=(
                "An Open ID Connect ID Token encoded with JWS Compact "
                "serialization."
            )
        )
    ],
    base_url: Annotated[
        str,
        typer.Option(
            '--base-url',
            help=(
                "Base URL at which the IAM service is listening."
            )
        )
    ] = 'http://127.0.0.1:8000'
):
    url = "/keys:authorize"
    jwk = JSONWebKey(
        use='sig',
        key_ops={'verify'},
        private_key=load_pem_private_key(
            open(str(AEGIS_KEYDIR.joinpath(key)), 'rb').read(),
            password=None
        )
    )
    if not jwk.public:
        typer.secho(f"Not an asymmetric key: {key}", fg=typer.colors.RED)
        return
    builder = TokenBuilder(AuthorizedKeyToken, signers=[jwk])\
        .compact()
    with httpx.Client(base_url=base_url) as client:
        response = client.post(
            url=url,
            headers={
                'Authorization': f'Bearer {id_token}'
            },
            json=jwk.public.model_dump(
                mode='json',
                exclude_defaults=True,
                exclude_none=True,
                exclude_unset=True
            )
        )
        print(response.content)