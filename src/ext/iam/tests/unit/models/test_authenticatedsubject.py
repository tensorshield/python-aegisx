import pytest

from aegisx.ext.iam.models import AuthenticatedSubject
from aegisx.ext.iam.types import DomainPrincipal
from aegisx.ext.iam.types import GroupPrincipal
from aegisx.ext.iam.types import ServiceAccountPrincipal
from aegisx.ext.iam.types import UserPrincipal


def test_service_account_principal():
    subject = AuthenticatedSubject.model_validate({
        'email': 'test@tensorshield.ai',
        'service_account': True
    })
    assert isinstance(subject.principal, ServiceAccountPrincipal)


def test_user_principal():
    subject = AuthenticatedSubject.model_validate({
        'email': 'test@tensorshield.ai',
        'service_account': False
    })
    assert isinstance(subject.principal, UserPrincipal)


@pytest.mark.parametrize("domain, email,service_account", [
    ('test.tensorshield.ai', 'root@test.tensorshield.ai', True),
    ('test.tensorshield.ai', 'root@test.tensorshield.ai', False),
])
def test_subject_has_domain_principal_from_email(domain: str, email: str, service_account: bool):
    subject = AuthenticatedSubject.model_validate({
        'email': email,
        'service_account': service_account
    })
    assert DomainPrincipal.validate(f'domain:{domain}') in subject.principals()



@pytest.mark.parametrize("groups", [
    {
        'group1@a.tensorshield.ai',
        'group1@b.tensorshield.ai',
    },
])
@pytest.mark.parametrize("email,service_account", [
    ('root@test.tensorshield.ai', True),
    ('root@test.tensorshield.ai', False),
])
def test_subject_has_domain_principal_from_groups(
    groups: set[str],
    email: str,
    service_account: bool
):
    subject = AuthenticatedSubject.model_validate({
        'email': email,
        'service_account': service_account,
        'groups': groups
    })
    assert subject.principals() >= {
        GroupPrincipal.fromemail(x)
        for x in groups
    }