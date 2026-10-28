import pytest

from api.auth import validate_password_strength
from scripts.purge_test_users import plan_purge
from scripts.rotate_admin_password import generate_temporary_password


def test_temporary_password_satisfies_policy():
    for _ in range(20):
        password = generate_temporary_password()
        ok, reason = validate_password_strength(password)
        assert ok, reason


def test_purge_refuses_empty_keep_list():
    with pytest.raises(ValueError):
        plan_purge([])


def test_purge_keep_list_must_include_an_admin():
    with pytest.raises(ValueError):
        plan_purge(["definitely_not_a_user"])
