"""The Sophos XML API client accepts only plain entity names and known Set operations,
because both are placed into the request XML."""
import pytest
from xml.etree import ElementTree as ET

from app.modules.sophos.api import SophosAPI, SophosAPIError


def _api():
    api = SophosAPI("192.0.2.1", 4444, "admin", "secret")
    api._post = lambda body: pytest.fail("no request may be sent")  # noqa: E731
    return api


@pytest.mark.parametrize("entity", ["Zone/><Set", "", "1Zone", "Zone Name", "A" * 65])
def test_get_refuses_entity_names_that_are_not_plain(entity):
    with pytest.raises(SophosAPIError):
        _api().get(entity)


def test_set_refuses_unknown_operation():
    with pytest.raises(SophosAPIError):
        _api().set(ET.Element("Zone"), operation='update"><Remove')
