"""API-response handling. No network: `Client.request` is stubbed per test."""

import pytest

from policy import UNKNOWN
from signals import Client, gather


class FakeClient(Client):
    """Client whose HTTP layer is a scripted {url-substring: (status, payload)}."""

    def __init__(self, routes):
        super().__init__("https://api.github.com", "https://api.github.com/graphql", "t")
        self.routes = routes
        self.calls = []

    def request(self, url, *, data=None, token=None):
        self.calls.append(url)
        for fragment, response in self.routes.items():
            if fragment in url:
                return response
        return 0, None


# --------------------------------------------------------------------------
# org_role
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ((200, {"state": "active", "role": "admin"}), "admin"),
        ((200, {"state": "active", "role": "member"}), "member"),
        ((200, {"state": "pending", "role": "admin"}), "outside"),
        ((404, None), "outside"),
        ((500, None), UNKNOWN),
        ((0, None), UNKNOWN),
    ],
)
def test_org_role(response, expected):
    client = FakeClient({"/memberships/": response})
    assert client.org_role("acme", "alice") == expected


def test_pending_invite_is_not_active_membership():
    client = FakeClient({"/memberships/": (200, {"state": "pending", "role": "admin"})})
    assert client.org_role("acme", "alice") == "outside"


# --------------------------------------------------------------------------
# teams
# --------------------------------------------------------------------------
def test_teams_active_membership_matches():
    client = FakeClient({"/teams/": (200, {"state": "active"})})
    matched, resolved = client.teams("acme", "alice", ("release",))
    assert matched == ("release",)
    assert resolved is True


def test_teams_404_is_resolved_but_unmatched():
    client = FakeClient({"/teams/": (404, None)})
    matched, resolved = client.teams("acme", "alice", ("release",))
    assert matched == ()
    assert resolved is True, "a definitive 404 means 'not a member', not 'unknown'"


def test_teams_server_error_marks_unresolved():
    client = FakeClient({"/teams/": (502, None)})
    matched, resolved = client.teams("acme", "alice", ("release",))
    assert resolved is False


def test_teams_pending_membership_does_not_match():
    client = FakeClient({"/teams/": (200, {"state": "pending"})})
    matched, _ = client.teams("acme", "alice", ("release",))
    assert matched == ()


# --------------------------------------------------------------------------
# repo permission
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ((200, {"role_name": "maintain", "permission": "write"}), "maintain"),
        ((200, {"permission": "admin"}), "admin"),
        ((404, None), "none"),
        ((403, None), "none"),
        ((500, None), UNKNOWN),
    ],
)
def test_repo_permission(response, expected):
    client = FakeClient({"/collaborators/": response})
    assert client.repo_permission("acme/app", "alice") == expected


def test_role_name_preferred_over_legacy_permission_field():
    client = FakeClient({"/collaborators/": (200, {"role_name": "triage", "permission": "write"})})
    assert client.repo_permission("acme/app", "alice") == "triage"


# --------------------------------------------------------------------------
# enterprise owner
# --------------------------------------------------------------------------
def test_enterprise_owner_match():
    payload = {"data": {"enterprise": {"ownerInfo": {"admins": {"nodes": [{"login": "Alice"}]}}}}}
    client = FakeClient({"graphql": (200, payload)})
    assert client.enterprise_owner("acme", "alice") == "true", "comparison must be case-insensitive"


def test_enterprise_owner_absent():
    payload = {"data": {"enterprise": {"ownerInfo": {"admins": {"nodes": [{"login": "bob"}]}}}}}
    client = FakeClient({"graphql": (200, payload)})
    assert client.enterprise_owner("acme", "alice") == "false"


@pytest.mark.parametrize(
    "payload",
    [
        {"errors": [{"message": "insufficient scope"}]},
        {"data": {"enterprise": None}},
        {"data": {}},
        None,
    ],
)
def test_enterprise_owner_unreadable_is_unknown_not_false(payload):
    client = FakeClient({"graphql": (200, payload)})
    assert client.enterprise_owner("acme", "alice") == UNKNOWN, (
        "an unreadable enterprise response must not be reported as 'not an owner'"
    )


def test_enterprise_owner_non_200_is_unknown():
    client = FakeClient({"graphql": (401, None)})
    assert client.enterprise_owner("acme", "alice") == UNKNOWN


# --------------------------------------------------------------------------
# Transport guard
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "http://api.github.com/orgs/a", "ftp://x/y", "gopher://x"],
)
def test_non_https_urls_are_refused(url):
    client = Client("https://api.github.com", "https://api.github.com/graphql", "t")
    status, payload = client.request(url)
    assert (status, payload) == (0, None), "non-HTTPS must never reach urllib"


def test_poisoned_api_url_yields_unknown_not_a_grant():
    client = Client("file:///tmp", "file:///tmp", "t")
    assert client.org_role("acme", "alice") == UNKNOWN
    assert client.enterprise_owner("acme", "alice") == UNKNOWN


# --------------------------------------------------------------------------
# gather only calls what the policy needs
# --------------------------------------------------------------------------
def test_gather_skips_unneeded_lookups():
    client = FakeClient({"/memberships/": (200, {"state": "active", "role": "member"})})
    result = gather(
        client,
        actor="alice",
        organization="acme",
        need_org_role=True,
        need_repo_permission=False,
    )
    assert result.repo_permission == UNKNOWN
    assert result.enterprise_owner == UNKNOWN
    assert not any("/collaborators/" in c for c in client.calls)
    assert not any("graphql" in c for c in client.calls)


def test_gather_requests_repo_permission_when_needed():
    client = FakeClient(
        {
            "/memberships/": (200, {"state": "active", "role": "member"}),
            "/collaborators/": (200, {"role_name": "write"}),
        }
    )
    result = gather(
        client,
        actor="alice",
        organization="acme",
        repository="acme/app",
        need_repo_permission=True,
    )
    assert result.repo_permission == "write"
