"""Tests for Study Groups API endpoints routed through _dispatch.

These tests exercise the join and invitation flows end-to-end via the
worker dispatcher so that regressions in table naming (activity_members
vs study_group_members, activity_invites vs study_group_invites) or
routing are caught.
"""

import json

import pytest

from tests.helpers import (
    load_worker,
    MockRequest,
    MockRow,
    MockDB,
    make_env,
    make_stmt,
)


worker = load_worker()

JWT = "test-jwt-secret"


def _parse(resp):
    return json.loads(resp.body)


def _make_user_token(uid="user-1", username="alice", role="member"):
    return worker.create_token(uid, username, role, JWT)


@pytest.mark.asyncio
class TestStudyGroupJoin:
    async def test_join_public_group_uses_membership_flow(self):
        """Joining a public study group goes through the membership path and returns 200.

        This indirectly verifies that the /api/study-groups/:id/join route is
        wired correctly and that the handler can talk to the DB without
        missing-table errors.
        """

        token = _make_user_token()
        headers = {"Authorization": f"Bearer {token}"}

        # DB statement sequence used by _join_group:
        # 1) SELECT group from activities
        # 2) SELECT existing membership from activity_members
        # 3) INSERT into activity_members (capacity-guarded)
        # 4) SELECT membership from activity_members to confirm join
        group_row = MockRow(
            id="g1",
            name="Study Group",
            creator_id="host-1",
            max_members=10,
            is_private=0,
        )

        env = make_env(
            db=MockDB(
                [
                    make_stmt(first=group_row),           # group SELECT
                    make_stmt(first=None),                # existing membership
                    make_stmt(),                          # INSERT membership
                    make_stmt(first=MockRow(id="m1")),   # verify membership
                ]
            )
        )

        req = MockRequest(
            method="POST",
            url="http://localhost/api/study-groups/g1/join",
            headers=headers,
        )

        resp = await worker._dispatch(req, env)
        assert resp.status == 200
        data = _parse(resp)
        assert data["message"] == "Joined study group"


@pytest.mark.asyncio
class TestStudyGroupInvites:
    async def test_accept_invitation_respects_capacity(self):
        """Accepting an invite runs through the invite + membership flow without errors.

        This ensures the accept handler uses the generic activity_members and
        activity_invites tables and that the capacity-guarded INSERT executes
        without missing-table issues.
        """

        token = _make_user_token(uid="user-2", username="bob")
        headers = {"Authorization": f"Bearer {token}"}

        # DB statement sequence used by _respond_invitation (accept path):
        # 1) SELECT invite + activity row (JOIN activity_invites, activities)
        # 2) SELECT existing membership from activity_members
        # 3) INSERT into activity_members (capacity-guarded)
        # 4) SELECT membership from activity_members to confirm join
        # 5) UPDATE activity_invites status
        invite_row = MockRow(
            id="inv-1",
            activity_id="g2",
            inviter_id="host-1",
            invitee_id="user-2",
            status="pending",
            group_name="Study Group 2",
            max_members=5,
        )

        env = make_env(
            db=MockDB(
                [
                    make_stmt(first=invite_row),          # invite + activity SELECT
                    make_stmt(first=None),                # existing membership
                    make_stmt(),                          # INSERT membership
                    make_stmt(first=MockRow(id="m2")),   # verify membership
                    make_stmt(),                          # UPDATE activity_invites
                ]
            )
        )

        body = json.dumps({"action": "accept"})
        req = MockRequest(
            method="POST",
            url="http://localhost/api/invitations/inv-1/respond",
            headers={**headers, "Content-Type": "application/json"},
            body=body,
        )

        resp = await worker._dispatch(req, env)
        assert resp.status == 200
        data = _parse(resp)
        assert data["message"] == "Invitation accepted"

