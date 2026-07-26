"""Live PostgreSQL integration coverage for the optional fleet persistence adapter."""

from __future__ import annotations

import os
import uuid

import pytest

from agentic_security import EnterpriseFleetStore, FleetIdentity, PostgresFleetPersistenceAdapter


def test_live_postgres_fleet_lifecycle() -> None:
    """Exercise migrations, tenant state, rollout, and capability reporting on PostgreSQL."""
    dsn = os.environ.get("AAI_SEC_POSTGRES_DSN")
    if not dsn:
        pytest.skip("AAI_SEC_POSTGRES_DSN is not configured")

    suffix = uuid.uuid4().hex[:12]
    organization_id = f"org-pg-{suffix}"
    project_id = f"project-pg-{suffix}"
    deployment_id = f"deployment-pg-{suffix}"
    template_id = f"template-pg-{suffix}"
    identity = FleetIdentity("postgres-integration", organization_id, frozenset({"admin"}))
    store = EnterpriseFleetStore(
        dsn,
        persistence=PostgresFleetPersistenceAdapter(),
        require_high_availability=True,
    )
    try:
        store.create_organization(organization_id, "PostgreSQL integration")
        store.create_project(organization_id, project_id, "Fleet project")
        store.create_deployment(
            organization_id,
            project_id,
            deployment_id,
            "Fleet deployment",
            environment="test",
            region="ci",
            team="security",
        )
        template = store.create_template(
            identity,
            template_id=template_id,
            name="Safe PostgreSQL template",
            configuration={"policy": {"denyByDefault": True}, "budgets": {"maxActions": 5}},
        )
        assigned = store.assign_template(identity, deployment_id, template["id"])
        rolled_out = store.set_rollout(identity, deployment_id, state="canary", percentage=10)
        assert assigned["rolloutState"] == "staged"
        assert rolled_out["rolloutState"] == "canary"
        assert store.persistence_capabilities()["highAvailability"] is True
        assert store.list_inventory(identity, "deployments").items[0]["team"] == "security"
    finally:
        store.close()
