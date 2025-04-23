#!/usr/bin/env python3
# Copyright 2025 Alexandre Gomes
# See LICENSE file for licensing details.

import logging
import subprocess

import pytest
import pytest_asyncio
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

# Test configurations
TEST_SSH_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 test-user@host"
TEST_SUDOER = "ALL=(ALL) NOPASSWD:ALL"
CHARM_NAME = "rundeck-access"
PRINCIPAL_APP = "ubuntu"
PRINCIPAL_SERIES = "focal"  # 20.04


@pytest_asyncio.fixture(scope="module")
async def deploy_charms(ops_test: OpsTest):
    """Build the charm and deploy it with a principal charm."""
    # Build the charm
    charm_path = await ops_test.build_charm(".")

    logger.info(f"Charm path:{charm_path}")

    # First deploy a principal application
    await ops_test.model.deploy(PRINCIPAL_APP, series=PRINCIPAL_SERIES)
    await ops_test.model.wait_for_idle(status="active", timeout=1000)

    # Deploy subordinate with configuration
    await ops_test.model.deploy(
        charm_path,
        application_name=CHARM_NAME,
        config={"ssh-key": TEST_SSH_KEY, "sudoer": TEST_SUDOER},
        num_units=0,
    )

    # Create relation between principal and subordinate
    await ops_test.model.integrate(f"{PRINCIPAL_APP}", f"{CHARM_NAME}")

    # Wait for active status
    await ops_test.model.wait_for_idle(status="active", timeout=1000)

    # Return the principal unit name for testing
    return f"{PRINCIPAL_APP}/0"


class TestRundeckAccessCharm:
    """Integration tests for the RundeckAccess charm."""

    @pytest.mark.asyncio
    async def test_verify_rundeck_user_setup(self, ops_test: OpsTest, deploy_charms):
        """Verify the rundeck user setup after deployment."""
        principal_unit = deploy_charms

        # Check if the rundeck user exists - use subprocess instead of ops_test.juju
        cmd = [
            "juju",
            "ssh",
            "--model",
            ops_test.model_name,
            principal_unit,
            "id rundeck",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0, "Rundeck user was not created"

        # Check SSH key configuration
        cmd = [
            "juju",
            "ssh",
            "--model",
            ops_test.model_name,
            principal_unit,
            "sudo cat /home/rundeck/.ssh/authorized_keys",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0, "Could not read authorized_keys file"
        assert TEST_SSH_KEY in result.stdout, "SSH key not properly configured"

        # Check permissions
        cmd = [
            "juju",
            "ssh",
            "--model",
            ops_test.model_name,
            principal_unit,
            "sudo ls -la /home/rundeck/.ssh/authorized_keys",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0, "Could not check file permissions"
        assert "-rw-------" in result.stdout, "SSH key file has incorrect permissions"

        # Check sudoers configuration
        cmd = [
            "juju",
            "ssh",
            "--model",
            ops_test.model_name,
            principal_unit,
            "sudo cat /etc/sudoers.d/rundeck",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0, "Could not read sudoers file"
        assert f"rundeck {TEST_SUDOER}" in result.stdout, "Sudoers not properly configured"

    @pytest.mark.asyncio
    async def test_update_configuration(self, ops_test: OpsTest, deploy_charms):
        """Test updating the configuration."""
        principal_unit = deploy_charms

        # Get status to verify the application exists
        status = await ops_test.model.get_status()
        assert CHARM_NAME in status.applications, f"Application {CHARM_NAME} not found in model"

        # Update with new SSH key and remove sudo
        updated_ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI updated-user@host"
        await ops_test.model.applications[CHARM_NAME].set_config(
            {"ssh-key": updated_ssh_key, "sudoer": ""}
        )

        # Wait for idle
        await ops_test.model.wait_for_idle(status="active", timeout=1000)

        # Verify SSH key was updated - use subprocess
        cmd = [
            "juju",
            "ssh",
            "--model",
            ops_test.model_name,
            principal_unit,
            "sudo cat /home/rundeck/.ssh/authorized_keys",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0, "Could not read updated authorized_keys file"
        assert updated_ssh_key in result.stdout, "Updated SSH key not applied"

        # Verify sudoers file was removed - use subprocess
        cmd = [
            "juju",
            "ssh",
            "--model",
            ops_test.model_name,
            principal_unit,
            "sudo ls -la /etc/sudoers.d/rundeck || echo 'File removed'",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert "File removed" in result.stdout, "Sudoers file was not removed"

    @pytest.mark.asyncio
    async def test_invalid_configuration(self, ops_test: OpsTest):
        """Test charm behavior with invalid configuration."""
        # Get status to verify the application exists
        status = await ops_test.model.get_status()
        assert CHARM_NAME in status.applications, f"Application {CHARM_NAME} not found in model"

        # Set invalid SSH key
        await ops_test.model.applications[CHARM_NAME].set_config(
            {
                "ssh-key": "invalid-ssh-key",
            }
        )

        # Charm should go to blocked status
        await ops_test.model.wait_for_idle(status="blocked", timeout=1000)

        # Verify the status message
        status = await ops_test.model.get_status()
        assert status.applications[CHARM_NAME].status == "blocked", (
            "Charm status should be blocked"
        )
        assert "Invalid or missing SSH key" in status.applications[CHARM_NAME].status_message, (
            "Charm did not block with invalid SSH key"
        )

        # Reset to valid configuration
        await ops_test.model.applications[CHARM_NAME].set_config(
            {
                "ssh-key": TEST_SSH_KEY,
            }
        )

        # Wait for active status
        await ops_test.model.wait_for_idle(status="active", timeout=1000)

    @pytest.mark.asyncio
    async def test_rundeck_user_functionality(self, ops_test: OpsTest, deploy_charms):
        """Test that the rundeck user can perform expected operations."""
        principal_unit = deploy_charms

        # Create a test file as the rundeck user to verify sudo works
        if TEST_SUDOER:  # Only test if sudo was configured
            cmd = [
                "juju",
                "ssh",
                "--model",
                ops_test.model_name,
                principal_unit,
                "sudo -u rundeck touch /tmp/rundeck_test_file && ls -la /tmp/rundeck_test_file",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            assert result.returncode == 0, "Failed to create test file as rundeck user"
            assert "rundeck_test_file" in result.stdout, "Test file was not created"

            # Verify the file ownership
            cmd = [
                "juju",
                "ssh",
                "--model",
                ops_test.model_name,
                principal_unit,
                "sudo ls -la /tmp/rundeck_test_file",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            assert result.returncode == 0, "Could not check file ownership"
            assert "rundeck" in result.stdout, "File not owned by rundeck user"
