#!/usr/bin/env python3
# Copyright 2025 Alexandre Gomes
# See LICENSE file for licensing details.

import logging
import subprocess

import pytest
import pytest_asyncio
from pytest_operator.plugin import OpsTest
import json

logger = logging.getLogger(__name__)

# Test configurations
TEST_SSH_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 test-user@host"
TEST_ALLOWED_COMMANDS_LIST = [
    "/usr/bin/uptime",
    "/usr/bin/top -bn1",
    "/usr/bin/systemctl restart something",
]
TEST_ALLOWED_COMMANDS = json.dumps(TEST_ALLOWED_COMMANDS_LIST)
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
    logger.info(f"Deploying {CHARM_NAME} with SSH key and allowed commands")
    logger.info(f"Allowed commands: {TEST_ALLOWED_COMMANDS}")
    logger.info(TEST_ALLOWED_COMMANDS)
    await ops_test.model.deploy(
        charm_path,
        application_name=CHARM_NAME,
        config={"ssh-key": TEST_SSH_KEY, "allowed-commands": TEST_ALLOWED_COMMANDS},
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
            f"id rundeck-{CHARM_NAME}",
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
            f"sudo cat /home/rundeck-{CHARM_NAME}/.ssh/authorized_keys",
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
            f"sudo stat -c '%a' /home/rundeck-{CHARM_NAME}/.ssh/authorized_keys",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0, "Could not check file permissions"
        assert "600" in result.stdout, "SSH key file has incorrect permissions"

        # Check sudoers configuration
        cmd = [
            "juju",
            "ssh",
            "--model",
            ops_test.model_name,
            principal_unit,
            f"sudo cat /etc/sudoers.d/rundeck-{CHARM_NAME}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0, "Could not read sudoers file"
        # Check for Cmnd_Alias and rundeck ALL line
        cmd_alias = f"RUNDECK_CMDS_{CHARM_NAME.upper().replace('-', '_')}"
        assert f"Cmnd_Alias {cmd_alias}" in result.stdout, "Sudoers missing Cmnd_Alias"
        assert f"rundeck-{CHARM_NAME} ALL=(ALL) NOPASSWD: {cmd_alias}" in result.stdout, "Sudoers not properly configured"
        for cmd_str in json.loads(TEST_ALLOWED_COMMANDS):
            assert cmd_str in result.stdout, f"Allowed command {cmd_str} missing from sudoers"

    @pytest.mark.asyncio
    async def test_update_configuration(self, ops_test: OpsTest, deploy_charms):
        """Test updating the configuration."""
        principal_unit = deploy_charms

        # Get status to verify the application exists
        status = await ops_test.model.get_status()
        assert CHARM_NAME in status.applications, f"Application {CHARM_NAME} not found in model"

        # Update with new SSH key and remove allowed commands
        updated_ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI updated-user@host"
        await ops_test.model.applications[CHARM_NAME].set_config(
            {"ssh-key": updated_ssh_key, "allowed-commands": ""}
        )
        await ops_test.model.wait_for_idle(status="active", timeout=1000)

        # Verify SSH key was updated - use subprocess
        cmd = [
            "juju",
            "ssh",
            "--model",
            ops_test.model_name,
            principal_unit,
            f"sudo cat /home/rundeck-{CHARM_NAME}/.ssh/authorized_keys",
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
            f"if [ -f /etc/sudoers.d/rundeck-{CHARM_NAME} ]; then echo 'exists'; else echo 'removed'; fi",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert "removed" in result.stdout, "Sudoers file was not removed"

    @pytest.mark.asyncio
    async def test_invalid_configuration(self, ops_test: OpsTest):
        """Test charm behavior with invalid configuration."""
        # Get status to verify the application exists
        status = await ops_test.model.get_status()
        assert CHARM_NAME in status.applications, f"Application {CHARM_NAME} not found in model"

        # Set invalid SSH key
        await ops_test.model.applications[CHARM_NAME].set_config(
            {"ssh-key": "invalid-ssh-key"}
        )
        await ops_test.model.wait_for_idle(status="blocked", timeout=60, apps=[CHARM_NAME])

        # Verify the status message
        status = await ops_test.model.get_status()
        logger.info(f"Current status: {status.applications[CHARM_NAME].status.status}")
        logger.info(f"Current status: {status.applications[CHARM_NAME]}")
        assert status.applications[CHARM_NAME].status.status == "blocked", (
            "Charm status should be blocked"
        )
        assert "Invalid or missing SSH key" in status.applications[CHARM_NAME].status.info, (
            "Charm did not block with invalid SSH key"
        )

        # Reset to valid configuration
        logger.info("Resetting configuration to valid state")
        await ops_test.model.applications[CHARM_NAME].set_config(
            {"ssh-key": TEST_SSH_KEY, "allowed-commands": TEST_ALLOWED_COMMANDS}
        )
        await ops_test.model.wait_for_idle(status="active", timeout=60)
        logger.info("test_invalid_configuration completed successfully")

    @pytest.mark.asyncio
    async def test_rundeck_user_functionality(self, ops_test: OpsTest, deploy_charms):
        """Test that the rundeck user can perform expected operations."""
        principal_unit = deploy_charms

        logger.info("Testing rundeck user functionality")
        # Create a test file as the rundeck user to verify sudo works
        if TEST_ALLOWED_COMMANDS:  # Only test if sudo was configured
            cmd = [
                "juju",
                "ssh",
                "--model",
                ops_test.model_name,
                principal_unit,
                f"sudo -u rundeck-{CHARM_NAME} touch /tmp/rundeck_test_file && ls -la /tmp/rundeck_test_file",
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

    @pytest.mark.asyncio
    async def test_remove_relation_removes_user_and_sudoers(self, ops_test: OpsTest, deploy_charms):
        """Test removing the relation cleans up the rundeck user and sudoers file."""
        principal_unit = deploy_charms

        # Remove the relation between principal and subordinate
        ops_test.model.applications[PRINCIPAL_APP].remove_relation(CHARM_NAME, PRINCIPAL_APP)
        await ops_test.model.wait_for_idle(status="active", timeout=1000)

        # Check that the rundeck user is removed
        cmd = [
            "juju",
            "ssh",
            "--model",
            ops_test.model_name,
            principal_unit,
            "id rundeck",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode != 0, "Rundeck user was not removed"

        # Check that the sudoers file is removed
        cmd = [
            "juju",
            "ssh",
            "--model",
            ops_test.model_name,
            principal_unit,
            "test -f /etc/sudoers.d/rundeck && echo exists || echo removed",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert "removed" in result.stdout, "Sudoers file was not removed"
