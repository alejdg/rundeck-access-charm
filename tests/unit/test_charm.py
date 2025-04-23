# Copyright 2025 Alexandre
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest
from unittest.mock import mock_open, patch

from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness

from charm import RundeckAccessCharm


class TestRundeckAccessCharm(unittest.TestCase):
    def setUp(self):
        config_yaml = """
        options:
          ssh-key:
            type: string
            default: ""
          sudoer:
            type: string
            default: ""
        """
        self.harness = Harness(RundeckAccessCharm, config=config_yaml)
        self.harness.set_model_name("testing")
        self.harness.begin()
        print("Available config options:", list(self.harness.charm.config.keys()))

        # Set up config options
        self.harness.update_config({"ssh-key": "", "sudoer": ""})
        self.addCleanup(self.harness.cleanup)

    def test_start(self):
        """Test that the charm sets ActiveStatus on start event."""
        self.harness.charm.on.start.emit()
        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

    def test_validate_ssh_key_valid(self):
        """Test SSH key validation with valid keys."""
        valid_keys = [
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 user@host",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI user@host",
        ]
        for key in valid_keys:
            self.assertTrue(self.harness.charm._validate_ssh_key(key))

    def test_validate_ssh_key_invalid(self):
        """Test SSH key validation with invalid keys."""
        invalid_keys = [
            "not-a-ssh-key",
            "ssh-rsa invalid-format",
            "ssh rsa AAAAB3NzaC1yc2E",
            "",
        ]
        for key in invalid_keys:
            self.assertFalse(self.harness.charm._validate_ssh_key(key))

    @patch("os.system")
    @patch("os.chmod")
    @patch("os.makedirs")
    @patch("builtins.open", new_callable=mock_open)
    def test_configure_rundeck_user_with_sudo(
        self, mock_file, mock_makedirs, mock_chmod, mock_system
    ):
        """Test rundeck user configuration with sudo privileges."""
        ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 user@host"
        sudoer = "ALL=(ALL) NOPASSWD:ALL"

        self.harness.charm._configure_rundeck_user(ssh_key, sudoer)

        # Assert system calls were made correctly
        mock_system.assert_any_call("sudo useradd -m -s /bin/bash rundeck || true")
        mock_makedirs.assert_called_with("/home/rundeck/.ssh", exist_ok=True)
        mock_file.assert_any_call("/home/rundeck/.ssh/authorized_keys", "w")
        mock_file.assert_any_call("/etc/sudoers.d/rundeck", "w")
        mock_chmod.assert_called_with("/home/rundeck/.ssh/authorized_keys", 0o600)

        # Check file content
        mock_file().write.assert_any_call(f"{ssh_key}\n")
        mock_file().write.assert_any_call(f"rundeck {sudoer}\n")

    @patch("os.system")
    @patch("os.chmod")
    @patch("os.makedirs")
    @patch("os.path.exists")
    @patch("os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_configure_rundeck_user_without_sudo(
        self,
        mock_file,
        mock_remove,
        mock_exists,
        mock_makedirs,
        mock_chmod,
        mock_system,
    ):
        """Test rundeck user configuration without sudo privileges."""
        ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 user@host"
        sudoer = None
        mock_exists.return_value = True

        self.harness.charm._configure_rundeck_user(ssh_key, sudoer)

        # Assert system calls were made correctly
        mock_system.assert_any_call("sudo useradd -m -s /bin/bash rundeck || true")
        mock_remove.assert_called_with("/etc/sudoers.d/rundeck")
        mock_file().write.assert_called_with(f"{ssh_key}\n")

    @patch("charm.RundeckAccessCharm._configure_rundeck_user")
    def test_config_changed_with_valid_ssh_key(self, mock_configure):
        """Test config-changed event with valid SSH key."""
        self.harness.update_config(
            {
                "ssh-key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 user@host",
                "sudoer": "ALL=(ALL) NOPASSWD:ALL",
            }
        )

        mock_configure.assert_called_once()
        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus("Configuration applied successfully"),
        )

    def test_config_changed_with_invalid_ssh_key(self):
        """Test config-changed event with invalid SSH key."""
        self.harness.update_config(
            {"ssh-key": "invalid-ssh-key", "sudoer": "ALL=(ALL) NOPASSWD:ALL"}
        )

        self.assertEqual(
            self.harness.model.unit.status, BlockedStatus("Invalid or missing SSH key")
        )

    @patch("charm.RundeckAccessCharm._configure_rundeck_user")
    def test_config_changed_with_exception(self, mock_configure):
        """Test config-changed event with exception during configuration."""
        mock_configure.side_effect = Exception("Test exception")
        self.harness.update_config(
            {
                "ssh-key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 user@host",
                "sudoer": "ALL=(ALL) NOPASSWD:ALL",
            }
        )

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Failed to configure: Test exception"),
        )
