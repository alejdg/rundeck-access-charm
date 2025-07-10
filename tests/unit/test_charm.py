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

    @patch("subprocess.run")
    @patch("os.chmod")
    @patch("os.makedirs")
    @patch("builtins.open", new_callable=mock_open)
    def test_configure_rundeck_user_with_sudo(
        self, mock_file, mock_makedirs, mock_chmod, mock_run
    ):
        """Test rundeck user configuration with sudo privileges."""
        ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 user@host"
        allowed_commands = [
            "/usr/bin/uptime",
            "/usr/bin/top -bn1",
            "/usr/bin/systemctl restart <service>",
        ]

        # Patch _sanitize_commands and _prepare_sudoers_contents for predictable output
        with patch.object(self.harness.charm, "_sanitize_commands", return_value="cmd1, cmd2"), \
             patch.object(self.harness.charm, "_prepare_sudoers_contents", return_value="sudoers-content"), \
             patch.object(self.harness.charm, "_verify_sudoers", return_value=True):

            self.harness.charm._configure_rundeck_user(ssh_key, allowed_commands)

            # Assert subprocess.run was called for useradd and chown
            mock_run.assert_any_call(
                ["sudo", "useradd", "-m", "-s", "/bin/bash", "rundeck"], check=False
            )
            mock_run.assert_any_call(
                ["sudo", "chown", "-R", "rundeck:rundeck", "/home/rundeck/.ssh"], check=False
            )

            mock_makedirs.assert_called_with("/home/rundeck/.ssh", exist_ok=True)
            mock_file.assert_any_call("/home/rundeck/.ssh/authorized_keys", "w", encoding="utf-8")
            mock_file.assert_any_call("/etc/sudoers.d/rundeck", "w")
            mock_chmod.assert_any_call("/home/rundeck/.ssh/authorized_keys", 0o600)
            mock_chmod.assert_any_call("/etc/sudoers.d/rundeck", 0o440)

            # Check file content
            mock_file().write.assert_any_call(f"{ssh_key}\n")
            mock_file().write.assert_any_call("sudoers-content")

    @patch("subprocess.run")
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
        mock_run,
    ):
        """Test rundeck user configuration without sudo privileges."""
        ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 user@host"
        allowed_commands = None
        mock_exists.return_value = True

        self.harness.charm._configure_rundeck_user(ssh_key, allowed_commands)

        # Assert subprocess.run was called for useradd and chown
        mock_run.assert_any_call(
            ["sudo", "useradd", "-m", "-s", "/bin/bash", "rundeck"], check=False
        )
        mock_run.assert_any_call(
            ["sudo", "chown", "-R", "rundeck:rundeck", "/home/rundeck/.ssh"], check=False
        )

        mock_makedirs.assert_called_with("/home/rundeck/.ssh", exist_ok=True)
        mock_file.assert_any_call("/home/rundeck/.ssh/authorized_keys", "w", encoding="utf-8")
        mock_chmod.assert_any_call("/home/rundeck/.ssh/authorized_keys", 0o600)

        # Sudoers file should be removed
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
        mock_configure.side_effect = RuntimeError("Test exception")
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
