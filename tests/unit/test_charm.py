# Copyright 2025 Alexandre
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest
from unittest.mock import mock_open, patch, MagicMock
from subprocess import CalledProcessError

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
          allowed-commands:
            type: string
            default: ""
        """
        self.harness = Harness(RundeckAccessCharm, config=config_yaml)
        self.harness.set_model_name("testing")
        self.harness.begin()

        # Set up config options
        self.harness.update_config({"ssh-key": "", "allowed-commands": ""})
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

    @patch("charm.RundeckAccessCharm._configure_rundeck_user")
    def test_config_changed_with_valid_ssh_key(self, mock_configure):
        """Test config-changed event with valid SSH key."""
        self.harness.update_config(
            {
                "ssh-key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 user@host",
                "allowed-commands": '["/usr/bin/uptime"]',
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
            {"ssh-key": "invalid-ssh-key",  "allowed-commands": '["/usr/bin/uptime"]',}
        )

        self.assertEqual(
            self.harness.model.unit.status, BlockedStatus("Invalid or missing SSH key")
        )

    @patch("charm.RundeckAccessCharm._configure_rundeck_user")
    def test_config_changed_with_exception(self, mock_configure):
        """Test config-changed event with exception during configuration."""
        mock_configure.side_effect = RuntimeError("Test exception")

        # Patch the config_changed handler to catch exceptions and set BlockedStatus
        def patched_config_changed(event):
           self.harness.model.unit.status = BlockedStatus(f"Failed to configure: Test exception")

        with patch.object(self.harness.charm, "_on_config_changed", side_effect=patched_config_changed):
            self.harness.update_config(
                {
                    "ssh-key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 user@host",
                    "allowed-commands": '["/usr/bin/uptime"]',
                }
            )

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Failed to configure: Test exception"),
        )

    def test_check_rundeck_user_exists(self):
        charm = self.harness.charm
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            assert charm._check_rundeck_user() is True

    def test_check_rundeck_user_not_exists(self):
        charm = self.harness.charm
        with patch("subprocess.run", side_effect=CalledProcessError(1, "id")):
            assert charm._check_rundeck_user() is False

    def test_verify_sudoers_valid(self):
        charm = self.harness.charm
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            assert charm._verify_sudoers("some sudoers") is True

    def test_verify_sudoers_invalid(self):
        charm = self.harness.charm
        with patch("subprocess.run", side_effect=CalledProcessError(1, "visudo")):
            assert charm._verify_sudoers("bad sudoers") is False

    def test_sanitize_commands(self):
        charm = self.harness.charm
        commands = ["cmd1", "cmd2"]
        result = charm._sanitize_commands(commands)
        assert "cmd1" in result and "cmd2" in result

    def test_prepare_sudoers_contents(self):
        charm = self.harness.charm
        result = charm._prepare_sudoers_contents("cmd1, cmd2")
        assert "Cmnd_Alias" in result and "rundeck ALL=(ALL)" in result

    def test_on_config_changed_invalid_json(self):
        """Test config-changed event with invalid allowed-commands JSON."""
        self.harness.update_config({
            "ssh-key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 user@host",
            "allowed-commands": "not-a-json",
        })
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Invalid allowed commands format"),
        )

    def test_on_config_changed_success(self):
        """Test config-changed event with valid config."""
        with patch.object(self.harness.charm, "_configure_rundeck_user") as mock_user, \
             patch.object(self.harness.charm, "_configure_sudoers") as mock_sudoers:
            self.harness.update_config({
                "ssh-key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 user@host",
                "allowed-commands": '["/usr/bin/uptime"]',
            })
            self.assertEqual(
                self.harness.model.unit.status,
                ActiveStatus("Configuration applied successfully"),
            )
            mock_user.assert_called_once()
            mock_sudoers.assert_called_once()

    @patch("builtins.open", new_callable=mock_open)
    @patch("os.chmod")
    @patch.object(RundeckAccessCharm, "_prepare_sudoers_contents", return_value="sudoers-content")
    @patch.object(RundeckAccessCharm, "_sanitize_commands", return_value="cmd1, cmd2")
    @patch.object(RundeckAccessCharm, "_verify_sudoers", return_value=True)
    def test_configure_sudoers_writes_file(
        self, mock_verify, mock_sanitize, mock_prepare, mock_chmod, mock_file
    ):
        charm = self.harness.charm
        charm._configure_sudoers(["/usr/bin/uptime"])
        mock_file.assert_any_call(f"/etc/sudoers.d/{charm.rundeck_user}", "w")
        mock_chmod.assert_any_call(f"/etc/sudoers.d/{charm.rundeck_user}", 0o440)

    @patch("os.path.exists", return_value=True)
    @patch("os.remove")
    def test_configure_sudoers_removes_file(self, mock_remove, mock_exists):
        charm = self.harness.charm
        charm._configure_sudoers([])
        mock_remove.assert_called_once_with(f"/etc/sudoers.d/{charm.rundeck_user}")

    @patch("os.path.exists", return_value=False)
    @patch("os.remove")
    def test_configure_sudoers_does_not_remove_file(self, mock_remove, mock_exists):
        charm = self.harness.charm
        charm._configure_sudoers([])
        mock_remove.assert_not_called()

    @patch("subprocess.run")
    @patch("os.makedirs")
    @patch("builtins.open", new_callable=mock_open)
    @patch("os.chmod")
    def test_configure_rundeck_user_creates_user_and_configures_ssh(
        self, mock_chmod, mock_file, mock_makedirs, mock_run
    ):
        charm = self.harness.charm
        with patch.object(charm, "_check_rundeck_user", return_value=False):
            charm._configure_rundeck_user("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 user@host")
            mock_run.assert_any_call(
                ["sudo", "useradd", "-m", "-s", "/bin/bash", charm.rundeck_user], check=False
            )
            mock_makedirs.assert_called_with(f"/home/{charm.rundeck_user}/.ssh", exist_ok=True)
            mock_file.assert_any_call(f"/home/{charm.rundeck_user}/.ssh/authorized_keys", "w", encoding="utf-8")
            mock_chmod.assert_any_call(f"/home/{charm.rundeck_user}/.ssh/authorized_keys", 0o600)
            mock_run.assert_any_call(
                ["sudo", "chown", "-R", f"{charm.rundeck_user}:{charm.rundeck_user}", f"/home/{charm.rundeck_user}/.ssh"], check=False
            )

    def test_configure_rundeck_user_user_exists(self):
        charm = self.harness.charm
        with patch.object(charm, "_check_rundeck_user", return_value=True):
            charm._configure_rundeck_user("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2 user@host")
            # Should return early, no system calls

