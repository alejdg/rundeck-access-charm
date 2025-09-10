#!/usr/bin/env python3
# Copyright 2025 Alexandre
# See LICENSE file for licensing details.

"""Charm the application."""

import json
import logging
import os
import re
import subprocess

from ops.charm import CharmBase, ConfigChangedEvent, StartEvent
from ops.framework import Framework
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

logger = logging.getLogger(__name__)


class RundeckAccessCharm(CharmBase):
    """Charm the application."""

    def __init__(self, framework: Framework):
        super().__init__(framework)
        framework.observe(self.on.start, self._on_start)
        framework.observe(self.on.config_changed, self._on_config_changed)
        framework.observe(self.on.stop, self._on_stop)

    def _on_start(self, event: StartEvent):
        """Handle start event."""
        self.unit.status = ActiveStatus()

    def _on_config_changed(self, event: ConfigChangedEvent):
        logger.info("Configuration change detected")
        ssh_key = self.config.get("ssh-key")
        allowed_commands = self.config.get("allowed-commands") or "[]"
        try:
            allowed_commands = json.loads(allowed_commands)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse allowed commands config: {allowed_commands} - Error: {e}")
            self.unit.status = BlockedStatus("Invalid allowed commands format")
            return

        if not ssh_key or not self._validate_ssh_key(ssh_key):
            logger.error("Invalid or missing SSH key")
            self.unit.status = BlockedStatus("Invalid or missing SSH key")
            return

        try:
            self._configure_rundeck_user()
        except Exception as e:
            logger.error(f"Failed to configure user. Details: {e}")
            self.unit.status = BlockedStatus(f"Failed to configure user")

        try:
            self._configure_ssh_key(ssh_key)
        except Exception as e:
            logger.error(f"Failed to configure ssh key. Details: {e}")
            self.unit.status = BlockedStatus(f"Failed to configure ssh key")

        try:
            self._configure_sudoers(allowed_commands)
        except Exception as e:
            logger.error(f"Failed to configure sudoers file. Details: {e}")
            self.unit.status = BlockedStatus(f"Failed to configure sudoers file")

        # If nothing fails, set the unit status to Active
        self.unit.status = ActiveStatus("Configuration applied successfully")
        logger.info("Configuration applied successfully")

    def _on_stop(self, event):
        """Handle stop event."""
        logger.info("Charm is stopping. Cleaning up.")
        # Make sure the user is removed
        if self._check_rundeck_user():
            subprocess.run(["sudo", "userdel", "-r", self.rundeck_user], check=False)
            logger.info(f"Removed user {self.rundeck_user}")
        # Remove sudoers file if exists
        sudoers_file = f"/etc/sudoers.d/{self.rundeck_user}"
        if os.path.exists(sudoers_file):
            os.remove(sudoers_file)
            logger.info(f"Removed sudoers file {sudoers_file}")
        self.unit.status = ActiveStatus("Charm stopped")

    @property
    def rundeck_user(self):
        return f"rundeck-{self.app.name}"

    def _validate_ssh_key(self, key: str) -> bool:
        """Validate the SSH key format."""
        logger.debug("Validating SSH key format")
        key_pattern = re.compile(r"^(ssh-(rsa|dss|ecdsa|ed25519) [A-Za-z0-9+/=]+( [^\n\r]+)?)$")
        valid = bool(key_pattern.match(key))
        if valid:
            logger.debug("SSH key format is valid")
        else:
            logger.error("SSH key format is invalid")
        return valid

    def _configure_rundeck_user(self):
        """Configure the rundeck user, its SSH key, and sudo access."""
        if self._check_rundeck_user():
            logger.debug("Rundeck user already exists")
            return

        logger.info("Configuring rundeck user")
        # Ensure the user exists
        subprocess.run(["sudo", "useradd", "-m", "-s", "/bin/bash", self.rundeck_user], check=False)
        logger.debug(f"{self.rundeck_user} user ensured")


    def _configure_ssh_key(self, ssh_key: str):
        """Configure the SSH key for the rundeck user.
        Args:
            ssh_key (str): The SSH public key to be added to the rundeck user's authorized_keys
                           file.
        """
        logger.info("Configuring SSH key for rundeck user")
        # Configure SSH key
        ssh_dir = f"/home/{self.rundeck_user}/.ssh"
        auth_keys_file = os.path.join(ssh_dir, "authorized_keys")
        os.makedirs(ssh_dir, exist_ok=True)
        logger.debug(f"Created SSH directory: {ssh_dir}")
        with open(auth_keys_file, "w", encoding="utf-8") as f:
            f.write(f"{ssh_key}\n")
        os.chmod(auth_keys_file, 0o600)
        subprocess.run(["sudo", "chown", "-R", f"{self.rundeck_user}:{self.rundeck_user}", ssh_dir], check=False)
        logger.info(f"SSH key configured for {self.rundeck_user} user")


    def _configure_sudoers(self, allowed_commands: list):
        """Configure the sudoers file for the rundeck user.
        Args:
            allowed_commands (list): List of commands to be allowed for the rundeck user.
        """
        sudoers_file = f"/etc/sudoers.d/{self.rundeck_user}"
        if allowed_commands:
            sudoers = self._prepare_sudoers_contents(self._sanitize_commands(allowed_commands))
            if not self._verify_sudoers(sudoers):
                raise ValueError("Sudoers config syntax error")
            logger.debug("Configuring sudoers file")
            with open(sudoers_file, "w") as f:
                f.write(sudoers)
            os.chmod(sudoers_file, 0o440)
            logger.info("Sudoers file configured")
        elif os.path.exists(sudoers_file):
            logger.debug("Removing sudoers file")
            os.remove(sudoers_file)
            logger.info("Sudoers file removed")

    def _check_rundeck_user(self) -> bool:
        """Check if the rundeck user exists."""
        try:
            subprocess.run(["id", self.rundeck_user], check=True, capture_output=True)
            logger.debug(f"User {self.rundeck_user} exists")
            return True
        except subprocess.CalledProcessError:
            logger.debug(f"User {self.rundeck_user} does not exist")
            return False

    def _verify_sudoers(self, sudoers) -> bool:
        """Verify the sudoers file syntax."""
        logger.debug("Verifying sudoers file syntax")
        try:
            subprocess.run(
                ["visudo", "--check"],
                input=sudoers,
                text=True,
                capture_output=True,
                check=True,
            )
            logger.debug("Sudoers file syntax is valid")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Sudoers file syntax error: {e.stderr}")
            return False

    def _sanitize_commands(self, commands: list) -> str:
        """Sanitize commands before adding to sudoers."""
        logger.debug("Sanitizing commands for sudoers")
        sanitized_commands = ", \\\n".join(commands)
        return sanitized_commands

    def _prepare_sudoers_contents(self, commands: str) -> str:
        """Prepare the sudoers file contents."""
        alias_name = f"RUNDECK_CMDS_{self.app.name.upper().replace('-', '_')}"
        return (
            f"Cmnd_Alias {alias_name} = \\\n{commands}\n"
            f"{self.rundeck_user} ALL=(ALL) NOPASSWD: {alias_name}\n"
        )


if __name__ == "__main__":  # pragma: nocover
    main(RundeckAccessCharm)
