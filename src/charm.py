#!/usr/bin/env python3
# Copyright 2025 Alexandre
# See LICENSE file for licensing details.

"""Charm the application."""

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

    def _on_start(self, event: StartEvent):
        """Handle start event."""
        self.unit.status = ActiveStatus()

    def _on_config_changed(self, event: ConfigChangedEvent):
        logger.info("Configuration change detected")
        ssh_key = self.config.get("ssh-key")
        allowed_commands = self.config.get("allowed-commands", [])

        if not ssh_key or not self._validate_ssh_key(ssh_key):
            logger.error("Invalid or missing SSH key")
            self.unit.status = BlockedStatus("Invalid or missing SSH key")
            return

        try:
            self._configure_rundeck_user(ssh_key, allowed_commands)
            self.unit.status = ActiveStatus("Configuration applied successfully")
            logger.info("Configuration applied successfully")
        except Exception as e:
            logger.error("Failed to configure user during configuration step")
            self.unit.status = BlockedStatus(f"Failed to configure: {e}")

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

    def _configure_rundeck_user(self, ssh_key, allowed_commands):
        """Configure the rundeck user, its SSH key, and sudo access.

        Args:
            ssh_key (str): The SSH public key to be added to the rundeck user's authorized_keys
                           file.
            allowed_commands (list): A list of strings representing commands that the rundeck user
                                     is allowed to execute via sudo.
                                     Each command should be a valid shell command without special
                                     characters or unsafe patterns.
        """
        logger.info("Configuring rundeck user")
        # Ensure the user exists
        subprocess.run(["sudo", "useradd", "-m", "-s", "/bin/bash", "rundeck"], check=False)
        logger.debug("rundeck user ensured")

        # Configure SSH key
        ssh_dir = "/home/rundeck/.ssh"
        auth_keys_file = os.path.join(ssh_dir, "authorized_keys")
        os.makedirs(ssh_dir, exist_ok=True)
        logger.debug(f"Created SSH directory: {ssh_dir}")
        with open(auth_keys_file, "w", encoding="utf-8") as f:
            f.write(f"{ssh_key}\n")
        os.chmod(auth_keys_file, 0o600)
        subprocess.run(["sudo", "chown", "-R", "rundeck:rundeck", ssh_dir], check=False)
        logger.info("SSH key configured for rundeck user")

        # Configure sudoers file
        sudoers_file = "/etc/sudoers.d/rundeck"
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
        sanitized_commands = [re.escape(command) for command in commands]
        sanitized_commands = ", \\\n".join(sanitized_commands)
        return sanitized_commands

    def _prepare_sudoers_contents(self, commands: str) -> str:
        """Prepare the sudoers file contents."""
        return (
            f"Cmnd_Alias RUNDECK_CMDS = \\\n{commands}\nrundeck ALL=(ALL) NOPASSWD: RUNDECK_CMDS\n"
        )


if __name__ == "__main__":  # pragma: nocover
    main(RundeckAccessCharm)
