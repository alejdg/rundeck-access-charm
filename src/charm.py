#!/usr/bin/env python3
# Copyright 2025 Alexandre
# See LICENSE file for licensing details.

"""Charm the application."""

import logging
import os
import re

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
        sudoer = self.config.get("sudoer")

        if not ssh_key or not self._validate_ssh_key(ssh_key):
            logger.error("Invalid or missing SSH key")
            self.unit.status = BlockedStatus("Invalid or missing SSH key")
            return

        try:
            self._configure_rundeck_user(ssh_key, sudoer)
            self.unit.status = ActiveStatus("Configuration applied successfully")
            logger.info("Configuration applied successfully")
        except Exception as e:
            logger.exception("Failed to configure user")
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

    def _configure_rundeck_user(self, ssh_key, sudoer):
        """Configure the rundeck user, its SSH key, and sudo access."""
        logger.info("Configuring rundeck user")
        # Ensure the user exists
        os.system("sudo useradd -m -s /bin/bash rundeck || true")
        logger.debug("rundeck user ensured")

        # Configure SSH key
        ssh_dir = "/home/rundeck/.ssh"
        auth_keys_file = os.path.join(ssh_dir, "authorized_keys")
        os.makedirs(ssh_dir, exist_ok=True)
        logger.debug(f"Created SSH directory: {ssh_dir}")
        with open(auth_keys_file, "w") as f:
            f.write(f"{ssh_key}\n")
        os.chmod(auth_keys_file, 0o600)
        os.system(f"sudo chown -R rundeck:rundeck {ssh_dir}")
        logger.info("SSH key configured for rundeck user")

        # Configure sudoers file
        temp_file = "/tmp/sudoers-rundeck"
        sudoers_file = "/etc/sudoers.d/rundeck"
        if sudoer:
            if not self._verify_sudoers(sudoer):
                self.unit.status = BlockedStatus("Sudoers file syntax error")
                return
            logger.debug("Configuring sudoers file")
            with open(sudoers_file, "w") as f:
                f.write(f"rundeck {sudoer}\n")
            logger.info("Sudoers file configured")
        elif os.path.exists(sudoers_file):
            logger.debug("Removing sudoers file")
            os.remove(sudoers_file)
            logger.info("Sudoers file removed")

    def _verify_sudoers(self, sudoer) -> bool:
        """Verify the sudoers file syntax."""
        temp_file = "/tmp/sudoers-rundeck"
        logger.debug("Verifying sudoers file syntax")
        with open(temp_file, "w") as f:
            f.write(f"rundeck {sudoer}\n")
        result = os.system(f"visudo --check -f {temp_file}")
        os.remove(temp_file)
        logger.debug("Sudoers file syntax verification completed")
        if result != 0:
            logger.error("Sudoers file syntax error")
            return False
        logger.debug("Sudoers file syntax is valid")
        return True

if __name__ == "__main__":  # pragma: nocover
    main(RundeckAccessCharm)
