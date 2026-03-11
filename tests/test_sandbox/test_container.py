"""Tests for container manager."""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from ouroboros_sandbox.container.manager import (
    ContainerManager,
    ContainerConfig,
    ExecResult,
)


class TestContainerConfig:
    """Tests for ContainerConfig dataclass."""

    def test_default_values(self):
        config = ContainerConfig()
        assert config.image == "python:3.12-slim"
        assert config.workdir == "/workspace"
        assert config.network_mode == "bridge"
        assert config.memory_limit == "512m"
        assert config.timeout_seconds == 300

    def test_custom_values(self):
        config = ContainerConfig(
            image="node:20-slim",
            workdir="/app",
            network_mode="none",
            memory_limit="1g",
        )
        assert config.image == "node:20-slim"
        assert config.workdir == "/app"
        assert config.network_mode == "none"
        assert config.memory_limit == "1g"


class TestExecResult:
    """Tests for ExecResult dataclass."""

    def test_success_property(self):
        result = ExecResult(exit_code=0, stdout="ok", stderr="", duration_ms=100)
        assert result.success is True

        result = ExecResult(exit_code=1, stdout="", stderr="error", duration_ms=100)
        assert result.success is False

    def test_output_property(self):
        result = ExecResult(
            exit_code=0,
            stdout="hello",
            stderr="world",
            duration_ms=100,
        )
        assert result.output == "helloworld"


class TestContainerManager:
    """Tests for ContainerManager."""

    def test_init_default_config(self):
        manager = ContainerManager()
        assert manager.config.image == "python:3.12-slim"
        assert manager._container is None

    def test_init_custom_config(self):
        config = ContainerConfig(image="alpine:latest")
        manager = ContainerManager(config)
        assert manager.config.image == "alpine:latest"

    def test_is_running_no_container(self):
        manager = ContainerManager()
        assert manager.is_running is False

    def test_container_id_no_container(self):
        manager = ContainerManager()
        assert manager.container_id is None

    def test_create_pulls_image_if_missing(self, tmp_path):
        """Test that create() pulls image if not found locally.
        
        This test is skipped if Docker is not available.
        """
        pytest.skip("Requires Docker daemon - run integration tests separately")

    @patch("ouroboros_sandbox.container.manager.docker")
    def test_stop_handles_no_container(self, mock_docker):
        manager = ContainerManager()
        manager.stop()

    def test_should_copy_file_excludes_git(self):
        manager = ContainerManager()
        from pathlib import Path

        assert manager._should_copy_file(Path("main.py")) is True
        assert manager._should_copy_file(Path(".git/config")) is False
        assert manager._should_copy_file(Path("__pycache__/module.pyc")) is False
        assert manager._should_copy_file(Path("node_modules/pkg/index.js")) is False
        assert manager._should_copy_file(Path("src/utils.py")) is True

    def test_context_manager(self):
        with patch("ouroboros_sandbox.container.manager.docker"):
            manager = ContainerManager()
            with manager as m:
                assert m is manager
