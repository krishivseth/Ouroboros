"""Docker container lifecycle management for sandbox auditing."""
from __future__ import annotations

import io
import logging
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import docker
from docker.models.containers import Container

logger = logging.getLogger(__name__)


@dataclass
class ContainerConfig:
    """Configuration for sandbox container."""
    image: str = "python:3.12-slim"
    workdir: str = "/workspace"
    network_mode: str = "bridge"
    memory_limit: str = "512m"
    cpu_limit: float = 1.0
    timeout_seconds: int = 300
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class ExecResult:
    """Result of executing a command in the container."""
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    @property
    def output(self) -> str:
        return self.stdout + self.stderr


class ContainerManager:
    """Manages Docker container lifecycle for sandbox auditing.

    Creates isolated containers, copies code into them, executes commands,
    and cleans up after auditing is complete.
    """

    def __init__(self, config: ContainerConfig | None = None):
        self.config = config or ContainerConfig()
        self._client: docker.DockerClient | None = None
        self._container: Container | None = None
        self._container_id: str | None = None
        self._start_time: float | None = None

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    @property
    def container(self) -> Container | None:
        return self._container

    @property
    def container_id(self) -> str | None:
        return self._container_id

    @property
    def is_running(self) -> bool:
        if self._container is None:
            return False
        self._container.reload()
        return self._container.status == "running"

    def create(self, repo_path: str | Path) -> str:
        """Create a container with the repository copied into it.

        Args:
            repo_path: Path to the repository to audit.

        Returns:
            Container ID.
        """
        repo_path = Path(repo_path).resolve()
        if not repo_path.exists():
            raise FileNotFoundError(f"Repository path not found: {repo_path}")

        logger.info("Creating container with image %s", self.config.image)

        try:
            self.client.images.get(self.config.image)
        except docker.errors.ImageNotFound:
            logger.info("Pulling image %s...", self.config.image)
            self.client.images.pull(self.config.image)

        self._container = self.client.containers.create(
            image=self.config.image,
            command="sleep infinity",
            working_dir=self.config.workdir,
            network_mode=self.config.network_mode,
            mem_limit=self.config.memory_limit,
            nano_cpus=int(self.config.cpu_limit * 1e9),
            environment=self.config.env,
            detach=True,
            tty=True,
        )
        self._container_id = self._container.id
        logger.info("Created container %s", self._container_id[:12])

        self._copy_to_container(repo_path, self.config.workdir)

        return self._container_id

    def start(self) -> None:
        """Start the container."""
        if self._container is None:
            raise RuntimeError("Container not created. Call create() first.")

        logger.info("Starting container %s", self._container_id[:12])
        self._container.start()
        self._start_time = time.time()

        for _ in range(30):
            self._container.reload()
            if self._container.status == "running":
                logger.info("Container started successfully")
                return
            time.sleep(0.1)

        raise RuntimeError(f"Container failed to start: {self._container.status}")

    def exec(
        self,
        command: str,
        timeout: int = 30,
        workdir: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ExecResult:
        """Execute a command inside the container.

        Args:
            command: Shell command to execute.
            timeout: Maximum execution time in seconds.
            workdir: Working directory for the command.
            env: Additional environment variables.

        Returns:
            ExecResult with exit code, stdout, stderr, and duration.
        """
        if self._container is None or not self.is_running:
            raise RuntimeError("Container not running")

        start = time.perf_counter()

        exec_env = {**self.config.env, **(env or {})}
        exec_workdir = workdir or self.config.workdir

        logger.debug("Executing: %s", command[:100])

        try:
            exit_code, output = self._container.exec_run(
                cmd=["sh", "-c", command],
                workdir=exec_workdir,
                environment=exec_env,
                demux=True,
            )
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            return ExecResult(
                exit_code=-1,
                stdout="",
                stderr=f"Execution failed: {e}",
                duration_ms=duration,
            )

        duration = (time.perf_counter() - start) * 1000

        stdout = output[0].decode("utf-8", errors="replace") if output[0] else ""
        stderr = output[1].decode("utf-8", errors="replace") if output[1] else ""

        return ExecResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration,
        )

    def read_file(self, path: str) -> str:
        """Read a file from the container filesystem.

        Args:
            path: Absolute path to the file in the container.

        Returns:
            File contents as string.
        """
        if self._container is None:
            raise RuntimeError("Container not created")

        try:
            bits, _ = self._container.get_archive(path)
            tar_stream = io.BytesIO()
            for chunk in bits:
                tar_stream.write(chunk)
            tar_stream.seek(0)

            with tarfile.open(fileobj=tar_stream, mode="r") as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        f = tar.extractfile(member)
                        if f:
                            return f.read().decode("utf-8", errors="replace")

            return ""
        except docker.errors.NotFound:
            raise FileNotFoundError(f"File not found in container: {path}")
        except Exception as e:
            raise RuntimeError(f"Failed to read file {path}: {e}")

    def list_dir(self, path: str) -> list[str]:
        """List directory contents in the container.

        Args:
            path: Absolute path to the directory.

        Returns:
            List of filenames in the directory.
        """
        result = self.exec(f"ls -1 {path}")
        if not result.success:
            raise FileNotFoundError(f"Directory not found: {path}")
        return [f for f in result.stdout.strip().split("\n") if f]

    def get_logs(self, tail: int = 1000) -> str:
        """Get container stdout/stderr logs.

        Args:
            tail: Number of lines to return from the end.

        Returns:
            Container logs as string.
        """
        if self._container is None:
            return ""

        logs = self._container.logs(tail=tail)
        if isinstance(logs, bytes):
            return logs.decode("utf-8", errors="replace")
        return str(logs)

    def stop(self) -> None:
        """Stop and remove the container."""
        if self._container is None:
            return

        container_id = self._container_id[:12] if self._container_id else "unknown"

        try:
            self._container.reload()
            if self._container.status == "running":
                logger.info("Stopping container %s", container_id)
                self._container.stop(timeout=10)
        except Exception as e:
            logger.warning("Error stopping container: %s", e)

        try:
            logger.info("Removing container %s", container_id)
            self._container.remove(force=True)
        except Exception as e:
            logger.warning("Error removing container: %s", e)

        self._container = None
        self._container_id = None

    def _copy_to_container(self, local_path: Path, container_path: str) -> None:
        """Copy a directory into the container.

        Args:
            local_path: Local path to copy from.
            container_path: Container path to copy to.
        """
        if self._container is None:
            raise RuntimeError("Container not created")

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            for file_path in local_path.rglob("*"):
                if file_path.is_file():
                    rel_path = file_path.relative_to(local_path)
                    if self._should_copy_file(rel_path):
                        tar.add(file_path, arcname=str(rel_path))

        tar_stream.seek(0)
        self._container.put_archive(container_path, tar_stream)
        logger.debug("Copied %s to container:%s", local_path, container_path)

    def _should_copy_file(self, rel_path: Path) -> bool:
        """Check if a file should be copied to the container."""
        skip_patterns = [
            ".git",
            "__pycache__",
            "node_modules",
            ".venv",
            "venv",
            ".env",
            "*.pyc",
            "*.pyo",
            ".DS_Store",
        ]
        path_str = str(rel_path)
        for pattern in skip_patterns:
            if pattern in path_str:
                return False
        return True

    def __enter__(self) -> "ContainerManager":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
