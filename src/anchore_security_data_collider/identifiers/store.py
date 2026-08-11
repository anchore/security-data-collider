import logging
import os
import shutil
import tarfile
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING

from oras.client import OrasClient

from anchore_security_data_collider.identifiers.anchore_id import AnchoreId, parse
from anchore_security_data_collider.sqlite import connect
from anchore_security_data_collider.utils import timer

if TYPE_CHECKING:
    from sqlite3 import Connection

    from anchore_security_data_collider.deployment import DeploymentEnvironment


@dataclass
class Extract:
    path: str # Relative to the archive download directory
    dest: str | None = None # Relative to the data store path, if not supplied the full extract path will be copied to the data store

@dataclass
class SecurityIdentifiersStoreConfig:
    pull_format_string: str
    extracts: list[Extract] | None = None

    def pull_string(self, env: DeploymentEnvironment) -> str:
        return self.pull_format_string.format(environment=env.value)

class _StoreThreadLocal(threading.local):
    """
    thread-local storage for per-thread Sqlite3 connections.  Allowing cross-thread access to connections even for
    read-only dbs seemed particularly unstable.
    """

    conn: Connection | None = None

class SecurityIdentifiersStore:
    def __init__(self, root: str, config: SecurityIdentifiersStoreConfig):
        self._name = "security-identifiers"
        self._root = root
        self._config = config
        self._logger = logging.getLogger(self._name)
        self._store_path = os.path.join(self._root, "inputs", self._name, f"{self._name}.db")
        self._thread_local_store = _StoreThreadLocal()

    @property
    def name(self) -> str:
        return self._name

    def _store(self) -> Connection:
        if self._thread_local_store.conn is None:
            self._thread_local_store.conn = connect(self._store_path, readonly=True)

        return self._thread_local_store.conn

    def ready(self) -> bool:
        return os.path.exists(self._store_path)

    def fetch(self, environment: DeploymentEnvironment):
        self._logger.debug(f"{self._name}: Start fetch")
        pull_string = self._config.pull_string(environment)
        download_path = os.path.join(self._root, "downloads", self._name)
        extracted_paths = []
        with timer(f"{self._name}: Fetching from {pull_string}", logger=self._logger):
            with timer(f"{self._name}: Downloading from {pull_string} to {download_path}", logger=self._logger):
                if os.path.exists(download_path):
                    shutil.rmtree(download_path)

                os.makedirs(download_path)

                client = OrasClient()
                extracted_paths = client.pull(target=pull_string, outdir=download_path)

            dest = os.path.join(self._root, "inputs", self._name)
            with timer(f"{self._name}: Extracting content to {dest}", logger=self._logger):
                if os.path.exists(dest):
                    shutil.rmtree(dest)

                os.makedirs(dest)

                for p in extracted_paths:
                    with tarfile.open(p, "r:*") as stream:
                        if self._config.extracts:
                            for extract in self._config.extracts:
                                if extract.dest:
                                    f = stream.extractfile(member=extract.path)
                                    with open (os.path.join(dest, extract.dest), "wb") as out:
                                        out.write(f.read())  # ty:ignore[unresolved-attribute]
                                else:
                                    stream.extract(extract.path, dest, filter="data")
                        else:
                            stream.extractall(dest, filter="data")

            with timer(f"{self._name}: Cleaning up {download_path}", logger=self._logger):
                shutil.rmtree(download_path)
        self._logger.debug(f"{self._name}: Finish fetch")

    def _lookup(self, record_id: str) -> AnchoreId | None:
        cursor = self._store().execute("""
                SELECT anchore_id FROM security_aliases where alias_id = ?
            """,
            (record_id,),
        )
        r = cursor.fetchall()
        if not r:
            return None

        if len(r) > 1:
            raise ValueError(f"{record_id} is associated with multiple ANCHORE identifiers, please reconcile before continuing")

        return parse(r[0]["anchore_id"])

    def lookup(self, record_id: str) -> AnchoreId | None:
        self._logger.trace(f"{self._name}: Start lookup for {record_id}")  # ty:ignore[unresolved-attribute]
        try:
            lookup = self._lookup(record_id)
        except Exception:
            self._logger.error(f"{self._name}: Error during lookup for record {record_id}")
            raise
        self._logger.trace(f"{self._name}: Finish lookup for {record_id}")  # ty:ignore[unresolved-attribute]
        return lookup
