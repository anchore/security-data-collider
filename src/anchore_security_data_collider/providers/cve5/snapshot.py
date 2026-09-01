import json
import logging
import os
import shlex
import shutil
import tempfile
from glob import iglob

import requests

from anchore_security_data_collider.providers.cve5.identifier import parse_identifier
from anchore_security_data_collider.utils import execute_command, timer


class CVE5Snapshotter:
    def __init__(self, repo_root: str):
        self._github_repo = "CVEProject/cvelistV5"
        self._default_branch = "main"
        self._repo_root = repo_root
        self._logger = logging.getLogger("cve5-snapshotter")

    def _process_files(self, tmp_path: str):
        base_path = os.path.join(self._repo_root, "data")
        for file in iglob(os.path.join(tmp_path, "**/CVE-*.json"), recursive=True):
            if not os.path.isfile(file):
                continue

            with open(file) as f:
                data = json.load(f)

            identifier = parse_identifier(data.get("cveMetadata", {}).get("cveId"))
            if not identifier:
                raise ValueError(f"Unable to parse CVE identifier from {file}")

            output_path = identifier.filename(base_path)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)

    def _get_latest_commit(self) -> str:
        r = requests.get(
            f"https://api.github.com/repos/{self._github_repo}/commits/{self._default_branch}",
            timeout=10,
        )

        r.raise_for_status()

        return r.json()["sha"]

    def process(self, commit: str | None = None):
        if not commit:
            commit = self._get_latest_commit()

        url = f"https://github.com/{self._github_repo}/archive/{commit}.zip"
        with tempfile.TemporaryDirectory() as tmp:
            with timer(f"downloading from {url}"):
                cmd = f"curl -f -L -o content.zip -X GET {shlex.quote(url)}"
                execute_command(cmd, cwd=tmp)

            with timer(f"extracting archive content from {url}"):
                execute_command("unzip content.zip", cwd=tmp)

            repo_path = os.path.join(self._repo_root, "data")
            with timer(f"processing data from {url}"):
                if os.path.exists(repo_path):
                    shutil.rmtree(repo_path)
                tmp_path = os.path.join(tmp, f"cvelistV5-{commit}", "cves")
                self._process_files(tmp_path)

            with open(os.path.join(self._repo_root, "index.json"), "w") as f:
                json.dump({
                    "snapshots": [
                        {
                            "repo": "https://github.com/CVEProject/cvelistV5",
                            "commit": commit,
                        },
                    ],
                }, f, ensure_ascii=False, indent=2, sort_keys=True)

            self._logger.info("git add data")
            self._logger.info(f'git commit -s -m "snapshot from https://github.com/{self._github_repo}/commits/{commit}"')
            self._logger.info("git push origin main")
