import os
import time

import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDClient:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self._last = 0.0
        # NVD rate limits: 5 req / 30s without key; 50 / 30s with key
        self._min_gap = 0.7 if self.api_key else 6.5

    def _throttle(self):
        gap = time.time() - self._last
        if gap < self._min_gap:
            time.sleep(self._min_gap - gap)
        self._last = time.time()

    def search_by_cpe(self, cpe: str):
        self._throttle()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        params = {"cpeName": cpe, "resultsPerPage": 200}
        r = requests.get(NVD_API, params=params, headers=headers, timeout=45)
        if r.status_code == 403:
            raise RuntimeError(
                "NVD API rate limit hit. Set the NVD_API_KEY environment "
                "variable to raise the limit (free key at nvd.nist.gov)."
            )
        r.raise_for_status()
        return r.json().get("vulnerabilities", [])

    # ---------- high-level ----------

    def search_many(self, cpes):
        merged = {}
        for cpe in sorted(set(cpes)):
            try:
                items = self.search_by_cpe(cpe)
            except Exception:                        # noqa: BLE001
                continue
            for item in items:
                cve = item.get("cve") or {}
                cid = cve.get("id")
                if not cid:
                    continue
                if cid not in merged:
                    merged[cid] = {**cve, "_matched_cpes": []}
                merged[cid]["_matched_cpes"].append(cpe)
        return list(merged.values())
