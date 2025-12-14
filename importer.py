#!/usr/bin/env python

import requests
from typing import Dict, List, Optional
from datetime import datetime


def select_cpe_name(cve) -> Optional[str]:
    if "configurations" not in cve:
        return None

    for configuration in cve["configurations"]:
        if "nodes" not in configuration:
            continue
        node = configuration["nodes"][0]
        if "cpeMatch" not in node:
            continue
        for cpe in node["cpeMatch"]:
            if not cpe["vulnerable"]:
                continue
            criteria = cpe["criteria"].split(":")
            pkgname = criteria[4]
            return pkgname
    return None


def select_description(cve) -> str:
    for current_description in cve["descriptions"]:
        if current_description["lang"] == "en":
            description = current_description["value"].strip()
            return description
    return ""

def select_references(cve) -> List[str]:
    references = []
    for reference in cve["references"]:
        references.append(reference["url"])
    return references


if __name__ == "__main__":
    url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    start_index: int = 241712

    params: Dict[str, str] = {}

    while True:
        params["startIndex"] = start_index
        # params["cveId"] = "CVE-2022-3256"

        print(f"query {start_index}")
        resp = requests.get(url, params=params)
        resp.raise_for_status()

        result = resp.json()

        results_per_page = result["resultsPerPage"]
        start_index = result["startIndex"]
        total_results = result["totalResults"]

        for vulnerability in result["vulnerabilities"]:
            if "cve" not in vulnerability:
                continue

            cve = vulnerability["cve"]
            id = cve["id"]

            published = datetime.strptime(cve["published"], "%Y-%m-%dT%H:%M:%S.%f")
            last_modified = datetime.strptime(cve["lastModified"], "%Y-%m-%dT%H:%M:%S.%f")

            description = select_description(cve)
            pkgname = select_cpe_name(cve)
            references = select_references(cve)

            print(id, description, pkgname)

        if start_index + results_per_page >= total_results:
            break
        start_index += results_per_page
