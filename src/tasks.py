# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
from collections import defaultdict
from dataclasses import dataclass

import yara
from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.reporting import MarkdownTable, Priority, Report
from openrelik_worker_common.task_utils import create_task_result, get_input_files

from .app import celery
from .providers import yeti

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TASK_NAME = "openrelik-worker-yara-scan.tasks.yara-scan"

TASK_METADATA = {
    "display_name": "Yara scan",
    "description": "Scans a folder with Yara rules obtained from Yeti",
    "task_config": [
        {
            "name": "Manual Yara rules",
            "label": 'rule test { strings: $ = "test" condition: true }',
            "description": "Run these extra Yara rules using the YaraScan plugin.",
            "type": "textarea",
            "required": False,
        },
    ],
}

AVAILABLE_PROVIDERS = {}
if os.environ.get("YETI_PROVIDER"):
    AVAILABLE_PROVIDERS["yeti"] = yeti.YetiIntelProvider

# Only add the Yara sources field if there are available providers
if AVAILABLE_PROVIDERS:
    TASK_METADATA["task_config"].extend(
        [
            {
                "name": "Yara sources",
                "label": "Select systems to fetch Yara from",
                "description": f"Available systems: {', '.join(AVAILABLE_PROVIDERS.keys())}",
                "type": "text",
                "required": False,
            },
            {
                "name": "Yara rule name filter",
                "label": "Filter rules by name",
                "description": "Filter to apply on rules to obtain from the TIP",
                "type": "text",
                "required": False,
            },
        ]
    )


@dataclass
class YaraMatch:
    """Dataclass to store Yara match information."""

    rule: str
    strings: list
    meta: str
    filepath: str


def generate_report_from_matches(matches: list[YaraMatch]) -> Report:
    """Generate a report from Yara matches.

    Args:
        matches: List of YaraMatch objects.

    Returns:
        Report object.
    """
    report = Report("Yara scan report")
    matches_section = report.add_section()
    matches_section.add_paragraph(
        "List of Yara matches found in the scanned files. Check out all.yar for source rules."
    )
    if matches:
        report.priority = Priority.CRITICAL
    match_table = MarkdownTable(["filepath", "rule", "meta", "strings"])
    for match in matches:
        match_table.add_row([match.filepath, match.rule, match.meta, match.strings])

    matches_section.add_table(match_table)

    return report


@celery.task(bind=True, name=TASK_NAME, metadata=TASK_METADATA)
def command(
    self,
    pipe_result: str = None,
    input_files: list = None,
    output_path: str = None,
    workflow_id: str = None,
    task_config: dict = None,
) -> str:
    """Fetch and run Yara rules on the input files.

    Args:
        pipe_result: Base64-encoded result from the previous Celery task, if any.
        input_files: List of input file dictionaries (unused if pipe_result exists).
        output_path: Path to the output directory.
        workflow_id: ID of the workflow.
        task_config: User configuration for the task.

    Returns:
        Base64-encoded dictionary containing task results.
    """
    output_files = []

    all_patterns = ""

    if AVAILABLE_PROVIDERS:
        providers = []
        for provider_key in task_config.get("Yara sources").split(","):
            provider_class = AVAILABLE_PROVIDERS.get(provider_key, None)
            providers.append(provider_class())

        for provider in providers:
            all_patterns += provider.get_yara_rules(
                name_filter=task_config.get("Yara rule name filter", "")
            )
            logger.info(f"Obtained {len(all_patterns)} bytes of Yara rules from {provider.NAME}")

    manual_yara = task_config.get("Manual Yara rules", "")
    if manual_yara:
        logger.info("Manual rules provided, added manual Yara rules")
        all_patterns += manual_yara

    if not all_patterns:
        raise ValueError(
            "No Yara rules were collected, select a system or provide a manual Yara rule"
        )

    output_file = create_output_file(output_path, display_name="all.yara")
    with open(output_file.path, "w") as fh:
        fh.write(all_patterns)

    output_files.append(output_file.to_dict())

    files_scanned = 0
    files_matched = 0
    progress = {
        "files_scanned": files_scanned,
        "files_matched": files_matched,
        "unique_rules_matched": 0,
    }
    rule_count_per_name = defaultdict(int)
    self.send_event("task-progress", data=progress)
    all_matches = []

    for input_file in get_input_files(pipe_result, input_files):
        internal_path = input_file.get("path")
        filepath = input_file.get("display_name")
        logging.info(f"Scanning file: ({filepath}) {internal_path}")
        externals = {
            "filepath": filepath,
            "filename": os.path.basename(filepath),
            "extension": input_file.get("extension"),
            "filetype": input_file.get("data_type"),
            "owner": "",
        }
        compiled_rules = yara.compile(output_file.path, externals=externals)
        matches = compiled_rules.match(internal_path)
        files_scanned += 1
        if matches:
            files_matched += 1

        for match in matches:
            rule_count_per_name[match.rule] += 1
            all_matches.append(
                YaraMatch(
                    rule=match.rule,
                    strings=str(match.strings),
                    meta=str(match.meta),
                    filepath=filepath,
                )
            )

        progress["files_scanned"] = files_scanned
        progress["files_matched"] = files_matched
        progress["unique_rules_matched"] = len(rule_count_per_name)
        self.send_event("task-progress", data=progress)

    report = generate_report_from_matches(all_matches)
    report_file = create_output_file(output_path, display_name="report.md")
    with open(report_file.path, "w") as fh:
        fh.write(report.to_markdown())

    progress["matching_rule_names"] = rule_count_per_name

    output_files.append(report_file.to_dict())

    return create_task_result(
        output_files=output_files,
        workflow_id=workflow_id,
        command="yeti api query",
        meta=progress,
    )
