#!/usr/bin/env python3
"""Temporary integration keys. Uses AWS CLI v2; no AWS SDK dependency.

Keep this file and its tests identical in the action and CLI repositories.
The CLI repository owns the lifecycle/IAM documentation.
"""
import argparse
from dataclasses import dataclass
from datetime import datetime
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

PROJECT = "openpgp-sign-kms"
PURPOSE = "integration-temporary"
MANAGER = "openpgp-sign-kms-ci"
TTL = 24 * 60 * 60
SPECS = {"RSA": "RSA_3072", "ED25519": "ECC_NIST_EDWARDS25519"}
TRANSIENT = {"NotFoundException", "AccessDeniedException", "KMSInvalidStateException",
             "DependencyTimeoutException", "KMSInternalException", "ThrottlingException"}


class AwsError(RuntimeError):
    def __init__(self, message):
        super().__init__(message)
        match = re.search(r"\((\w+)\)", message)
        self.code = match[1] if match else "Unknown"


class Aws:
    def __init__(self, region):
        self.region = region

    def call(self, service, operation, *args):
        # CreateKey has no idempotency token. Never automatically retry it: a
        # lost response is recovered by the tag-based sweeper instead.
        env = dict(os.environ, AWS_RETRY_MODE="standard",
                   AWS_MAX_ATTEMPTS="1" if operation == "create-key" else "3")
        result = subprocess.run(
            ["aws", service, operation, "--region", self.region, "--output", "json",
             "--no-cli-pager", "--cli-connect-timeout", "5", "--cli-read-timeout", "20", *args],
            env=env, capture_output=True, text=True, timeout=90,
        )
        if result.returncode:
            raise AwsError(result.stderr.strip())
        return json.loads(result.stdout)


@dataclass(frozen=True)
class Context:
    region: str
    account: str
    repository: str
    run: str
    attempt: str
    job: str

    def tags(self, now):
        return {"Project": PROJECT, "Purpose": PURPOSE, "ManagedBy": MANAGER,
                "Repository": self.repository, "RunId": self.run,
                "RunAttempt": self.attempt, "Job": self.job,
                "ExpiresAt": str(int(now) + TTL)}

    def validate_arn(self, arn):
        parts = arn.split(":")
        if (len(parts) != 6 or parts[0] != "arn" or parts[1] not in {"aws", "aws-cn", "aws-us-gov"}
                or parts[2:5] != ["kms", self.region, self.account]
                or not parts[5].startswith("key/")):
            raise ValueError("key ARN is outside the configured account/region")
        uuid.UUID(parts[5][4:])  # Only single-region key UUIDs, never aliases/MRKs.


def context(aws):
    repository = os.environ["GITHUB_REPOSITORY"]
    run, attempt = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
    job = os.environ.get("KMS_TEST_JOB", "orphan-cleanup")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid GITHUB_REPOSITORY")
    if not run.isdecimal() or not attempt.isdecimal() or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", job):
        raise ValueError("invalid workflow run or job identity")
    account = aws.call("sts", "get-caller-identity")["Account"]
    if not re.fullmatch(r"[0-9]{12}", account):
        raise ValueError("invalid AWS account")
    return Context(aws.region, account, repository, run, attempt, job)


def retry(operation, budget=360):
    deadline = time.monotonic() + budget
    while True:
        try:
            return operation()
        except AwsError as error:
            if error.code not in TRANSIENT or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def tag_map(aws, arn):
    # AWS CLI automatic pagination returns all tags and all keys in sweep().
    tags = aws.call("kms", "list-resource-tags", "--key-id", arn)["Tags"]
    return {tag["TagKey"]: tag["TagValue"] for tag in tags}


def managed(tags, ctx):
    return all(tags.get(k) == v for k, v in {
        "Project": PROJECT, "Purpose": PURPOSE, "ManagedBy": MANAGER,
        "Repository": ctx.repository,
    }.items())


def metadata(aws, arn, ctx):
    ctx.validate_arn(arn)
    key = aws.call("kms", "describe-key", "--key-id", arn)["KeyMetadata"]
    if (key.get("Arn") != arn or key.get("KeyManager") != "CUSTOMER"
            or key.get("KeyUsage") != "SIGN_VERIFY" or key.get("Origin") != "AWS_KMS"
            or key.get("MultiRegion") is not False or key.get("KeySpec") not in SPECS.values()):
        raise ValueError("refusing key with unexpected metadata: " + arn)
    return key


def schedule(aws, arn, key, dry_run=False):
    if key["KeyState"] == "PendingDeletion":
        print("Already pending deletion: " + arn)
        return
    if key["KeyState"] not in {"Enabled", "Disabled"}:
        raise ValueError("refusing unexpected key state: " + key["KeyState"])
    if dry_run:
        print("Would schedule deletion: " + arn)
        return
    response = aws.call("kms", "schedule-key-deletion", "--key-id", arn,
                        "--pending-window-in-days", "7")
    if response.get("KeyState") != "PendingDeletion" or response.get("KeyId") != arn:
        raise ValueError("unexpected ScheduleKeyDeletion response")
    print("Scheduled deletion (7 days): " + arn)


def create(aws, ctx, state, kinds, env_file, now=None):
    if len(set(kinds)) != len(kinds):
        raise ValueError("duplicate key type")
    tags = ctx.tags(time.time() if now is None else now)
    # Exclusive creation prevents accidentally mixing another attempt's journal.
    with state.open("x", encoding="utf-8") as journal:
        os.chmod(state, 0o600)
        for kind in kinds:
            result = aws.call("kms", "create-key", "--key-usage", "SIGN_VERIFY",
                              "--key-spec", SPECS[kind], "--origin", "AWS_KMS",
                              "--no-multi-region", "--no-bypass-policy-lockout-safety-check", "--description",
                              f"Temporary integration: {ctx.repository} run {ctx.run}/{ctx.attempt} {ctx.job}",
                              "--tags", json.dumps([{"TagKey": k, "TagValue": v} for k, v in tags.items()]))
            arn = result["KeyMetadata"]["Arn"]
            ctx.validate_arn(arn)
            journal.write(json.dumps({"arn": arn, "tags": tags}) + "\n")
            journal.flush()
            os.fsync(journal.fileno())  # Record each key before readiness/next creation.
            def ready():
                key = metadata(aws, arn, ctx)
                if key["KeyState"] != "Enabled":
                    raise AwsError("(KMSInvalidStateException) key is not enabled")
                if tag_map(aws, arn) != tags:
                    raise AwsError("(NotFoundException) creation tags not visible yet")
                aws.call("kms", "get-public-key", "--key-id", arn)
            retry(ready)
            with env_file.open("a", encoding="utf-8") as output:
                output.write(f"KMS_{kind}_KEY_ARN={arn}\n")
            print(f"Created {kind} key: {arn}")


def cleanup(aws, ctx, state):
    if not state.exists():
        print("No local key journal; orphan cleanup covers lost creation responses.")
        return
    failures = []
    for line in state.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
            arn, expected = record["arn"], record["tags"]
            if (not managed(expected, ctx) or any(expected.get(k) != v for k, v in {
                    "RunId": ctx.run, "RunAttempt": ctx.attempt, "Job": ctx.job}.items())):
                raise ValueError("journal belongs to a different workflow job")
            def remove():
                key = metadata(aws, arn, ctx)
                # Deletion may have succeeded before an earlier cleanup lost its response.
                if key["KeyState"] == "PendingDeletion":
                    schedule(aws, arn, key)
                    return
                if tag_map(aws, arn) != expected:
                    raise AwsError("(NotFoundException) journal tags do not match current key tags")
                schedule(aws, arn, key)
            retry(remove)
        except Exception as error:
            failures.append(str(error))
            print("Cleanup failed: " + str(error), file=sys.stderr)
    if failures:
        raise RuntimeError(f"cleanup failed for {len(failures)} record(s); daily recovery remains enabled")


def created_seconds(value):
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("key creation timestamp has no timezone")
        return parsed.timestamp()
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return value
    raise ValueError("invalid key creation timestamp")


def sweep(aws, ctx, dry_run=False, now=None):
    now = time.time() if now is None else now
    failures = []
    entries = aws.call("kms", "list-keys")["Keys"]
    owned = eligible = 0
    for entry in entries:
        arn = entry["KeyArn"]
        try:
            tags = tag_map(aws, arn)
            if not managed(tags, ctx):
                continue
            owned += 1
            if (not re.fullmatch(r"[0-9]{1,12}", tags.get("ExpiresAt", ""))
                    or not tags.get("RunId", "").isdecimal()
                    or not tags.get("RunAttempt", "").isdecimal() or not tags.get("Job")):
                raise ValueError("invalid integration tags: " + arn)
            if int(tags["ExpiresAt"]) > now:
                continue
            key = metadata(aws, arn, ctx)
            created = created_seconds(key["CreationDate"])
            # Never delete a fresh key because of an incorrect/past expiry tag.
            if created > now - TTL:
                continue
            if int(tags["ExpiresAt"]) < created:
                raise ValueError("expiry predates key creation: " + arn)
            eligible += 1
            schedule(aws, arn, key, dry_run)
        except AwsError as error:
            # Another cleanup may have completed deletion between listing and reading.
            if error.code != "NotFoundException":
                failures.append(str(error))
                print("Orphan cleanup failed: " + str(error), file=sys.stderr)
        except Exception as error:
            failures.append(str(error))
            print("Orphan cleanup failed: " + str(error), file=sys.stderr)
    print(f"Scanned {len(entries)} keys; {owned} owned by this repository; "
          f"{eligible} expired candidates; dry_run={dry_run}.")
    if failures:
        raise RuntimeError(f"orphan cleanup failed for {len(failures)} key(s)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    provision = commands.add_parser("create")
    provision.add_argument("--kind", choices=SPECS, action="append", required=True)
    provision.add_argument("--state", type=Path, required=True)
    release = commands.add_parser("cleanup")
    release.add_argument("--state", type=Path, required=True)
    orphan = commands.add_parser("sweep")
    orphan.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    region = os.environ["AWS_REGION"]
    if not re.fullmatch(r"[a-z0-9-]+", region):
        raise ValueError("invalid AWS_REGION")
    aws = Aws(region)
    ctx = context(aws)
    if args.command == "create":
        create(aws, ctx, args.state, args.kind, Path(os.environ["GITHUB_ENV"]))
    elif args.command == "cleanup":
        cleanup(aws, ctx, args.state)
    else:
        sweep(aws, ctx, args.dry_run)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
