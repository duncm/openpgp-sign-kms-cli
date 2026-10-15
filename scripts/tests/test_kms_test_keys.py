"""Offline lifecycle tests. No credentials, AWS account, or network needed."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("kms_test_keys", Path(__file__).resolve().parents[1] / "kms-test-keys.py")
keys = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = keys
spec.loader.exec_module(keys)
NOW = 1_800_000_000
CTX = keys.Context("ap-southeast-2", "123456789012", "duncm/openpgp-sign-kms", "100", "2", "test-arm64-RSA")


class FakeAws:
    def __init__(self):
        self.items = {}
        self.calls = []
        self.created = 0
        self.fail_creation = None
        self.lose_response = False
        self.fail_schedule = set()

    def add(self, tags=None, created=NOW, **changes):
        arn = f"arn:aws:kms:ap-southeast-2:123456789012:key/00000000-0000-0000-0000-{len(self.items) + 1:012d}"
        key = dict(Arn=arn, KeyManager="CUSTOMER", KeyUsage="SIGN_VERIFY", KeySpec="RSA_3072",
                   Origin="AWS_KMS", MultiRegion=False, KeyState="Enabled", CreationDate=created)
        key.update(changes)
        self.items[arn] = (key, dict(CTX.tags(created) if tags is None else tags))
        return arn

    def call(self, service, operation, *args):
        self.calls.append((service, operation, args))
        if operation == "create-key":
            self.created += 1
            if self.created == self.fail_creation:
                raise keys.AwsError("(AccessDeniedException) denied")
            tags = {t['TagKey']: t['TagValue'] for t in json.loads(args[args.index('--tags') + 1])}
            arn = self.add(tags=tags, KeySpec=args[args.index('--key-spec') + 1])
            if self.lose_response:
                raise keys.AwsError("connection lost after key creation")
            return {"KeyMetadata": self.items[arn][0]}
        if operation == "list-keys":
            return {"Keys": [{"KeyArn": arn} for arn in self.items]}
        arn = args[args.index('--key-id') + 1]
        key, tags = self.items[arn]
        if operation == "describe-key":
            return {"KeyMetadata": key}
        if operation == "list-resource-tags":
            return {"Tags": [{"TagKey": k, "TagValue": v} for k, v in tags.items()]}
        if operation == "get-public-key":
            return {"PublicKey": "test"}
        if operation == "schedule-key-deletion":
            if arn in self.fail_schedule:
                raise keys.AwsError("(AccessDeniedException) denied")
            assert args[-2:] == ('--pending-window-in-days', '7')
            key['KeyState'] = 'PendingDeletion'
            return {"KeyId": arn, "KeyState": "PendingDeletion"}
        raise AssertionError(operation)

    def deleted(self):
        return {arn for arn, (key, _) in self.items.items() if key['KeyState'] == 'PendingDeletion'}


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / 'keys.jsonl'
        self.env = Path(self.temp.name) / 'env'
        self.aws = FakeAws()
        # Retry behavior is tested separately, without six-minute waits for denials.
        retry = patch.object(keys, 'retry', lambda operation: operation())
        retry.start()
        self.addCleanup(retry.stop)

    def create(self, kinds=('RSA', 'ED25519')):
        keys.create(self.aws, CTX, self.state, kinds, self.env, now=NOW)

    def test_per_job_creation_and_idempotent_cleanup(self):
        self.create()
        records = [json.loads(line) for line in self.state.read_text().splitlines()]
        self.assertEqual(len(records), 2)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        self.assertIn('KMS_RSA_KEY_ARN=', self.env.read_text())
        self.assertIn('KMS_ED25519_KEY_ARN=', self.env.read_text())
        for record in records:
            self.assertEqual(record['tags'], CTX.tags(NOW))
        keys.cleanup(self.aws, CTX, self.state)
        keys.cleanup(self.aws, CTX, self.state)
        self.assertEqual(len(self.aws.deleted()), 2)
        self.assertEqual(sum(c[1] == 'schedule-key-deletion' for c in self.aws.calls), 2)

    def test_partial_creation_retains_first_key_for_cleanup(self):
        self.aws.fail_creation = 2
        with self.assertRaises(keys.AwsError):
            self.create()
        self.assertEqual(len(self.state.read_text().splitlines()), 1)
        keys.cleanup(self.aws, CTX, self.state)
        self.assertEqual(len(self.aws.deleted()), 1)

    def test_record_is_saved_before_readiness_failure(self):
        original = self.aws.call
        def call(service, operation, *args):
            if operation == 'get-public-key':
                raise keys.AwsError('(AccessDeniedException) not ready')
            return original(service, operation, *args)
        with patch.object(self.aws, 'call', side_effect=call):
            with self.assertRaises(keys.AwsError):
                self.create(('RSA',))
        self.assertEqual(len(self.state.read_text().splitlines()), 1)
        self.assertFalse(self.env.exists())
        keys.cleanup(self.aws, CTX, self.state)
        self.assertEqual(len(self.aws.deleted()), 1)

    def test_lost_creation_response_is_recovered_by_sweeper(self):
        self.aws.lose_response = True
        with self.assertRaises(keys.AwsError):
            self.create(('RSA',))
        self.assertEqual(self.aws.created, 1)
        self.assertEqual(self.state.read_text(), '')
        keys.sweep(self.aws, CTX, now=NOW + keys.TTL + 1)
        self.assertEqual(len(self.aws.deleted()), 1)

    def test_cleanup_continues_after_one_failure_and_reports_it(self):
        self.create()
        first = next(iter(self.aws.items))
        self.aws.fail_schedule.add(first)
        with self.assertRaises(RuntimeError):
            keys.cleanup(self.aws, CTX, self.state)
        self.assertEqual(len(self.aws.deleted()), 1)
        self.assertNotIn(first, self.aws.deleted())

    def test_corrupt_journal_does_not_block_other_records(self):
        self.create()
        self.state.write_text('incomplete JSON\n' + self.state.read_text())
        with self.assertRaises(RuntimeError):
            keys.cleanup(self.aws, CTX, self.state)
        self.assertEqual(len(self.aws.deleted()), 2)

    def test_cleanup_refuses_other_attempt_or_changed_tags(self):
        self.create(('RSA',))
        other = keys.Context(CTX.region, CTX.account, CTX.repository, CTX.run, '3', CTX.job)
        with self.assertRaises(RuntimeError):
            keys.cleanup(self.aws, other, self.state)
        next(iter(self.aws.items.values()))[1]['Job'] = 'different-job'
        with self.assertRaises(RuntimeError):
            keys.cleanup(self.aws, CTX, self.state)
        self.assertEqual(self.aws.deleted(), set())

    def test_existing_journal_and_duplicate_kinds_are_refused(self):
        with self.assertRaises(ValueError):
            self.create(('RSA', 'RSA'))
        self.state.touch()
        with self.assertRaises(FileExistsError):
            self.create()
        self.assertEqual(self.aws.created, 0)

    def test_no_journal_is_safe(self):
        keys.cleanup(self.aws, CTX, self.state)
        self.assertEqual(self.aws.calls, [])

    def test_sweep_ignores_unrelated_unexpired_and_fresh_keys(self):
        old = NOW - keys.TTL - 1
        wanted = self.aws.add(created=old)
        self.aws.add(tags={'Project': keys.PROJECT}, created=old)  # Permanent key.
        other = CTX.tags(old)
        other['Repository'] = 'duncm/openpgp-sign-kms-cli'
        self.aws.add(tags=other, created=old)
        future = CTX.tags(NOW)
        self.aws.add(tags=future, created=old)
        self.aws.add(tags=CTX.tags(old), created=NOW)  # Bad expiry must not kill active keys.
        # Unrelated multi-region and encryption keys are not cleanup candidates.
        self.aws.add(tags={}, MultiRegion=True, KeyUsage='ENCRYPT_DECRYPT')
        keys.sweep(self.aws, CTX, now=NOW)
        self.assertEqual(self.aws.deleted(), {wanted})

    def test_dry_run_and_pending_deletion(self):
        old = NOW - keys.TTL - 1
        self.aws.add(created=old)
        pending = self.aws.add(created=old, KeyState='PendingDeletion')
        keys.sweep(self.aws, CTX, dry_run=True, now=NOW)
        self.assertEqual(self.aws.deleted(), {pending})
        self.assertFalse(any(c[1] == 'schedule-key-deletion' for c in self.aws.calls))

    def test_sweep_reports_malformed_tags_and_continues(self):
        old = NOW - keys.TTL - 1
        bad = CTX.tags(old)
        bad['ExpiresAt'] = 'not-a-date'
        self.aws.add(tags=bad, created=old)
        wanted = self.aws.add(created=old)
        with self.assertRaises(RuntimeError):
            keys.sweep(self.aws, CTX, now=NOW)
        self.assertEqual(self.aws.deleted(), {wanted})

    def test_sweep_refuses_unexpected_metadata(self):
        for changes in [{'KeyUsage': 'ENCRYPT_DECRYPT'}, {'MultiRegion': True},
                        {'Origin': 'EXTERNAL'}, {'KeyManager': 'AWS'}, {'KeySpec': 'RSA_2048'}]:
            with self.subTest(changes=changes):
                aws = FakeAws()
                aws.add(created=NOW - keys.TTL - 1, **changes)
                with self.assertRaises(RuntimeError):
                    keys.sweep(aws, CTX, now=NOW)
                self.assertEqual(aws.deleted(), set())

    def test_arn_scope(self):
        arn = self.aws.add()
        CTX.validate_arn(arn)
        for invalid in [arn.replace('123456789012', '999999999999'),
                        arn.replace('ap-southeast-2', 'us-east-1'), arn + '\nEVIL=1']:
            with self.assertRaises(ValueError):
                CTX.validate_arn(invalid)


class AwsCliTests(unittest.TestCase):
    def test_create_has_no_automatic_retries_and_reads_keep_pagination(self):
        aws = keys.Aws('ap-southeast-2')
        with patch.object(keys.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{}', '')) as run:
            aws.call('kms', 'create-key')
            self.assertEqual(run.call_args.kwargs['env']['AWS_MAX_ATTEMPTS'], '1')
            aws.call('kms', 'list-keys')
            self.assertEqual(run.call_args.kwargs['env']['AWS_MAX_ATTEMPTS'], '3')
            self.assertNotIn('--no-paginate', run.call_args.args[0])

    def test_eventual_consistency_retry_and_deadline(self):
        transient = keys.AwsError('(NotFoundException) not visible')
        with patch.object(keys.time, 'sleep') as sleep:
            operation = unittest.mock.Mock(side_effect=[transient, {'ready': True}])
            self.assertEqual(keys.retry(operation), {'ready': True})
            sleep.assert_called_once_with(5)
            with self.assertRaises(keys.AwsError):
                keys.retry(unittest.mock.Mock(side_effect=transient), budget=0)

    def test_timestamps(self):
        self.assertEqual(keys.created_seconds('2027-01-15T08:00:00+00:00'), 1800000000)
        for value in [float('nan'), float('inf'), True, None, '2027-01-15T08:00:00']:
            with self.assertRaises(ValueError):
                keys.created_seconds(value)


if __name__ == '__main__':
    unittest.main()
