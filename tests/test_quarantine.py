import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.quarantine import ResponseError, quarantine


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.watch = self.root / "watch"
        self.destination = self.root / "quarantine"
        self.watch.mkdir()
        self.destination.mkdir()
        self.source = self.watch / "eicar.com"
        self.source.write_bytes(b"synthetic test content")

    def tearDown(self):
        self.temp.cleanup()

    def message(self, source=None, rule_id="87105", command="add"):
        return {
            "command": command,
            "parameters": {
                "alert": {
                    "rule": {"id": rule_id},
                    "data": {"virustotal": {"source": {"file": str(source or self.source)}}},
                }
            },
        }

    def test_dry_run_reports_candidate_without_moving_it(self):
        result = quarantine(self.message(), self.watch, self.destination)

        self.assertEqual(result, {"status": "dry-run", "source": str(self.source)})
        self.assertTrue(self.source.exists())
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_execute_moves_file_to_uuid_named_destination(self):
        result = quarantine(self.message(), self.watch, self.destination, execute=True)

        moved = Path(result["destination"])
        self.assertEqual(result["status"], "quarantined")
        self.assertEqual(moved.parent, self.destination)
        self.assertRegex(moved.name, r"^eicar\.com\.[0-9a-f]{32}\.quarantine$")
        self.assertEqual(moved.read_bytes(), b"synthetic test content")
        self.assertFalse(self.source.exists())

    def test_unique_names_preserve_existing_quarantine_files(self):
        existing = self.destination / "eicar.com.known.quarantine"
        existing.write_bytes(b"keep this file")

        result = quarantine(self.message(), self.watch, self.destination, execute=True)

        self.assertEqual(existing.read_bytes(), b"keep this file")
        self.assertNotEqual(Path(result["destination"]), existing)

    def test_rejects_destination_collision_without_overwriting(self):
        target = self.destination / ("eicar.com." + "a" * 32 + ".quarantine")
        target.write_bytes(b"preexisting content")
        uuid = type("UUID", (), {"hex": "a" * 32})()

        with patch("tools.quarantine.uuid4", return_value=uuid):
            with self.assertRaises(ResponseError):
                quarantine(self.message(), self.watch, self.destination, execute=True)

        self.assertEqual(target.read_bytes(), b"preexisting content")
        self.assertTrue(self.source.exists())

    def test_different_filesystems_fail_without_removing_source(self):
        if not Path("/dev/shm").is_dir():
            self.skipTest("/dev/shm is unavailable for a cross-filesystem check")
        with tempfile.TemporaryDirectory(dir="/dev/shm") as other_fs:
            other_destination = Path(other_fs) / "quarantine"
            other_destination.mkdir()
            if os.stat(self.watch).st_dev == os.stat(other_destination).st_dev:
                self.skipTest("temporary directories share a filesystem")

            with self.assertRaises(ResponseError):
                quarantine(self.message(), self.watch, other_destination, execute=True)

            self.assertTrue(self.source.exists())
            self.assertEqual(list(other_destination.iterdir()), [])

    def test_rejects_path_outside_watch_directory(self):
        outside = self.root / "outside"
        outside.write_bytes(b"do not move")

        with self.assertRaisesRegex(ResponseError, "direct child"):
            quarantine(self.message(outside), self.watch, self.destination)

    def test_rejects_symlink_source(self):
        link = self.watch / "linked-file"
        link.symlink_to(self.source)

        with self.assertRaisesRegex(ResponseError, "regular file"):
            quarantine(self.message(link), self.watch, self.destination)

    def test_rejects_missing_file(self):
        missing = self.watch / "missing"

        with self.assertRaises(ResponseError):
            quarantine(self.message(missing), self.watch, self.destination)

    def test_rejects_non_regular_file(self):
        directory = self.watch / "directory"
        directory.mkdir()

        with self.assertRaisesRegex(ResponseError, "regular file"):
            quarantine(self.message(directory), self.watch, self.destination)

    def test_rejects_symlink_watch_or_quarantine_directory(self):
        watch_link = self.root / "watch-link"
        watch_link.symlink_to(self.watch, target_is_directory=True)
        with self.assertRaises(ResponseError):
            quarantine(self.message(), watch_link, self.destination)

        destination_link = self.root / "quarantine-link"
        destination_link.symlink_to(self.destination, target_is_directory=True)
        with self.assertRaises(ResponseError):
            quarantine(self.message(), self.watch, destination_link)

    def test_rejects_wrong_rule_and_non_add_command(self):
        with self.assertRaisesRegex(ResponseError, "rule ID"):
            quarantine(self.message(rule_id="550"), self.watch, self.destination)
        with self.assertRaisesRegex(ResponseError, "stateless add"):
            quarantine(self.message(command="delete"), self.watch, self.destination)


if __name__ == "__main__":
    unittest.main()
