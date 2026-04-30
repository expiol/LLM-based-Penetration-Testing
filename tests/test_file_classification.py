"""Tests for the unified file_classification module."""

from __future__ import annotations

import unittest

from nyuctf_mutil_killchain.state.file_classification import (
    EXT_TO_KIND,
    FileKind,
    SOURCE_EXTS,
    basename,
    classify,
    files_by_kind,
    filter_by_kind,
    looks_like_archive,
    looks_like_pcap,
    looks_like_source,
    looks_like_sqlite,
    split_source_and_binary,
)


class FileClassificationTests(unittest.TestCase):
    def test_classify_source_extensions(self):
        for ext in SOURCE_EXTS:
            self.assertEqual(classify(f"foo{ext}"), FileKind.SOURCE)

    def test_classify_archive_extensions(self):
        for ext in (".zip", ".tar", ".gz", ".tgz", ".7z"):
            self.assertEqual(classify(f"bundle{ext}"), FileKind.ARCHIVE)

    def test_classify_pcap_extensions(self):
        for ext in (".pcap", ".pcapng", ".cap"):
            self.assertEqual(classify(f"capture{ext}"), FileKind.PCAP)

    def test_classify_sqlite_extensions(self):
        for ext in (".db", ".sqlite", ".sqlite3"):
            self.assertEqual(classify(f"data{ext}"), FileKind.SQLITE)

    def test_unknown_extension_falls_through_to_binary(self):
        self.assertEqual(classify("stfu"), FileKind.BINARY)
        self.assertEqual(classify("flag.stfu"), FileKind.BINARY)
        self.assertEqual(classify(""), FileKind.BINARY)

    def test_files_by_kind_groups_correctly(self):
        files = ["solve.py", "data.bin", "stfu", "csaw.tar.gz", "log.pcap", "users.db"]
        groups = files_by_kind(files)
        self.assertEqual(groups[FileKind.SOURCE], ["solve.py"])
        self.assertEqual(groups[FileKind.BINARY], ["data.bin", "stfu"])
        self.assertEqual(groups[FileKind.ARCHIVE], ["csaw.tar.gz"])
        self.assertEqual(groups[FileKind.PCAP], ["log.pcap"])
        self.assertEqual(groups[FileKind.SQLITE], ["users.db"])

    def test_filter_by_kind(self):
        files = ["a.py", "b.zip", "c.pcap", "d"]
        self.assertEqual(filter_by_kind(files, FileKind.SOURCE), ["a.py"])
        self.assertEqual(filter_by_kind(files, FileKind.ARCHIVE), ["b.zip"])
        self.assertEqual(filter_by_kind(files, FileKind.PCAP), ["c.pcap"])
        self.assertEqual(filter_by_kind(files, FileKind.BINARY), ["d"])

    def test_split_source_and_binary(self):
        sources, others = split_source_and_binary(["x.py", "y", "z.tar.gz"])
        self.assertEqual(sources, ["x.py"])
        self.assertEqual(others, ["y", "z.tar.gz"])

    def test_looks_like_predicates(self):
        self.assertTrue(looks_like_source("a.py"))
        self.assertFalse(looks_like_source("a"))
        self.assertTrue(looks_like_archive("a.zip"))
        self.assertTrue(looks_like_pcap("a.pcap"))
        self.assertTrue(looks_like_sqlite("a.sqlite3"))

    def test_basename_handles_archive_member_paths(self):
        self.assertEqual(basename("csaw.tar.gz:csaw/docs/index.html"), "index.html")
        self.assertEqual(basename("plain.py"), "plain.py")

    def test_ext_to_kind_table_coverage(self):
        # Sanity: every value in EXT_TO_KIND must be a FileKind
        for kind in EXT_TO_KIND.values():
            self.assertIsInstance(kind, FileKind)


if __name__ == "__main__":
    unittest.main()
