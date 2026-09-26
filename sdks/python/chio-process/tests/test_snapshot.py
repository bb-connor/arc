import copy
import hashlib
import json
import unittest

from chio_process import WorkerError, snapshot


class MemoryBlobs:
    def __init__(self):
        self.blobs = {}
        self.puts = 0
        self.reads = []
        self.fail_at = None

    def put_blob(self, data):
        self.puts += 1
        if self.puts == self.fail_at:
            raise WorkerError("transport_error")
        assert len(data) <= snapshot.MAX_STATE_BLOB_BYTES
        key = hashlib.sha256(data).hexdigest()
        self.blobs[key] = data
        return {"sha256": key, "bytes": len(data)}

    def read_blob(self, key):
        self.reads.append(key)
        if key not in self.blobs:
            raise WorkerError("blob_missing")
        return self.blobs[key]


def stored_index(client, reference, data):
    result = copy.deepcopy(reference)
    result["index"] = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "blobs": [
            client.put_blob(data[i : i + snapshot.MAX_STATE_BLOB_BYTES])["sha256"]
            for i in range(0, len(data), snapshot.MAX_STATE_BLOB_BYTES)
        ],
    }
    return result


class JsonSnapshotTests(unittest.TestCase):
    def test_fresh_reader_recovers_the_original_json_encoding(self):
        for value in [
            None,
            False,
            0,
            -0.0,
            1.234e-50,
            {},
            [],
            "",
            "\x00雪🚀",
            "\ud800",
            {"z": [True, False, None, 123, -4.5], "a": {"nested": "x"}},
            {"large": "x" * (snapshot.MAX_STATE_BLOB_BYTES + 1)},
        ]:
            with self.subTest(value=value):
                client = MemoryBlobs()
                parts = snapshot.parts(value)
                self.assertTrue(b"".join(parts) == snapshot.encode(value))
                reference = snapshot.JsonSnapshot(client).write(value)
                self.assertTrue(reference["bytes"] == len(snapshot.encode(value)))
                self.assertTrue(
                    reference["sha256"] == hashlib.sha256(snapshot.encode(value)).hexdigest()
                )
                restored = snapshot.JsonSnapshot(client).read(reference)
                self.assertTrue(snapshot.encode(restored) == snapshot.encode(value))

    def test_small_edits_share_unchanged_atoms_and_keep_all_snapshot_references(self):
        client = MemoryBlobs()
        writer = snapshot.JsonSnapshot(client)
        history = []
        for turn in range(128):
            value = {
                "counter": turn,
                "messages": [
                    {"role": "tool", "content": f"observation-{n}:" + "x" * 4096}
                    for n in range(turn + 1)
                ],
            }
            history.append((writer.write(value), value))
        self.assertTrue(sum(map(len, client.blobs.values())) < 4 * 1024 * 1024)
        self.assertTrue(client.puts < 1024)
        for reference, expected in history:
            self.assertTrue(snapshot.JsonSnapshot(client).read(reference) == expected)

    def test_reuse_is_private_to_one_client_and_reads_verify_every_blob(self):
        client = MemoryBlobs()
        writer = snapshot.JsonSnapshot(client)
        value = {"large": "x" * 8192}
        reference = writer.write(value)
        puts = client.puts
        self.assertTrue(writer.write(value) == reference)
        self.assertTrue(client.puts == puts)
        reader = snapshot.JsonSnapshot(client)
        self.assertTrue(reader.read(reference) == value)
        client.reads.clear()
        self.assertTrue(reader.read(reference) == value)
        self.assertTrue(len(client.reads) > 1)
        with self.assertRaisesRegex(WorkerError, "blob_missing"):
            snapshot.JsonSnapshot(MemoryBlobs()).read(reference)

    def test_unencodable_or_oversized_document_writes_nothing(self):
        for value in [float("nan"), float("inf"), {"x": "a" * snapshot.MAX_SNAPSHOT_BYTES}]:
            with self.subTest(value=value):
                client = MemoryBlobs()
                with self.assertRaises(ValueError):
                    snapshot.JsonSnapshot(client).write(value)
                self.assertTrue(not client.blobs and client.puts == 0)

    def test_invalid_root_reference_is_refused_without_reading_blobs(self):
        for mutation in [
            "unknown",
            "schema",
            "bytes_bool",
            "bytes_overflow",
            "digest",
            "index_unknown",
            "index_size",
            "index_count",
            "index_digest",
        ]:
            with self.subTest(mutation=mutation):
                client = MemoryBlobs()
                reference = snapshot.JsonSnapshot(client).write({"x": 1})
                if mutation == "unknown":
                    reference["extra"] = True
                elif mutation == "schema":
                    reference["schema"] = []
                elif mutation == "bytes_bool":
                    reference["bytes"] = True
                elif mutation == "bytes_overflow":
                    reference["bytes"] = snapshot.MAX_SNAPSHOT_BYTES + 1
                elif mutation == "digest":
                    reference["sha256"] = "../outside"
                elif mutation == "index_unknown":
                    reference["index"]["extra"] = 1
                elif mutation == "index_size":
                    reference["index"]["bytes"] = snapshot.MAX_INDEX_BYTES + 1
                elif mutation == "index_count":
                    reference["index"]["blobs"] *= 2
                else:
                    reference["index"]["sha256"] = "A" * 64
                with self.assertRaises(ValueError):
                    snapshot.JsonSnapshot(client).read(reference)
                self.assertTrue(client.reads == [])

    def test_invalid_index_cannot_start_payload_reconstruction(self):
        for chunks in [
            None,
            [],
            [["0" * 64, True]],
            [["0" * 64, 0]],
            [["../outside", 1]],
            [["0" * 64, snapshot.MAX_STATE_BLOB_BYTES + 1]],
            [["0" * 64, 1, 2]],
            [["0" * 64, 1]] * (snapshot.MAX_PARTS + 1),
            [["0" * 64, snapshot.MAX_STATE_BLOB_BYTES]] * 9,
        ]:
            with self.subTest(chunks=chunks):
                client = MemoryBlobs()
                reference = snapshot.JsonSnapshot(client).write({"x": 1})
                reference = stored_index(client, reference, snapshot.encode(chunks))
                with self.assertRaises(ValueError):
                    snapshot.JsonSnapshot(client).read(reference)
                self.assertTrue(client.reads == reference["index"]["blobs"])

    def test_missing_or_changed_bytes_never_return_a_document(self):
        for location in ["index", "payload"]:
            with self.subTest(location=location):
                for mutation in ["missing", "truncated", "corrupt"]:
                    with self.subTest(mutation=mutation):
                        client = MemoryBlobs()
                        reference = snapshot.JsonSnapshot(client).write(
                            {"large": "x" * (2 * snapshot.MIN_ATOM_BYTES)}
                        )
                        index_key = reference["index"]["blobs"][0]
                        key = (
                            index_key
                            if location == "index"
                            else json.loads(client.blobs[index_key])[1][0]
                        )
                        if mutation == "missing":
                            del client.blobs[key]
                        elif mutation == "truncated":
                            client.blobs[key] = client.blobs[key][:-1]
                        else:
                            client.blobs[key] = b"x" * len(client.blobs[key])
                        with self.assertRaises((ValueError, WorkerError)):
                            snapshot.JsonSnapshot(client).read(reference)

    def test_valid_hashes_do_not_make_invalid_json_acceptable(self):
        for data in [b'{"x":1,"x":2}', b"NaN", b"1e999", b"{bad"]:
            with self.subTest(data=data):
                client = MemoryBlobs()
                key = client.put_blob(data)["sha256"]
                reference = {"schema": snapshot.SCHEMA, "bytes": len(data), "sha256": key}
                reference = stored_index(client, reference, snapshot.encode([[key, len(data)]]))
                with self.assertRaises(ValueError):
                    snapshot.JsonSnapshot(client).read(reference)

    def test_reordering_valid_segments_cannot_substitute_another_valid_document(self):
        client = MemoryBlobs()
        count = 2 * snapshot.MIN_ATOM_BYTES
        reference = snapshot.JsonSnapshot(client).write({"a": "x" * count, "b": "y" * count})
        chunks = json.loads(client.blobs[reference["index"]["blobs"][0]])
        chunks[1], chunks[3] = chunks[3], chunks[1]
        substituted = b"".join(client.blobs[key] for key, _ in chunks)
        self.assertEqual(json.loads(substituted), {"a": "y" * count, "b": "x" * count})
        reference = stored_index(client, reference, snapshot.encode(chunks))
        with self.assertRaisesRegex(ValueError, "snapshot is missing or corrupt"):
            snapshot.JsonSnapshot(client).read(reference)

    def test_interrupted_writes_preserve_existing_references_and_can_retry(self):
        for offset in [1, 2, 3]:
            with self.subTest(offset=offset):
                client = MemoryBlobs()
                writer = snapshot.JsonSnapshot(client)
                original = {"original": "x" * (2 * snapshot.MIN_ATOM_BYTES)}
                reference = writer.write(original)
                before = set(client.blobs)
                client.fail_at = client.puts + offset
                changed = {"new": "y" * (2 * snapshot.MIN_ATOM_BYTES)}
                with self.assertRaisesRegex(WorkerError, "transport_error"):
                    writer.write(changed)
                self.assertTrue(before <= set(client.blobs))
                self.assertTrue(snapshot.JsonSnapshot(client).read(reference) == original)
                client.fail_at = None
                committed = writer.write(changed)
                self.assertTrue(snapshot.JsonSnapshot(client).read(committed) == changed)
                self.assertTrue(snapshot.JsonSnapshot(client).read(reference) == original)


if __name__ == "__main__":
    unittest.main()
