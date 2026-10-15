"""Test socket diagnostic replies with literal wire records."""

import importlib.util
from pathlib import Path
import struct
import unittest


SPEC = importlib.util.spec_from_file_location("qemu_socket_diag_subject", Path(__file__).with_name("check-qemu-health.py"))
SUBJECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUBJECT)


def attribute(kind, payload):
    length = 4 + len(payload)
    return struct.pack("=HH", length, kind) + payload + bytes((-length) % 4)


def message(payload, *, kind=20, flags=0, sequence=23, port=4321):
    return struct.pack("=IHHII", 16 + len(payload), kind, flags, sequence, port) + payload


# Declared synthetic little/native-endian UAPI records, not captured kernel bytes.
REQUEST = message(struct.pack("=BBHIIIII", 1, 0, 0, 1024, 9001, 83,
                              0x12345678, 0x9ABCDEF0), flags=1)
RECORD = struct.pack("=BBBBIII", 1, 1, 10, 0, 9001, 0x12345678, 0x9ABCDEF0)
NAME = attribute(0, b"/private/listener\0")
VFS = attribute(1, struct.pack("=II", 7001, 0x00800123))
UID = attribute(7, struct.pack("=I", 1000))
SHUTDOWN = attribute(6, b"\0")
ZERO_QUEUE = attribute(4, struct.pack("=II", 0, 4))
ONE_QUEUE = attribute(4, struct.pack("=II", 1, 4))
PREFIX = RECORD + NAME + VFS + UID + SHUTDOWN


class UnixDiagnosticReplyTests(unittest.TestCase):
    def decode(self, data, **changes):
        arguments = {
            "sender": (0, 0), "msg_flags": 0, "seq": 23, "port_id": 4321,
            "inode": 9001, "cookie": (0x12345678, 0x9ABCDEF0),
            "name": b"/private/listener", "request": REQUEST,
        }
        arguments.update(changes)
        return SUBJECT.decode_socket_reply(data, **arguments)

    def test_zero_queue_is_observed_with_complete_identity(self):
        self.assertEqual(self.decode(message(PREFIX + ZERO_QUEUE)), {
            "inode": 9001, "cookie": (0x12345678, 0x9ABCDEF0),
            "name": b"/private/listener", "vfs_inode": 7001,
            "vfs_major": 8, "vfs_minor": 291, "rqueue": 0, "wqueue": 4,
            "uid": 1000, "shutdown": 0,
        })

    def test_one_pending_connection_is_not_replaced_with_zero(self):
        result = self.decode(message(PREFIX + ONE_QUEUE))
        self.assertEqual(result, {
            "inode": 9001, "cookie": (0x12345678, 0x9ABCDEF0),
            "name": b"/private/listener", "vfs_inode": 7001,
            "vfs_major": 8, "vfs_minor": 291, "rqueue": 1, "wqueue": 4,
            "uid": 1000, "shutdown": 0,
        })

    def test_missing_rqlen_is_refused(self):
        with self.assertRaises(ValueError):
            self.decode(message(PREFIX))

    def test_short_rqlen_is_refused(self):
        with self.assertRaises(ValueError):
            self.decode(message(PREFIX + attribute(4, struct.pack("=I", 0))))

    def test_truncated_rqlen_is_refused_even_with_matching_outer_length(self):
        with self.assertRaises(ValueError):
            self.decode(message(PREFIX + struct.pack("=HHI", 12, 4, 0)))

    def test_duplicate_queue_is_refused(self):
        with self.assertRaises(ValueError):
            self.decode(message(PREFIX + ZERO_QUEUE + ONE_QUEUE))

    def test_flagged_queue_attribute_is_refused(self):
        with self.assertRaises(ValueError):
            self.decode(message(PREFIX + attribute(0x8004, struct.pack("=II", 0, 4))))

    def test_kernel_peer_is_separate_from_reply_port_id(self):
        for sender in ((4321, 0), (0, 1)):
            with self.subTest(sender=sender), self.assertRaises(ValueError):
                self.decode(message(PREFIX + ZERO_QUEUE), sender=sender)
        with self.assertRaises(ValueError):
            self.decode(message(PREFIX + ZERO_QUEUE, port=0))

    def test_wrong_sequence_and_cookie_are_refused(self):
        with self.assertRaises(ValueError):
            self.decode(message(PREFIX + ZERO_QUEUE, sequence=24))
        with self.assertRaises(ValueError):
            self.decode(message(PREFIX + ZERO_QUEUE), cookie=(1, 2))

    def test_received_cookie_corruption_is_refused_with_valid_request(self):
        wrong_cookie_record = struct.pack("=BBBBIII", 1, 1, 10, 0, 9001,
                                          0x12345679, 0x9ABCDEF0)
        with self.assertRaises(ValueError):
            self.decode(message(wrong_cookie_record + NAME + VFS + UID + SHUTDOWN + ZERO_QUEUE))

    def test_receive_truncation_flags_are_refused(self):
        # Linux MSG_TRUNC=0x20 and MSG_CTRUNC=0x08, deliberately literal.
        for flag in (0x20, 0x08):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                self.decode(message(PREFIX + ZERO_QUEUE), msg_flags=flag)

    def test_wrong_state_and_multiple_messages_are_refused(self):
        not_listening = struct.pack("=BBBBIII", 1, 1, 1, 0, 9001, 0x12345678, 0x9ABCDEF0)
        with self.assertRaises(ValueError):
            self.decode(message(not_listening + NAME + VFS + UID + SHUTDOWN + ZERO_QUEUE))
        with self.assertRaises(ValueError):
            self.decode(message(PREFIX + ZERO_QUEUE) * 2)

    def test_exact_negative_error_preserves_errno(self):
        for error in (2, 116):
            with self.subTest(error=error):
                with self.assertRaises(OSError) as caught:
                    self.decode(message(struct.pack("=i", -error) + REQUEST, kind=2))
                self.assertEqual(caught.exception.errno, error)

    def test_zero_ack_and_wrong_error_echo_are_not_absence(self):
        for payload in (struct.pack("=i", 0) + REQUEST,
                        struct.pack("=i", -2) + REQUEST[:-1] + b"\xff"):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.decode(message(payload, kind=2))

    def test_missing_name_vfs_uid_or_shutdown_is_refused(self):
        for omitted in (NAME, VFS, UID, SHUTDOWN):
            payload = RECORD + b"".join(item for item in (NAME, VFS, UID, SHUTDOWN) if item != omitted)
            with self.subTest(omitted=omitted), self.assertRaises(ValueError):
                self.decode(message(payload + ZERO_QUEUE))

    def test_wrong_name_and_malformed_identity_attributes_are_refused(self):
        records = (
            RECORD + attribute(0, b"/another/path\0") + VFS + UID + SHUTDOWN,
            RECORD + NAME + attribute(1, b"\0" * 4) + UID + SHUTDOWN,
            RECORD + NAME + VFS + attribute(7, b"\0") + SHUTDOWN,
            RECORD + NAME + VFS + UID + attribute(6, b""),
        )
        for payload in records:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.decode(message(payload + ZERO_QUEUE))

    def test_inode_family_type_and_padding_mismatches_are_refused(self):
        for fields in ((1, 1, 10, 0, 9002), (2, 1, 10, 0, 9001),
                       (1, 2, 10, 0, 9001), (1, 1, 10, 1, 9001)):
            record = struct.pack("=BBBBIII", *fields, 0x12345678, 0x9ABCDEF0)
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.decode(message(record + NAME + VFS + UID + SHUTDOWN + ZERO_QUEUE))

    def test_truncated_header_bad_length_and_error_are_refused(self):
        for data in (b"\0" * 15, message(PREFIX + ZERO_QUEUE)[:-1],
                     message(struct.pack("=i", -2), kind=2),
                     message(struct.pack("=i", 2) + REQUEST, kind=2)):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.decode(data)

    def test_capped_negative_error_preserves_errno(self):
        with self.assertRaises(OSError) as caught:
            self.decode(message(struct.pack("=i", -2) + REQUEST[:16], kind=2, flags=0x100))
        self.assertEqual(caught.exception.errno, 2)

    def test_invalid_request_and_multipart_are_refused(self):
        with self.assertRaises(ValueError):
            self.decode(message(PREFIX + ZERO_QUEUE), request=REQUEST[:-1])
        with self.assertRaises(ValueError):
            self.decode(message(PREFIX + ZERO_QUEUE, flags=2))


if __name__ == "__main__":
    unittest.main()
