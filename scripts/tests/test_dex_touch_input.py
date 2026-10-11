"""Exercise the actual patched Dalvik instructions with MotionEvent fixtures.

A small metadata fixture covers DEX lookup/patch guards. Set PHIRAIAD_TEST_APK
for the real release shell check. The interpreter checks event dispatch and
register usage; Android's verifier and device execution require an APK build.
"""
import hashlib
import os
from pathlib import Path
import struct
import sys
import unittest
import zipfile
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dex_touch_input as patch
from dex_density_dpi import patch_density_dpi, verify_density_dpi

M = patch._MOTION
EXTRA = {
    1570: (M, 'getEventTime', '()J'),
    1569: (M, 'getDeviceId', '()I'),
    1464: ('Landroid/view/InputDevice;', 'getDevice', '(I)Landroid/view/InputDevice;'),
    1574: (M, 'getX', '()F'),
    1576: (M, 'getY', '()F'),
    9830: ('Ll0/c;', 'f', '(Landroid/view/InputDevice;)Z'),
    1467: ('Landroid/view/InputDevice;', 'isVirtual', '()Z'),
}
PRELUDE = bytes.fromhex(
    '1209390a0300283d6e1022060a000b046e1021060a000a007110b80500000c00'
    '6e1026060a000a016e1028060a000a02380007007110662600000a0328021203'
    '380007006e10bb0500000a0028021200000000000000'
)
TOUCH = ('Lfixture/Activity;', 'onTouch', '(Landroid/view/View;Landroid/view/MotionEvent;)Z')


def checksum(data):
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data)


def uleb(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return result


def signature(proto):
    end = proto.index(')')
    args, pos = [], 1
    while pos < end:
        nxt = proto.index(';', pos) + 1 if proto[pos] == 'L' else pos + 1
        args.append(proto[pos:nxt])
        pos = nxt
    return proto[end + 1:], args


def fixture():
    methods = sorted(set(EXTRA.values()) | set(patch._REFERENCE_IDS.values()) | {TOUCH})
    protos = sorted({m[2] for m in methods})
    types = sorted({m[0] for m in methods} | {t for p in protos for t in (signature(p)[0], *signature(p)[1])})
    short = lambda p: ''.join('L' if t.startswith('L') else t for t in (signature(p)[0], *signature(p)[1]))
    strings = sorted(set(types) | {m[1] for m in methods} | {short(p) for p in protos})
    data = bytearray(112)
    slots = []
    for count, width in ((len(strings), 4), (len(types), 4), (len(protos), 12), (0, 8), (len(methods), 8), (1, 32)):
        slots.append(len(data));data.extend(bytes(count * width))
    data_start = len(data)
    for i, value in enumerate(strings):
        struct.pack_into('<I', data, slots[0] + 4 * i, len(data))
        data.extend(uleb(len(value)) + value.encode() + b'\0')
    for i, value in enumerate(types):
        struct.pack_into('<I', data, slots[1] + 4 * i, strings.index(value))
    for i, proto in enumerate(protos):
        result, args = signature(proto)
        params = 0
        if args:
            data.extend(bytes(-len(data) % 4));params = len(data)
            data.extend(struct.pack('<I', len(args)) + b''.join(struct.pack('<H', types.index(t)) for t in args))
        struct.pack_into('<III', data, slots[2] + 12 * i, strings.index(short(proto)), types.index(result), params)
    for i, (owner, name, proto) in enumerate(methods):
        struct.pack_into('<HHI', data, slots[4] + 8 * i, types.index(owner), protos.index(proto), strings.index(name))
    class_data = len(data)
    data.extend(bytes([0, 0, 0, 1]) + uleb(methods.index(TOUCH)) + uleb(0x11) + uleb(4096))
    struct.pack_into('<8I', data, slots[5], types.index(TOUCH[0]), 1, 0xffffffff, 0, 0xffffffff, 0, class_data, 0)
    prelude = list(struct.unpack('<43H', PRELUDE));pc = 0
    while pc < len(prelude):
        opcode = prelude[pc] & 255
        if opcode in (0x6e, 0x71):
            prelude[pc + 1] = methods.index(EXTRA[prelude[pc + 1]]);pc += 3
        else:
            pc += 2 if opcode in (0x38, 0x39) else 1
    data.extend(bytes(4096 - len(data)))
    data.extend(struct.pack('<4H2I', 11, 3, 6, 0, 0, 172))
    data.extend(struct.pack('<43H', *prelude) + patch._bind_original(methods))
    data[:8] = b'dex\n035\0'
    struct.pack_into('<5I', data, 32, len(data), 112, 0x12345678, 0, 0)
    for position, count, offset in zip(range(56, 104, 8), (len(strings), len(types), len(protos), 0, len(methods), 1), slots):
        struct.pack_into('<II', data, position, count, offset if count else 0)
    struct.pack_into('<II', data, 104, len(data) - data_start, data_start)
    return checksum(data)


def execute(data, event):
    methods = patch._methods(data)
    code = patch._touch_code_offset(data, methods)
    size = struct.unpack_from('<I', data, code + 12)[0]
    units = struct.unpack_from('<' + 'H' * size, data, code + 16)
    registers = [0] * 11;registers[10] = event if event is not None else 0
    pc, result, emitted = 0, None, []
    for _ in range(20000):
        word = units[pc];op = word & 255
        if op in (0x6e, 0x71, 0x77):
            owner, name, proto = methods[units[pc + 1]]
            count = word >> 12 if op != 0x77 else word >> 8
            if op == 0x77:
                args = registers[units[pc + 2]:units[pc + 2] + count]
            else:
                args = [registers[(units[pc + 2] >> (4 * i)) & 15] for i in range(count)]
            if (owner, name, proto) == patch._NATIVE:
                emitted.append((args[0], args[1], args[2], args[3], args[4]))
            elif owner == M:
                e = args[0]
                if name == 'getEventTime':result = e['time']
                elif name == 'getDeviceId':result = 7
                elif name == 'getActionMasked':result = e['action']
                elif name == 'getActionIndex':result = e['index']
                elif name == 'getPointerCount':result = len(e['pointers'])
                elif name == 'getPointerId':result = e['pointers'][args[1]][0]
                elif name in ('getX', 'getY'):result = e['pointers'][args[1] if len(args) > 1 else 0][1 if name == 'getX' else 2]
                else:raise AssertionError(name)
            elif name == 'getDevice':result = 0
            else:raise AssertionError((owner, name, proto))
            pc += 3
        elif op in (0x0a, 0x0b, 0x0c):
            registers[word >> 8] = result;pc += 1
        elif op == 0x12:
            value = word >> 12
            registers[(word >> 8) & 15] = value if value < 8 else value - 16;pc += 1
        elif op in (0x32, 0x33, 0x35, 0x38, 0x39):
            a = registers[(word >> 8) & 15];b = registers[word >> 12] if op < 0x38 else 0
            condition = (a == b) if op in (0x32, 0x38) else (a != b) if op in (0x33, 0x39) else (a >= b)
            displacement = struct.unpack('<h', struct.pack('<H', units[pc + 1]))[0]
            pc += displacement if condition else 2
        elif op == 0x28:
            displacement = word >> 8;pc += displacement if displacement < 128 else displacement - 256
        elif op == 0x29:
            pc += struct.unpack('<h', struct.pack('<H', units[pc + 1]))[0]
        elif op == 0xd8:
            source = units[pc + 1] & 255;value = units[pc + 1] >> 8
            registers[word >> 8] = registers[source] + (value if value < 128 else value - 256);pc += 2
        elif op == 0x0f:
            return bool(registers[word >> 8]), emitted
        elif op == 0:
            pc += 1
        else:
            raise AssertionError(('unsupported opcode', pc, hex(op)))
    raise AssertionError('Touch dispatch did not terminate')


def sample(action, index=0, count=3):
    return {'action': action, 'index': index, 'time': 987654321012,
            'pointers': [(i * 3 + 2, 0.1 + i * 20, 1.5 + i * 30) for i in range(count)]}


def expected(event):
    action, index = event['action'], event['index']
    if action not in (0, 1, 2, 3, 5, 6):return []
    return [(id, 3 if action == 3 else 2 if action in (0, 5) and i == index else 1 if action in (1, 6) and i == index else 0, x, y, event['time']) for i, (id, x, y) in enumerate(event['pointers'])]


class TouchPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = fixture()
        cls.patched = patch.patch_touch_input(cls.original)

    def test_single_pointer_down_up_move(self):
        for action in (0, 1, 2):
            e = sample(action, count=1)
            self.assertEqual(execute(self.patched, e), (True, expected(e)))

    def test_pointer_down_updates_survivors(self):
        e = sample(5, index=1)
        self.assertEqual(execute(self.patched, e), (True, expected(e)))
        self.assertEqual(len(execute(self.original, e)[1]), 1)

    def test_pointer_up_updates_survivors_without_releasing_them(self):
        e = sample(6, index=1)
        self.assertEqual(execute(self.patched, e), (True, expected(e)))
        self.assertEqual(len(execute(self.original, e)[1]), 1)

    def test_cancel_releases_all(self):
        e = sample(3)
        self.assertEqual(execute(self.patched, e), (True, expected(e)))

    def test_move_reports_every_pointer_once(self):
        e = sample(2)
        self.assertEqual(execute(self.patched, e), (True, expected(e)))

    def test_unknown_actions_remain_unhandled(self):
        for action in (4, 7, 8, 9, 10, 11, 12):
            self.assertEqual(execute(self.patched, sample(action)), (False, []))

    def test_null_event_keeps_original_behavior(self):
        self.assertEqual(execute(self.patched, None), (False, []))

    def test_every_valid_action_index_and_sparse_pointer_id(self):
        for count in range(1, 11):
            for index in range(count):
                for action in (2, 3, 5, 6):
                    e = sample(action, index, count)
                    self.assertEqual(execute(self.patched, e), (True, expected(e)))

    def test_patch_is_idempotent(self):
        self.assertEqual(patch.patch_touch_input(self.patched), self.patched)
        patch.verify_touch_input(self.patched)

    def test_only_dispatch_null_jump_debug_and_checksums_can_change(self):
        methods = patch._methods(self.original);code = patch._touch_code_offset(self.original, methods)
        allowed = set(range(8, 32)) | set(range(code + 8, code + 12)) | set(range(code + 22, code + 24)) | set(range(code + 102, code + 360))
        self.assertEqual(len(self.original), len(self.patched))
        self.assertTrue(all(i in allowed for i, (a, b) in enumerate(zip(self.original, self.patched)) if a != b))
        self.assertEqual(self.original[code:code + 8], self.patched[code:code + 8])

    def test_corrupt_checksum_rejected(self):
        data = bytearray(self.original);data[-1] ^= 1
        with self.assertRaises(ValueError):patch.patch_touch_input(bytes(data))

    def test_unknown_dispatch_rejected(self):
        data = bytearray(self.original);data[-2:] = b'\0\0'
        with self.assertRaises(ValueError):patch.patch_touch_input(checksum(data))

    def test_unknown_method_layout_rejected(self):
        data = bytearray(self.original);struct.pack_into('<H', data, 4096, 12)
        with self.assertRaises(ValueError):patch.patch_touch_input(checksum(data))

    @unittest.skipUnless(os.environ.get('PHIRAIAD_TEST_APK'), 'Set PHIRAIAD_TEST_APK for release-shell validation')
    def test_real_release_shell_and_density_patch_composition(self):
        with zipfile.ZipFile(os.environ['PHIRAIAD_TEST_APK']) as apk:
            original = apk.read('classes.dex')
        patched = patch.patch_touch_input(patch_density_dpi(original))
        patch.verify_touch_input(patched);verify_density_dpi(patched)
        self.assertEqual(patch.patch_touch_input(patched), patched)
        self.assertEqual(patch_density_dpi(patched), patched)
        for action in (0, 1, 2, 3, 5, 6):
            e = sample(action, count=1 if action in (0, 1) else 3)
            self.assertEqual(execute(patched, e), (True, expected(e)))
        self.assertEqual(execute(patched, None), (False, []))


if __name__ == '__main__':
    unittest.main()
