"""Synchronize every pointer in the supported Android shell's onTouch method.

The APK build replaces native libraries in an existing shell, so changing the
Rust dependency's Java source would not reach the APK. Replace only the known
onTouch dispatch body in place, retaining its device/time prelude and the
IIFFJ native bridge. Unknown dispatch bodies fail instead of being guessed.
No DEX tables, code offsets, register layout, or exception regions move.
"""
import hashlib
import struct
import zlib

from dex_density_dpi import _u32, _uleb

# r23 shell's original dispatch (code units 43..171), before method-ID binding.
_ORIGINAL = bytes.fromhex(
    '6e101f060a000a0012163800600032604200122132102500123132100900'
    '1251321055001261321036000f096e1023060a000a0735792e006e2024069a00'
    '0a006e2027069a000a026e2029069a000a03123177068c280000d809090128ec'
    '6e1023060a000a07357915006e2024069a000a006e2027069a000a026e2029069a00'
    '0a03120177068c280000d809090128ec0f066e101f060a000a00336003002805'
    '6e101e060a000a096e2024069a000a006e2027069a000a026e2029069a000a031211'
    '77068c2800000f066e101f060a000a003900030028056e101e060a000a09'
    '6e2024069a000a006e2027069a000a026e2029069a000a03122177068c2800000f06'
)
_MOTION = 'Landroid/view/MotionEvent;'
_NATIVE = ('Lquad_native/QuadNative;', 'surfaceOnTouch', '(IIFFJ)V')
_REFERENCE_IDS = {
    1566: (_MOTION, 'getActionIndex', '()I'),
    1567: (_MOTION, 'getActionMasked', '()I'),
    1571: (_MOTION, 'getPointerCount', '()I'),
    1572: (_MOTION, 'getPointerId', '(I)I'),
    1575: (_MOTION, 'getX', '(I)F'),
    1577: (_MOTION, 'getY', '(I)F'),
    10380: _NATIVE,
}


def _methods(data):
    if data[:4] != b'dex\n' or _u32(data, 32) != len(data) or _u32(data, 40) != 0x12345678:
        raise ValueError('Unsupported DEX header')
    if data[12:32] != hashlib.sha1(data[32:]).digest() or _u32(data, 8) != zlib.adler32(data[12:]) & 0xffffffff:
        raise ValueError('Invalid DEX checksums')
    count, offset = struct.unpack_from('<II', data, 56)
    strings = []
    for i in range(count):
        _, start = _uleb(data, _u32(data, offset + i * 4))
        strings.append(data[start:data.index(b'\0', start)].decode('utf8', errors='replace'))
    count, offset = struct.unpack_from('<II', data, 64)
    types = [strings[_u32(data, offset + i * 4)] for i in range(count)]
    count, offset = struct.unpack_from('<II', data, 72)
    protos = []
    for i in range(count):
        _, result, params = struct.unpack_from('<III', data, offset + i * 12)
        args = [] if not params else [types[struct.unpack_from('<H', data, params + 4 + j * 2)[0]] for j in range(_u32(data, params))]
        protos.append('(' + ''.join(args) + ')' + types[result])
    count, offset = struct.unpack_from('<II', data, 88)
    methods = []
    for i in range(count):
        owner, proto, name = struct.unpack_from('<HHI', data, offset + i * 8)
        methods.append((types[owner], strings[name], protos[proto]))
    return methods


def _touch_code_offset(data, methods):
    count, offset = struct.unpack_from('<II', data, 96)
    candidates = []
    native = methods.index(_NATIVE)
    for i in range(count):
        cursor = _u32(data, offset + i * 32 + 24)
        if not cursor:
            continue
        sizes = []
        for _ in range(4):
            size, cursor = _uleb(data, cursor)
            sizes.append(size)
        for _ in range(sizes[0] + sizes[1]):
            _, cursor = _uleb(data, cursor)
            _, cursor = _uleb(data, cursor)
        for size in sizes[2:]:
            method_id = 0
            for _ in range(size):
                delta, cursor = _uleb(data, cursor)
                method_id += delta
                flags, cursor = _uleb(data, cursor)
                code, cursor = _uleb(data, cursor)
                if not code or methods[method_id][1:] != ('onTouch', '(Landroid/view/View;Landroid/view/MotionEvent;)Z'):
                    continue
                body = data[code + 16:code + 16 + _u32(data, code + 12) * 2]
                call = struct.pack('<3H', 0x0677, native, 0)  # invoke-static/range {v0..v5}
                if call in body and not flags & 8:
                    candidates.append(code)
    if len(candidates) != 1:
        raise ValueError('Expected exactly one supported Android touch bridge')
    return candidates[0]


def _bind_original(methods):
    units = list(struct.unpack('<129H', _ORIGINAL))
    pc = 0
    while pc < len(units):
        opcode = units[pc] & 255
        if opcode in (0x6e, 0x77):
            units[pc + 1] = methods.index(_REFERENCE_IDS[units[pc + 1]])
            pc += 3
        else:
            pc += 2 if opcode in (0x38, 0x39, 0x32, 0x33, 0x35, 0xd8) else 1
    return struct.pack('<129H', *units)


def _dispatch(methods):
    units, labels, jumps = [], {}, []
    def emit(*words):
        units.extend(words)
    def mark(label):
        labels[label] = len(units)
    def branch(opcode, registers, label):
        jumps.append((len(units), label))
        emit(opcode | registers << 8, 0)
    def jump(label):
        branch(0x29, 0, label)  # goto/16
    def constant(register, value):
        emit(0x12 | register << 8 | value << 12)
    def invoke(name, proto, args, result):
        packed = sum(register << (i * 4) for i, register in enumerate(args))
        emit(0x6e | len(args) << 12, methods.index((_MOTION, name, proto)), packed)
        emit(0x0a | result << 8)

    invoke('getActionMasked', '()I', [10], 0)
    constant(6, 1)
    branch(0x38, 0, 'setup')
    branch(0x32, 0x60, 'setup')
    for action in (2, 3, 5, 6):
        constant(1, action)
        branch(0x32, 0x10, 'setup')
    mark('false')
    emit(0x090f)  # v9 is zero in the retained prelude
    mark('setup')
    invoke('getPointerCount', '()I', [10], 7)
    invoke('getActionIndex', '()I', [10], 8)
    mark('loop')
    branch(0x35, 0x79, 'done')
    invoke('getActionMasked', '()I', [10], 0)
    constant(1, 3)
    branch(0x32, 0x10, 'send')  # cancel every pointer
    constant(1, 0)
    branch(0x33, 0x89, 'send')  # surviving pointers are moves
    branch(0x38, 0, 'down')
    constant(1, 5)
    branch(0x32, 0x10, 'down')
    constant(1, 1)
    branch(0x32, 0x10, 'send')
    constant(1, 6)
    branch(0x32, 0x10, 'up')
    constant(1, 0)  # ACTION_MOVE
    jump('send')
    mark('down')
    constant(1, 2)
    jump('send')
    mark('up')
    constant(1, 1)
    mark('send')
    invoke('getPointerId', '(I)I', [10, 9], 0)
    invoke('getX', '(I)F', [10, 9], 2)
    invoke('getY', '(I)F', [10, 9], 3)
    emit(0x0677, methods.index(_NATIVE), 0)
    emit(0x09d8, 0x0109)  # add-int/lit8 v9, v9, 1
    jump('loop')
    mark('done')
    emit(0x060f)
    for pc, label in jumps:
        units[pc + 1] = (labels[label] - pc) & 65535
    if len(units) > 129:
        raise ValueError('Touch dispatch exceeds existing DEX code space')
    units.extend([0] * (129 - len(units)))
    return struct.pack('<129H', *units), 43 + labels['false'] - 3


def patch_touch_input(data):
    methods = _methods(data)
    try:
        code = _touch_code_offset(data, methods)
        original = _bind_original(methods)
        replacement, null_jump = _dispatch(methods)
    except (KeyError, ValueError) as error:
        raise ValueError('Unsupported Android touch shell') from error
    registers, inputs, outputs, tries, debug, size = struct.unpack_from('<4H2I', data, code)
    if (registers, inputs, outputs, tries, size) != (11, 3, 6, 0, 172):
        raise ValueError('Unsupported Android touch method layout')
    start = code + 16
    body = data[start + 86:start + 344]
    branch = struct.unpack_from('<H', data, start + 6)[0]
    if body == replacement and branch == (null_jump << 8 | 0x28) and debug == 0:
        return data
    if body != original or branch != 0x3d28 or data[start:start + 6] != bytes.fromhex('1209390a0300'):
        raise ValueError('Unrecognized Android touch dispatch; refusing to overwrite it')
    result = bytearray(data)
    result[start + 86:start + 344] = replacement
    struct.pack_into('<H', result, start + 6, null_jump << 8 | 0x28)
    struct.pack_into('<I', result, code + 8, 0)  # old source line mapping no longer applies
    result[12:32] = hashlib.sha1(result[32:]).digest()
    struct.pack_into('<I', result, 8, zlib.adler32(result[12:]) & 0xffffffff)
    return bytes(result)


def verify_touch_input(data):
    if patch_touch_input(data) != data:
        raise ValueError('APK still lacks synchronized multi-touch input')
