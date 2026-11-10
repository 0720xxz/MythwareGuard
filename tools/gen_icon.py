#!/usr/bin/env python3
"""Generate guard.ico (multi-size, 32bpp BMP entries) without PIL."""
import struct

SIZES = [16, 24, 32, 48, 64]

BG_TOP = (13, 40, 92)      # deep navy
BG_BOT = (30, 108, 214)    # bright blue
EDGE = (235, 244, 255)
LOCK = (255, 255, 255)


def lerp(a, b, t):
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))


def shield_halfwidth(v):
    """Half width of the shield outline at vertical position v (0..1)."""
    if v < 0.06:
        t = v / 0.06
        return 0.30 + 0.06 * t
    if v < 0.52:
        return 0.36
    t = (v - 0.52) / 0.48
    if t >= 1.0:
        return 0.0
    return 0.36 * (1.0 - t ** 1.7)


def sample(u, v):
    """Return RGBA for normalised coords."""
    half = shield_halfwidth(v)
    du = abs(u - 0.5)

    if v > 0.98 or v < 0.02 or half <= 0:
        return (0, 0, 0, 0)

    edge = du <= half
    inner = du <= (half - 0.045)

    if edge and not inner:
        return EDGE + (255,)
    if not edge:
        return (0, 0, 0, 0)

    base = lerp(BG_TOP, BG_BOT, min(1.0, max(0.0, (v - 0.05) / 0.9)))
    # keyhole: circle plus stem
    cx, cy, r = 0.5, 0.40, 0.11
    d = ((u - cx) ** 2 + (v - cy) ** 2) ** 0.5
    if d <= r:
        return LOCK + (255,)
    if abs(u - 0.5) <= 0.038 and 0.40 <= v <= 0.60:
        return LOCK + (255,)
    return base + (255,)


def render(size, ss=4):
    pix = []
    for y in range(size):
        row = []
        for x in range(size):
            acc = [0.0, 0.0, 0.0, 0.0]
            for sy in range(ss):
                for sx in range(ss):
                    u = (x + (sx + 0.5) / ss) / size
                    v = (y + (sy + 0.5) / ss) / size
                    r, g, b, a = sample(u, v)
                    af = a / 255.0
                    acc[0] += r * af
                    acc[1] += g * af
                    acc[2] += b * af
                    acc[3] += af
            n = ss * ss
            a = acc[3] / n
            if a <= 0.003:
                row.append((0, 0, 0, 0))
            else:
                row.append((
                    int(round(acc[0] / acc[3])),
                    int(round(acc[1] / acc[3])),
                    int(round(acc[2] / acc[3])),
                    int(round(a * 255)),
                ))
        pix.append(row)
    return pix


def bmp_entry(size):
    pix = render(size)
    xor = bytearray()
    for y in range(size - 1, -1, -1):          # bottom-up
        for x in range(size):
            r, g, b, a = pix[y][x]
            xor += bytes((b, g, r, a))
    mask_row = ((size + 31) // 32) * 4
    mask = bytearray()
    for y in range(size - 1, -1, -1):
        row = bytearray(mask_row)
        for x in range(size):
            if pix[y][x][3] < 128:
                row[x >> 3] |= 0x80 >> (x & 7)
        mask += row
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0,
                         len(xor) + len(mask), 0, 0, 0, 0)
    return header + bytes(xor) + bytes(mask)


def main(out="guard.ico"):
    images = [(s, bmp_entry(s)) for s in SIZES]
    dir_entries = bytearray()
    offset = 6 + 16 * len(images)
    blob = bytearray()
    for size, data in images:
        b = 0 if size >= 256 else size
        dir_entries += struct.pack("<BBBBHHII", b, b, 0, 0, 1, 32, len(data), offset)
        blob += data
        offset += len(data)
    ico = struct.pack("<HHH", 0, 1, len(images)) + bytes(dir_entries) + bytes(blob)
    with open(out, "wb") as f:
        f.write(ico)
    print(f"wrote {out}: {len(ico)} bytes, sizes={SIZES}")


if __name__ == "__main__":
    main()
