"""Generate the PhishGuard icon set (PIL only).

Writes extension/icons/{icon,warn,danger}-{16,32,48,128}.png and logo.png
  icon   = blue shield + check   (default / safe)
  warn   = amber shield + '!'    (suspicious)
  danger = red shield + cross    (dangerous)
Run:  python tools/make_icons.py
"""
import os
from PIL import Image, ImageDraw, ImageFilter

S = 1024  # master canvas; downsampled with LANCZOS for crisp small sizes
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "extension", "icons")
os.makedirs(OUT, exist_ok=True)

THEMES = {
    "icon":   {"top": (66, 133, 244), "bottom": (16, 40, 86),  "rim": (190, 215, 255)},
    "warn":   {"top": (255, 196, 60), "bottom": (190, 105, 10), "rim": (255, 232, 170)},
    "danger": {"top": (240, 92, 80),  "bottom": (140, 22, 28),  "rim": (255, 190, 185)},
}


def bez(p0, p1, p2, p3, n=60):
    pts = []
    for i in range(n + 1):
        t = i / n
        a, b, c, d = (1 - t) ** 3, 3 * (1 - t) ** 2 * t, 3 * (1 - t) * t ** 2, t ** 3
        pts.append((a * p0[0] + b * p1[0] + c * p2[0] + d * p3[0], a * p0[1] + b * p1[1] + c * p2[1] + d * p3[1]))
    return pts


def shield(scale=1.0):
    """Shield outline as a polygon; scale shrinks it toward the centre."""
    T, R, B, L = (512, 62), (878, 196), (512, 968), (146, 196)
    pts = (bez(T, (650, 128), (770, 186), R) + bez(R, (878, 580), (730, 840), B)[1:]
           + bez(B, (294, 840), (146, 580), L)[1:] + bez(L, (254, 186), (374, 128), T)[1:])
    cx, cy = 512, 520
    return [(cx + (x - cx) * scale, cy + (y - cy) * scale) for x, y in pts]


def gradient(top, bottom):
    img = Image.new("RGB", (S, S))
    px = img.load()
    for y in range(S):
        t = min(1, max(0, (y - 60) / 910))
        c = tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3))
        for x in range(S):
            px[x, y] = c
    return img


def round_line(draw, pts, width, fill):
    draw.line(pts, fill=fill, width=width, joint="curve")
    r = width // 2
    for x, y in (pts[0], pts[-1]):
        draw.ellipse((x - r, y - r, x + r, y + r), fill=fill)


def glyph(kind):
    """White glyph on a transparent layer."""
    layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    w = (255, 255, 255, 255)
    if kind == "icon":      # check mark
        pts = [(292, 530), (446, 684), (742, 366)]
        round_line(d, pts, 104, w)
        d2 = ImageDraw.Draw(layer)
        d2.line(pts, fill=w, width=104, joint="curve")
    elif kind == "warn":    # exclamation mark
        d.rounded_rectangle((462, 270, 562, 600), radius=50, fill=w)
        d.ellipse((452, 660, 572, 780), fill=w)
    else:                   # cross
        round_line(d, [(350, 360), (674, 684)], 100, w)
        round_line(d, [(674, 360), (350, 684)], 100, w)
    return layer


def render(name):
    th = THEMES[name]
    canvas = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # soft drop shadow
    sh = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(sh).polygon([(x + 0, y + 22) for x, y in shield()], fill=(0, 0, 0, 120))
    canvas.alpha_composite(sh.filter(ImageFilter.GaussianBlur(22)))

    # gradient body
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).polygon(shield(), fill=255)
    body = gradient(th["top"], th["bottom"]).convert("RGBA")
    body.putalpha(mask)
    canvas.alpha_composite(body)

    # glossy sheen on the upper left
    sheen = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(sheen).ellipse((-120, -260, 760, 520), fill=(255, 255, 255, 60))
    sheen.putalpha(Image.composite(sheen.getchannel("A"), Image.new("L", (S, S), 0), mask))
    canvas.alpha_composite(sheen)

    # inner rim
    rim = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(rim).line(shield(0.90) + [shield(0.90)[0]], fill=th["rim"] + (150,), width=14, joint="curve")
    canvas.alpha_composite(rim)

    # glyph with its own soft shadow
    g = glyph(name)
    gs = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    gs.paste((0, 0, 0, 110), mask=g.getchannel("A").transform((S, S), Image.AFFINE, (1, 0, 0, 0, 1, -16)))
    canvas.alpha_composite(gs.filter(ImageFilter.GaussianBlur(14)))
    canvas.alpha_composite(g)
    return canvas


for name in THEMES:
    master = render(name)
    for size in (16, 32, 48, 128):
        master.resize((size, size), Image.LANCZOS).save(os.path.join(OUT, f"{name}-{size}.png"))
    if name == "icon":
        master.resize((256, 256), Image.LANCZOS).save(os.path.join(OUT, "logo.png"))
print("icons written to", os.path.abspath(OUT))
