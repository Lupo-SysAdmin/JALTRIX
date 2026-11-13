"""Render the owner-supplied SVGs with librsvg; no image generation or network."""

from pathlib import Path
import gi

gi.require_version("Rsvg", "2.0")
from gi.repository import Rsvg
import cairo

ROOT = Path(__file__).resolve().parents[1]


def render(source, destination, size):
    svg = Rsvg.Handle.new_from_file(str(source))
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
    context = cairo.Context(surface)
    viewport = Rsvg.Rectangle()
    viewport.x = 0
    viewport.y = 0
    viewport.width = size
    viewport.height = size
    svg.render_document(context, viewport)
    surface.write_to_png(str(destination))


for name in ("icon", "logo", "emblem"):
    render(
        ROOT / f"src/jaltrix/ui/app-{name}.svg",
        ROOT / f"src/jaltrix/ui/app-{name}.png",
        512 if name == "icon" else 700,
    )
