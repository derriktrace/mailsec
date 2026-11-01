"""Bounded local OCR. Image decoders run in the already resource-limited worker.

Only fixed local binaries are invoked, without a shell. URLs and document actions
are never followed. A shared deadline prevents many attachments exhausting the
whole parser timeout and losing previously collected evidence.
"""

import shutil
import subprocess
import tempfile
import time
from pathlib import Path


class OCRFailure(Exception):
    pass


class OCRBudget:
    def __init__(self, limits):
        self.deadline = time.monotonic() + limits.get("max_ocr_seconds", 10)
        self.remaining = limits.get("max_ocr_images", 8)

    def claim(self):
        if self.remaining <= 0 or time.monotonic() >= self.deadline:
            raise OCRFailure("ocr_budget_limit")
        self.remaining -= 1

    def timeout(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise OCRFailure("ocr_budget_limit")
        return min(4, remaining)


def _command(name, args, budget, *, output_limit=65536):
    binary = shutil.which(name, path="/usr/bin:/bin")
    if binary is None:
        raise OCRFailure("ocr_engine_unavailable" if name == "tesseract" else "pdf_renderer_unavailable")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                   "OMP_THREAD_LIMIT": "1"}
    with tempfile.TemporaryFile() as output:
        try:
            process = subprocess.run([binary, *args], stdin=subprocess.DEVNULL, stdout=output,
                                     stderr=subprocess.DEVNULL, env=environment, timeout=budget.timeout(),
                                     check=False)
        except subprocess.TimeoutExpired as exc:
            raise OCRFailure("ocr_operation_timeout") from exc
        except OSError as exc:
            raise OCRFailure("ocr_operation_failed") from exc
        if process.returncode != 0:
            raise OCRFailure("ocr_operation_failed")
        output.seek(0)
        value = output.read(output_limit + 1)
        if len(value) > output_limit:
            raise OCRFailure("ocr_output_limit")
        return value


def read_image(image, budget, *, languages="eng+por+spa"):
    """Return text plus confidence; no recognized text does not imply safety."""
    budget.claim()
    # Bound both tesseract's decoded image and the on-disk interchange image.
    with tempfile.TemporaryDirectory(prefix="mailsec-ocr-") as directory:
        path = Path(directory) / "image.png"
        rgb = image.convert("RGB")
        try:
            rgb.thumbnail((2000, 2000))
            rgb.save(path, "PNG")
        finally:
            rgb.close()
        value = _command("tesseract", [str(path), "stdout", "-l", languages, "--psm", "11", "tsv"], budget)
    words, confidences = [], []
    for line in value.decode("utf-8", errors="replace").splitlines()[1:]:
        fields = line.split("\t", 11)
        if len(fields) == 12 and fields[11].strip():
            words.append(fields[11].strip())
            try:
                confidence = float(fields[10])
                if confidence >= 0:
                    confidences.append(confidence)
            except ValueError:
                pass
    return " ".join(words), (round(sum(confidences) / len(confidences), 1) if confidences else None)


def render_pdf_page(data, page_number, budget):
    """Rasterize one page only, without JavaScript/action execution or networking."""
    from PIL import Image

    with tempfile.TemporaryDirectory(prefix="mailsec-pdf-") as directory:
        source, target = Path(directory) / "input.pdf", Path(directory) / "page"
        source.write_bytes(data)
        _command("pdftoppm", ["-f", str(page_number), "-l", str(page_number), "-singlefile", "-scale-to",
                              "2000", "-png", str(source), str(target)], budget, output_limit=1024)
        image_path = target.with_suffix(".png")
        if not image_path.exists() or image_path.stat().st_size > 16 * 1024 * 1024:
            raise OCRFailure("pdf_render_output_limit")
        with Image.open(image_path) as image:
            if image.width * image.height > 4_000_000:
                raise OCRFailure("pdf_render_pixel_limit")
            return image.copy()
