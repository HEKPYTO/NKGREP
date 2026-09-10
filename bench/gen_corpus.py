"""Deterministic synthetic corpus. No hidden files, no gitignore, all UTF-8 text,
so walker differences between tools vanish and the oracle compares pure search."""
import random
import shutil
from pathlib import Path

SEED = 7
PKGS = 20
FILES_PER_PKG = 150
LINES_PER_FILE = 40
WORDS = ("config loader parser render cache token stream buffer node edge route "
         "table index query parse handle request reply frame packet socket port").split()

OUT = Path(__file__).parent / "corpus"


def main():
    rng = random.Random(SEED)
    if OUT.exists():
        shutil.rmtree(OUT)
    planted_alpha = 0
    planted_needles = {1: 0, 2: 0, 3: 0}
    for pkg in range(PKGS):
        d = OUT / f"pkg_{pkg:02d}" / ("deep" if pkg % 5 == 4 else "flat")
        d.mkdir(parents=True)
        for f in range(FILES_PER_PKG):
            p = d / f"mod_{f:03d}.txt"
            lines = []
            for ln in range(LINES_PER_FILE):
                lines.append(" ".join(rng.choice(WORDS) for _ in range(12)))
            r = rng.random()
            if r < 0.05:
                lines[rng.randrange(LINES_PER_FILE)] += " TODO_FIXME_ALPHA"
                planted_alpha += 1
            if r < 0.03:
                k = rng.choice([1, 2, 3])
                lines[rng.randrange(LINES_PER_FILE)] += f" needle_{k}"
                planted_needles[k] += 1
            if pkg % 5 == 4 and f % 10 == 0:
                lines[rng.randrange(LINES_PER_FILE)] = "fn parse_config(x: int) -> bool"
            p.write_text("\n".join(lines) + "\n")
    print(f"files={PKGS * FILES_PER_PKG} alpha_lines={planted_alpha} needles={planted_needles}")


if __name__ == "__main__":
    main()
