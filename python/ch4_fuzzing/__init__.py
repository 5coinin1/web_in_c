"""Chapter 4 -- dynamic analysis (coverage, black-box and white-box fuzzing)."""
from .build import build_target, asan_available, repo_root, work_dir, Target
from .fuzzing import (
    black_box_fuzz, coverage_guided_fuzz, measure_coverage,
    reset_gcda, run_target, is_crash, FuzzResult,
)
from .seeds import seed_corpus, write_seed_dir, header, record, MAGIC
from .whitebox import structural_gate, structural_deep, structural_crash, z3_solve_gate

__all__ = [
    "build_target", "asan_available", "repo_root", "work_dir", "Target",
    "black_box_fuzz", "coverage_guided_fuzz", "measure_coverage",
    "reset_gcda", "run_target", "is_crash", "FuzzResult",
    "seed_corpus", "write_seed_dir", "header", "record", "MAGIC",
    "structural_gate", "structural_deep", "structural_crash", "z3_solve_gate",
]
