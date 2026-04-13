"""
setup_ext.py - build the _array_tree Cython extension in-place.

Run from the inference/ directory:
    python setup_ext.py build_ext --inplace

Produces _array_tree.cpython-3*.so (Linux) or _array_tree.pyd (Windows)
in the same directory.  online_detector.py imports it at module load time
and falls back to pure-Python implementations if the .so is absent.
"""

from setuptools import setup
from Cython.Build import cythonize
import numpy as np

setup(
    name="_array_tree",
    ext_modules=cythonize(
        "_array_tree.pyx",
        compiler_directives={
            "boundscheck":  False,
            "wraparound":   False,
            "cdivision":    True,
            "language_level": "3",
            "initializedcheck": False,  # skip memoryview init check
        },
        annotate=False,
    ),
    include_dirs=[np.get_include()],
)
