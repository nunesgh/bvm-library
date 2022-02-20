"""
Bayes Vulnerability for Microdata library
=========================================
Quantitative Information Flow assessment of vulnerability
for microdata datasets using Bayes Vulnerability.
"""

try:
    import numpy
except:
    raise Exception("numpy is required by bvmlib.")

try:
    import pandas
except:
    raise Exception("pandas is required by bvmlib.")

try:
    from bvmlib.bvm import BVM
except:
    raise Exception("bvmlib was not imported.")

__version__ = '1.0.0'
