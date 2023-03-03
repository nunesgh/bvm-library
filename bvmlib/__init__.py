"""
Bayes Vulnerability for Microdata library
=========================================
Quantitative Information Flow assessment of vulnerability
for microdata datasets using Bayes Vulnerability.

bvmlib - Bayes Vulnerability for Microdata library
Copyright (C) 2021 Gabriel Henrique Lopes Gomes Alves Nunes

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

try:
    from dataclasses import dataclass
except:
    raise Exception("dataclass is required by qifprivlib.")

try:
    import numpy
except:
    raise Exception("numpy is required by bvmlib.")

try:
    import pandas
except:
    raise Exception("pandas is required by bvmlib.")

try:
    from bvmlib.bvm import BVM, BVMLongitudinal
except:
    raise Exception("bvmlib was not imported.")

__version__ = '1.1.0'
