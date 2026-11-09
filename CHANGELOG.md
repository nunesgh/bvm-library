# Changelog

The notable changes in each version of `bvmlib`. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and from 2.0.0 the version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Code written for 1.1.0 can break: the **Histogram** format changes, invalid arguments raise exceptions instead of printing a message, and some arguments accepted before are refused. Results change for tables that hold missing values, and in the cases listed below.

### Changed

- Each **Histogram** is a dict of 100 bins, `'(0, 1]'` to `'(99, 100]'`, where 1.1.0 gave the text of a dict of 101 bins, `'0'` to `'100'`. A row whose chance is the probability p falls in the bin `(k - 1, k]` with k = ceil(100p), so no row falls in a bin for 0%. `results['bins']` uses the same bins. Code that parsed the old text needs updating. Fixes #4, by Luigi D. C. Soares in #5.
- Invalid arguments to `BVM()`, `BVMLongitudinal()`, `ids()`, `qids()`, `sensitive()`, `worth()` and `assess()` raise `TypeError` (an argument or entry of the wrong type) or `ValueError` (any other fault), with a message saying what is wrong. 1.1.0 printed a message and carried on, so a later call often failed instead. The two internal consistency checks raise `RuntimeError`.
- `assess()` before `qids()` raises `ValueError` ("The quasi-identifiers have not been defined yet."), where 1.1.0 printed a message and returned `None`.
- Missing values (`NaN`, `None`, `pandas.NA` and `NaT`) need not be filled: for re-identification and attribute inference, `BVM()` counts all the missing values of an attribute as one value of their own. Tables that hold missing values give different results from 1.1.0: rows with missing quasi-identifiers no longer form classes of their own (a numeric column made each such row a class of its own, and a text column split `None` from `NaN`), a sensitive attribute's `None`, `NaN` and `pandas.NA` count as one value and no longer merge with the text `'nan'`, the attribute-inference Prior counts them, and `pandas.NA` in a quasi-identifier no longer raises `TypeError`. This change leaves tables without missing values as they were. Fixes #2.
- The attribute-inference Prior counts sensitive values by their text, as the classes always did. For an attribute where equal values have different texts (`-0.0` and `0.0`; `1` and `1.0`, or `True` and `1`, in an object column) or different values share a text (`1` and `'1'` in an object column), the Prior, pCA and Prior Worth change, and dCA can change in either direction. The Posterior can no longer fall below the Prior.
- On pandas below 3, a categorical sensitive attribute no longer counts its unused categories.
- `results['bins']['re_id']` holds re-identification's bins alone. A sensitive attribute named `re_id` takes `'re_id (sensitive)'`, with `' (sensitive)'` added again while another sensitive attribute has that name; 1.1.0 merged the two into one dict.
- The result tables have number dtypes: pCR `int64`; dCR, dCA, pCA, Prior, Posterior, Prior Worth and Posterior Worth `float64`. QID and Sensitive are `object` on pandas below 3 and `str` on pandas 3. In 1.1.0, every column was `object` on pandas 3, and pCR was on earlier pandas.
- Information worth: missing values have a worth only under the key `None`, in the Prior Worth and the Posterior Worth alike, and a text key such as `'nan'` matches only that text. 1.1.0 matched missing values by their text in the Posterior Worth and ignored them in the Prior Worth. The Prior Worth counts values by their text, as the Prior does.
- `worth()` stores each worth as a float, so every kind of real number gives `float64` results. In 1.1.0, a `fractions.Fraction` gave an `object` column, and with NumPy 2 a small NumPy integer could overflow.
- `worth()`, `qids()`, `sensitive()` and `BVMLongitudinal()` keep their own copies of the lists and dictionaries they are given.
- `BVMLongitudinal()`: in the join, a missing value and a row absent from a later dataset count as two values of their own, distinct from each other and from every real value, and values holding `#` can no longer join into the same text. Results change only for tables whose quasi-identifiers hold missing values, the texts `nan`, `None`, `<NA>` or `NaT`, or `#`, and for integers above 2**53 in a later dataset that lacks some rows.
- `BVMLongitudinal()` merges only the identifier and the quasi-identifiers of each later dataset, renamed as in the focal dataset. After `qids()`, `quasi_identifiers` holds the focal dataset's list and `all_quasi_identifiers` every dataset's; after `assess()`, `dataset` holds the focal dataset with the joined quasi-identifiers.
- `BVMLongitudinal()`'s messages name the dataset by its number, from 1, as `ids()` does.
- Speed against 1.0.0, on pandas 1.5.3 and 200,000 rows for each dataset: `BVM().assess()` takes about as long (6% longer with 100,000 classes, 17% less with 1,000 classes and two sensitive attributes), and a `BVMLongitudinal()` assessment of three datasets 19 to 26% longer.
- The example notebook loads the US Census Data (1990) with `ucimlrepo`, which only that section needs; 1.1.0 downloaded it from an address of the UCI archive that no longer works. By Luigi D. C. Soares in #5.

### Added

- `qids()` and `sensitive()` refuse a name listed twice.
- `worth()` refuses a key that is neither a string nor `None` (`TypeError`), a worth that is not a real number (`TypeError`), and an infinite or `NaN` worth, or one too large for a float (`ValueError`).
- `BVMLongitudinal.qids([])` assigns no quasi-identifiers, and `assess()` then returns `None`, as `BVM.qids([])` already did. `sensitive([])` assigns no sensitive attributes, and `assess()` then gives re-identification only.
- `BVMLongitudinal()` takes an identifier given as a list holding one string, and refuses a list of several identifiers for one dataset.
- `BVMLongitudinal()` refuses empty lists of datasets and identifiers; `BVMLongitudinal.qids()` refuses lists whose number differs from the number of datasets, lists of different lengths, and empty lists for the datasets.
- With two or more datasets, `BVMLongitudinal()` refuses a sensitive attribute that is also a quasi-identifier of the focal dataset, and a dataset's identifier among its own quasi-identifiers (`ValueError`).
- Tests, run with `pytest`, and licensing information for every file, following [REUSE](https://reuse.software/).

### Fixed

- `BVMLongitudinal.assess()` works with sensitive attributes; 1.1.0 raised `AttributeError` whenever they were set.
- `worth()` on an attribute that is not a sensitive attribute raises `ValueError`; 1.1.0 raised `NameError`.
- `BVMLongitudinal()` works with three or more datasets with their own column names, and with one list of quasi-identifiers for all the datasets, where 1.1.0 raised `KeyError`; and with later datasets holding columns named like the focal dataset's.
- `BVMLongitudinal.assess()` can be called more than once.
- `BVM` and `BVMLongitudinal` objects compare and hash by identity. Since 1.1.0, any two of them compared equal, and none could be put in a set or used as a dictionary key.
- `assess()` no longer warns on pandas 2 and 3.
- `ids()` of `BVMLongitudinal()` prints "Identifying" instead of "Indetifying".
- The licence notices in the source files name the GNU Lesser General Public License, the library's licence; 1.1.0's named the GNU General Public License. `setup.py` and `CITATION.cff` declare `LGPL-3.0-or-later`.
- An import error names `bvmlib`.

### Removed

- numpy as a direct dependency; pandas still installs it.

## [1.1.0] - 2024-03-24

### Added

- Information worth: `worth()` assigns worths to the values of a sensitive attribute, and `assess()` then returns their Prior Worth and Posterior Worth in `information_worth`, as proposed in M. S. Alvim, A. Scedrov and F. B. Schneider, "When Not All Bits Are Equal: Worth-Based Information Flow", Principles of Security and Trust, 2014.
- `CITATION.cff`.

### Changed

- Requires Python 3.10.6 or later, numpy 1.24.2 or later and pandas 1.5.3 or later.

### Fixed

- dCA was 0 where it should be 1 when the sensitive attribute is a function of the quasi-identifiers. Fixes #1.

## [1.0.0] - 2022-05-09

The first release, archived on Zenodo as [10.5281/zenodo.6533704](https://doi.org/10.5281/zenodo.6533704).

[Unreleased]: https://github.com/nunesgh/bvm-library/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/nunesgh/bvm-library/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/nunesgh/bvm-library/releases/tag/v1.0.0
