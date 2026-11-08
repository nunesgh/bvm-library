# BVM library

[![DOI (v1.0)](https://zenodo.org/badge/DOI/10.5281/zenodo.6533704.svg)](https://doi.org/10.5281/zenodo.6533704)

Quantitative Information Flow assessment of vulnerability for microdata datasets using Bayes Vulnerability.

DOI (v1.0): [10.5281/zenodo.6533704](https://doi.org/10.5281/zenodo.6533704).

This repository provides an implementation of the paper [*Flexible and scalable privacy assessment for very large datasets, with an application to official governmental microdata*](https://petsymposium.org/popets/2022/popets-2022-0114.php) (DOI: [10.56553/popets-2022-0114](https://doi.org/10.56553/popets-2022-0114), arXiv: [2204.13734](https://arxiv.org/abs/2204.13734)) that appeared in [PoPETs 2022](https://petsymposium.org/popets/2022/), and of the masters thesis [*A formal quantitative study of privacy in the publication of official educational censuses in Brazil*](https://repositorio.ufmg.br/handle/1843/38085) (DOI: [hdl:1843/38085](https://doi.org/hdl:1843/38085)). Please refer to the folder [examples](https://github.com/nunesgh/bvm-library/tree/main/examples#inep-1-experiments) for the Notebooks containing the actual results for the experiments performed.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install `bvmlib`.

```bash
pip install bvmlib
```

## Usage

From version 1.2.0, missing values (`NaN`, `None`, `pandas.NA` and `NaT`, as `pandas.isna` detects them) need not be filled: for re-identification and attribute inference, `BVM()` counts all the missing values of a quasi-identifying or sensitive attribute as one value of their own, distinct from every other value. With two or more datasets, `BVMLongitudinal()` joins the quasi-identifiers of all the datasets, and in the join a missing value and a row absent from a later dataset count as two values of their own, distinct from each other and from every real value, such as the text `nan` or `None`. Earlier versions need missing values filled first, for instance with the pandas `.fillna()` [method](https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.fillna.html).

From version 1.2.0, `BVM()`, `BVMLongitudinal()` and their methods check their arguments and raise `TypeError` or `ValueError`, with a message saying what is wrong, for instance for an attribute that is not in the dataset. Earlier versions print the message instead.

### Single-dataset

```python
import pandas
from bvmlib.bvm import BVM

# Create a pandas DataFrame for your data.
# For instance:
df = pandas.read_csv('file.csv')

# Create an instance.
I = BVM(df)

# Assign quasi-identifying attributes.
I.qids(['attribute_1','attribute_2'])

# Assign sensitive attributes (optional).
I.sensitive(['attribute_2','attribute_3'])

# Perform vulnerability assessment.
I_results = I.assess()

# Print re-identification results.
print(I_results['re_id'])

# Print attribute-inference results (only if computed).
print(I_results['att_inf'])
```

Optionally, after `I.sensitive()`, `I.worth('attribute_3', {'a': 1, 'b': 2, None: 0.5})` assigns worths to values of the sensitive attribute `attribute_3` (one call for each attribute to weigh), and `I.assess()` then also returns `I_results['information_worth']`, with the **Prior Worth** and **Posterior Worth** of each attribute given worths. Values are matched by their text, `str(value)`, so a column of floats needs keys such as `'1.0'`, and a value with no key has no worth. From version 1.2.0, missing values are matched by the key `None`, a key that is neither a string nor `None` raises `TypeError`, and each worth must be a finite number, zero or more.

### Additional examples

Please refer to the folder [examples](https://github.com/nunesgh/bvm-library/blob/main/examples) for additional usage examples, including attacks on longitudinal collections of datasets. For those, `BVMLongitudinal()` takes one identifying attribute for each dataset, as a string or, from version 1.2.0, as a list holding one string, which is how the `inep-school-2014-2017` example gives them.

### Note on the results

For privacy assessment of Collective Re-identification (**CRS** / **CRL**), for each list of quasi-identifying attributes (**QID**), the following results are computed:
- **dCR**: corresponds to the deterministic metric;
- **pCR**: corresponds to the probabilistic metric;
- **Prior**: corresponds to the adversary's prior knowledge in a probabilistic attack;
- **Posterior**: corresponds to the adversary's posterior knowledge in a probabilistic attack;
- **Histogram**: corresponds to the distribution of individuals according to the chance of re-identification.

For privacy assessment of Collective (sensitive) Attribute-inference (**CAS** / **CAL**), for each list of quasi-identifying attributes (**QID**) and for each sensitive attribute (**Sensitive**), the following results are computed:
- **dCA**: corresponds to the deterministic metric;
- **pCA**: corresponds to the probabilistic metric;
- **Prior**: corresponds to the adversary's prior knowledge in a probabilistic attack;
- **Posterior**: corresponds to the adversary's posterior knowledge in a probabilistic attack;
- **Histogram**: corresponds to the distribution of individuals according to the chance of attribute-inference.

From version 1.2.0, each **Histogram** is a dict of 100 bins, `'(0, 1]'` to `'(99, 100]'`: a row whose chance of re-identification, or of attribute-inference, is the probability p falls in the bin `(k - 1, k]` with k = ceil(100p), and each bin holds the fraction of all the rows that fall in it. Earlier versions give it as the text of a dict of 101 bins, `'0'` to `'100'`. `assess()` also returns these bins in `I_results['bins']`: re-identification's under `'re_id'`, and each sensitive attribute's under its name, except that a sensitive attribute named `re_id` takes `'re_id (sensitive)'`, with `' (sensitive)'` added again while another sensitive attribute has that name.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate. The tests are in the folder `tests`. To run them, install pandas and [pytest](https://docs.pytest.org/), then run `pytest` from the repository root, which needs no installation of `bvmlib`:

```bash
pip install pandas pytest
pytest
```

## License

[GNU LGPLv3](https://choosealicense.com/licenses/lgpl-3.0/), or any later version (`LGPL-3.0-or-later`). This project is [REUSE-compliant](https://reuse.software/).

To understand how the various GNU licenses are compatible with each other, please refer to the GNU licenses [FAQ](https://www.gnu.org/licenses/gpl-faq.html#AllCompatibility).
