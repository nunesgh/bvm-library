# BVM library

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.6533704.svg)](https://doi.org/10.5281/zenodo.6533704)

Quantitative Information Flow assessment of vulnerability for microdata datasets using Bayes Vulnerability.

DOI: [10.5281/zenodo.6533704](https://doi.org/10.5281/zenodo.6533704).

This repository provides an implementation of the paper [*Flexible and scalable privacy assessment for very large datasets, with an application to official governmental microdata*](https://petsymposium.org/popets/2022/popets-2022-0114.php) (DOI: [10.56553/popets-2022-0114](https://doi.org/10.56553/popets-2022-0114), arXiv: [2204.13734](https://arxiv.org/abs/2204.13734)) that appeared in [PoPETs 2022](https://petsymposium.org/popets/2022/), and of the masters thesis [*A formal quantitative study of privacy in the publication of official educational censuses in Brazil*](https://repositorio.ufmg.br/handle/1843/38085) (DOI: [hdl:1843/38085](https://doi.org/hdl:1843/38085)). Please refer to the folder [examples](https://github.com/nunesgh/bvm-library/tree/main/examples#inep-1-experiments) for the Notebooks containing the actual results for the experiments performed.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install `bvmlib`.

```bash
pip install bvmlib
```

## Usage

**Warning: Please fill `NA` and `NaN` values!**

A fix will be provided in a later version.

Meanwhile, consider using the pandas `.fillna()` [method](https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.fillna.html) before calling the `BVM()` class, e.g. when creating the pandas DataFrame, as shown below.

### Single-dataset

```python
import pandas
from bvmlib.bvm import BVM

# Create a pandas DataFrame for your data.
# For instance:
df = pandas.read_csv(file.csv).fillna(-1)

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

### Additional examples

Please refer to the folder [examples](https://github.com/nunesgh/bvm-library/blob/main/examples) for additional usage examples, including attacks on longitudinal collections of datasets.

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

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[GNU LGPLv3](https://choosealicense.com/licenses/lgpl-3.0/) [^compatibility].

[^compatibility]:
    To understand how the various GNU licenses are compatible with each other, please refer to:

    https://www.gnu.org/licenses/gpl-faq.html#AllCompatibility
