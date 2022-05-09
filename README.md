# BVM library

Quantitative Information Flow assessment of vulnerability for microdata datasets using Bayes Vulnerability.

DOI: [10.5281/zenodo.6533704](https://doi.org/10.5281/zenodo.6533704).

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install `bvmlib`.

```bash
pip install bvmlib
```

## Usage

### Single-dataset

```python
import pandas
from bvmlib.bvm import BVM

# Create a pandas DataFrame for your data.
# For instance:
df = pandas.read_csv(file.csv)

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

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[GNU LGPLv3](https://choosealicense.com/licenses/lgpl-3.0/) [^compatibility]

[^compatibility]:
    To understand how the various GNU licenses are compatible with each other, please refer to:
    
    https://www.gnu.org/licenses/gpl-faq.html#AllCompatibility
