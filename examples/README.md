# BVM library examples

For Python to properly import `bvmlib` into the Notebooks, remember to have either installed `bvmlib` via [pip](https://pip.pypa.io/en/stable/) or to have a copy of the root folder within the examples folder, i.e.

```
- examples/
    - setup.py
    - bvmlib/
        - __init__.py
        - bvm.py
```

## General examples

### single-dataset.ipynb

This example computes both deterministic and probabilistic Bayes Vulnerability for both re-identification and attribute-inference attacks of two publicly available datasets: the [Adult dataset](https://archive.ics.uci.edu/ml/datasets/Adult) and the [US Census Data (1990) dataset](https://archive.ics.uci.edu/ml/datasets/US+Census+Data+%281990%29).

For the Adult dataset, the following attributes are used as quasi-identifiers: `age`, `sex`, `race`, `native-country`, `marital-status`, `workclass`, and `occupation`. Also, the following attributes are used as sensitive attributes: `relationship` and `education-num`.

For the US Census Data (1990) dataset, the following attributes are used as quasi-identifiers: `dAge`, `dAncstry1`, `dAncstry2`, `iClass`, `iEnglish`, `dHour89`, `iLang1`, `iMarital`, `iMeans`, `dOccup`, `dPOB`, and `iSex`. Also, the following attributes are used as sensitive attributes: `iCitizen` and `dRearning`. All the attributes are briefly described within the notebook.

## INEP [^inep] experiments

The following examples are the actual results for the experiments performed as part of the following publications:
- Gabriel H. Nunes - _A formal quantitative study of privacy in the publication of official educational censuses in Brazil_ (2021, [hdl:1843/38085](https://doi.org/hdl:1843/38085)).
- Mário S. Alvim, Natasha Fernandes, Annabelle McIver, Carroll Morgan, Gabriel H. Nunes - _Flexible and scalable privacy assessment for very large datasets, with an application to official governmental microdata_ (2022, [10.48550/arXiv.2204.13734](https://doi.org/10.48550/arXiv.2204.13734)). For this publication, also refer to [10.5281/zenodo.6533684](https://doi.org/10.5281/zenodo.6533684) ([github.com/nunesgh/inep-anonymization](https://github.com/nunesgh/inep-anonymization)).

We randomly selected only one record for each student with a same unique pseudonymization code (`ID_ALUNO`) in each dataset. The enrollment code (`ID_MATRICULA`) for each selected record is available in [10.5281/zenodo.6533675](https://doi.org/10.5281/zenodo.6533675) ([gitlab.com/nunesgh/inep-enrollment-codes](https://gitlab.com/nunesgh/inep-enrollment-codes)).

### inep-school-2018.ipynb

The `inep-school-2018` example computes both deterministic and probabilistic Bayes Vulnerability for both re-identification and attribute-inference single-dataset attacks for the whole powerset of the 11 chosen quasi-identifiers. This particular version of the notebook was run on a machine with 40 CPU threads and 441G of random-access memory. Time performance was prioritized over memory, so the execution of all the 2,047 subsets of the powerset took 8 hours and 53 minutes, but used more than 400G of memory. The number of threads used, and hence the total memory, can be changed by setting a different value for the variable `pool_size`.

### inep-school-2014-2017.ipynb

The `inep-school-2014-2017` example computes both deterministic and probabilistic Bayes Vulnerability for both re-identification and attribute-inference longitudinal-dataset attacks for the following quasi-identifiers: `FK_COD_MUNICIPIO_END` / `CO_MUNICIPIO_END`, `PK_COD_ENTIDADE` / `CO_ENTIDADE`, `FK_COD_ETAPA_ENSINO` / `TP_ETAPA_ENSINO`. Also, the following attributes are used as sensitive attributes: `ID_POSSUI_NEC_ESPECIAL` and `ID_N_T_E_P`. All the attributes are briefly described within the notebook.

[^inep]:
    The [Anísio Teixeira National Institute of Educational Studies and Research](https://www.gov.br/INEP).
