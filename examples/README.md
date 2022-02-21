# BVM library examples

For Python to properly import `bvmlib` into the Notebooks, remember to have either installed `bvmlib` via `pip` or to have a copy of the root folder within the examples folder, i.e.
```
- examples/
    - setup.py
    - bvmlib/
        - __init__.py
        - bvm.py
```

The `inep-school-2018` example computes the Bayes Vulnerability for the whole powerset of the 11 chosen quasi-identifiers. The Notebook was run on a machine with 40 threads and 441G of memory. Time performance was prioritized over memory, so the execution of all the 2,047 subsets of the powerset took 8 hours and 53 minutes, but used more than 400G of memory. The number of threads used, and hence the total memory, can be changed by setting a different value for `pool_size`.
