# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2021-2026 Gabriel Henrique Lopes Gomes Alves Nunes

"""
Bayes Vulnerability for Microdata library
=========================================
Quantitative Information Flow assessment of vulnerability
for microdata datasets using Bayes Vulnerability.

bvmlib - Bayes Vulnerability for Microdata library
Copyright (C) 2021 Gabriel Henrique Lopes Gomes Alves Nunes

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from dataclasses import dataclass
import math
import numbers
import pandas

# Stands in for every missing value (pandas.isna) of an assessed column, so that they count as one
# value of their own (GitHub issue #2). Rows are matched against it by identity.
_MISSING = float('nan')

# The key of the re-identification bins until assess() returns them under 're_id'. It is not a
# string, so no sensitive attribute shares it, whatever its name.
_RE_ID = None

# The longitudinal join's text for a missing value and for a row absent from a later dataset. The
# join writes every other value as its text with each '\' and '#' escaped by '\', so that no value
# reads as either of them, and no two lists of values joined by '#' give the same text.
_JOINED_MISSING = '\\missing'
_JOINED_ABSENT = '\\absent'

def _joined_text(column):
    "The text of each value of column for the longitudinal join, as a Series of strings."

    missing = column.isna().to_numpy()
    values = column.to_numpy(dtype=object)
    return pandas.Series(
        [_JOINED_MISSING if is_missing else str(value).replace('\\', '\\\\').replace('#', '\\#')
         for value, is_missing in zip(values, missing)], index=column.index)

@dataclass
class BVM():
    "Bayes Vulnerability for Microdata class dedicated to single-dataset vulnerability assessment."

##### Constructor for single-dataset attacks.

    def __init__(self, dataset):
        "BVM(pandas.DataFrame): Initializes BVM class for single-dataset attacks."
        "Raises TypeError if dataset is not a pandas DataFrame, ValueError if it is empty."

        if type(dataset) is not pandas.DataFrame:
            raise TypeError("The dataset must be a pandas DataFrame.")
        if dataset.empty:
            raise ValueError("The dataset cannot be empty.")

        self.dataset = dataset
        self.identifiers = None
        self.quasi_identifiers = None
        self.sensitive_attributes = None
        self.worth_assignment = None

##### Public methods for single-dataset attacks.

    def ids(self, identifiers):
        "self.ids(['id_1',])"
        "Raises TypeError unless given a list of strings, ValueError for one not in the dataset."

        if type(identifiers) is not list:
            raise TypeError("A list of strings must be provided.")
        for i in identifiers:
            if type(i) is not str:
                raise TypeError("A list of strings must be provided.")
            elif i not in self.dataset.columns:
                raise ValueError(f"{i} is not an attribute of the dataset.")

        self.identifiers = identifiers

    def qids(self, quasi_identifiers):
        "self.qids(['quasi_identifier_1','quasi_identifier_2',])"
        "Raises TypeError unless given a list of strings, ValueError for one not in the dataset."

        if type(quasi_identifiers) is not list:
            raise TypeError("A list of strings must be provided.")
        for qid in quasi_identifiers:
            if type(qid) is not str:
                raise TypeError("A list of strings must be provided.")
            elif qid not in self.dataset.columns:
                raise ValueError(f"{qid} is not an attribute of the dataset.")

        self.quasi_identifiers = quasi_identifiers

    def sensitive(self, sensitive_attributes):
        "self.sensitive(['sensitive_attribute_1','sensitive_attribute_2',])"
        "Raises TypeError unless given a list of strings."
        "Raises ValueError for one not in the dataset, or one listed more than once."

        if type(sensitive_attributes) is not list:
            raise TypeError("A list of strings must be provided.")
        for s in sensitive_attributes:
            if type(s) is not str:
                raise TypeError("A list of strings must be provided.")
            elif s not in self.dataset.columns:
                raise ValueError(f"{s} is not an attribute of the dataset.")
            elif sensitive_attributes.count(s) > 1:
                raise ValueError(f"{s} is listed more than once.")

        self.sensitive_attributes = sensitive_attributes

    def worth(self, sensitive_attribute, worth_assignment):
        "self.worth('sensitive_attribute', {'val_1':worth_1,'val_2':worth_2,})"
        "Each value is matched by its text, str(value); missing values by the key None."
        "Raises TypeError unless given a string and a dictionary, or for a worth not a number."
        "Raises ValueError for an undefined sensitive attribute or a negative worth."

        # Must be run once for each sensitive attribute.

        if self.sensitive_attributes is None:
            raise ValueError("The sensitive attributes have not been defined yet.")
        elif type(sensitive_attribute) is not str:
            raise TypeError("A string and a dictionary must be provided.")
        elif sensitive_attribute not in self.sensitive_attributes:
            raise ValueError(f"{sensitive_attribute} is not a defined sensitive attribute.")
        elif type(worth_assignment) is not dict:
            raise TypeError("A string and a dictionary must be provided.")
        elif not all(isinstance(worth, numbers.Real) for worth in worth_assignment.values()):
            raise TypeError("Worth assignments must be numbers.")

        if any([True if worth < 0 else False for value, worth in worth_assignment.items()]):
            raise ValueError("Worth assignment cannot be negative!")

        if self.worth_assignment is None:
            self.worth_assignment = {}
        self.worth_assignment[sensitive_attribute] = worth_assignment

    def assess(self):
        "self.assess()"
        "Raises ValueError without quasi-identifiers, RuntimeError if an internal check fails."

        if self.quasi_identifiers is None:
            raise ValueError("One or more quasi-identifiers must be assigned.")
        else:
            if len(self.quasi_identifiers) > 0:
                "constants --> {sorted_dataset, attributes}"
                "variables --> {re_id, dCR, pCR, bins}"
                "variables --> {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA}"
                "variables --> {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA, information_worth, CW}"
                constants, variables = self.__setup()

                variables = self.__compute(constants, variables)

                return variables

##### Private methods for single-dataset attacks.

    def __update_eq_class(self, variables, eq_class, eq_class_size, row):
        "self.__update_eq_class(self, {re_id, dCR, pCR, bins}, eq_class, eq_class_size, row) --> ({re_id, dCR, pCR, bins}, eq_class)"
        "self.__update_eq_class(self, {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA}, eq_class, eq_class_size, row) --> ({re_id, dCR, pCR, bins, att_inf, sensitive_values, CA}, eq_class)"
        "self.__update_eq_class(self, {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA, information_worth, CW}, eq_class, eq_class_size, row) --> ({re_id, dCR, pCR, bins, att_inf, sensitive_values, CA, information_worth, CW}, eq_class)"

        variables['pCR'] = variables['pCR'] + 1
        class_size_one = False

        if self.sensitive_attributes is not None:
            class_size = sum(variables['sensitive_values'][self.sensitive_attributes[0]].values())
            bin_endpoint = math.ceil(100 * 1 / class_size)
            bin_interval = f"({bin_endpoint - 1}, {bin_endpoint}]"
            variables['bins'][_RE_ID][bin_interval] += class_size

            for attribute in self.sensitive_attributes:
                "counts --> dict_values (dict view, not list) of counts for all possible values of attribute"
                counts = variables['sensitive_values'][attribute].values()

                "max_value --> number of entries for the most common value of attribute"
                max_value = max(counts)

                "possible_values --> number of possible values for attribute"
                possible_values = len(counts)

                if class_size != sum(counts):
                    raise RuntimeError(
                        "class_size (=" + str(class_size) + ") and counts (=" + str(sum(counts))
                        + ") error!\n" + "QID: " + str(self.quasi_identifiers)
                        + ". Sensitive attribute: " + attribute + ".")

                bin_endpoint = math.ceil(100 * max_value / class_size)
                bin_interval = f"({bin_endpoint - 1}, {bin_endpoint}]"
                variables['bins'][attribute][bin_interval] += class_size

                variables['CA'][attribute].update(p = variables['CA'][attribute]['p'] + max_value)
                if possible_values == 1:
                    variables['CA'][attribute].update(d = variables['CA'][attribute]['d'] + max_value)
                    if max_value == 1:
                        class_size_one = True

                if (self.worth_assignment is not None) and (attribute in self.worth_assignment):
                    partition_worth = {
                        value : count * self.worth_assignment[attribute][value]
                        for value, count in variables['sensitive_values'][attribute].items()
                        if value in self.worth_assignment[attribute]}
                    if len(partition_worth) > 0:
                        variables['CW'][attribute].update(posterior = variables['CW'][attribute]['posterior'] + max(partition_worth.values()))

                # Adds the class's counts to the whole dataset's: the Prior counts by the same keys.
                prior_values = variables['prior_values'][attribute]
                for value, count in variables['sensitive_values'][attribute].items():
                    prior_values[value] = prior_values.get(value, 0) + count

                variables['sensitive_values'][attribute].clear()
        else:
            class_size = eq_class_size
            bin_endpoint = math.ceil(100 * 1 / class_size)
            bin_interval = f"({bin_endpoint - 1}, {bin_endpoint}]"
            variables['bins'][_RE_ID][bin_interval] += class_size
            if class_size == 1:
                class_size_one = True

        if class_size_one:
            variables['dCR'] = variables['dCR'] + 1
            if class_size != 1:
                raise RuntimeError(
                    "class_size (=" + str(class_size) + ") and class_size_one error!\n"
                    + "QID: " + str(self.quasi_identifiers) + ".")

        # Updates eq_class to new equivalence class.
        eq_class = row[0:len(self.quasi_identifiers)]
        eq_class_size = 0

        return (variables, eq_class, eq_class_size)

    def __compute(self, constants, variables):
        "self.__compute(self, {re_id, dCR, pCR, bins}) --> ({sorted_dataset, attributes}, {re_id, dCR, pCR, bins})"
        "self.__compute(self, {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA}) --> ({sorted_dataset, attributes}, {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA})"
        "self.__compute(self, {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA, information_worth, CW}) --> ({sorted_dataset, attributes}, {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA, information_worth, CW})"

        sorted_dataset = constants['sorted_dataset']
        for attribute in constants['attributes']:
            # Checked unsorted first: sorting can scatter the values in memory and slow the scan.
            if self.dataset[attribute].isna().to_numpy().any():
                missing = sorted_dataset[attribute].isna().to_numpy()
                values = sorted_dataset[attribute].to_numpy(dtype=object, copy=True)
                values[missing] = _MISSING
                # A Series of dtype object, so that pandas keeps _MISSING as it is.
                sorted_dataset[attribute] = pandas.Series(
                    values, index=sorted_dataset.index, dtype=object)

        # The Prior's counts, which __update_eq_class adds up from the classes'; not returned.
        variables['prior_values'] = {attribute: {} for attribute in self.sensitive_attributes or []}

        eq_class = ()
        eq_class_size = 0
        for row in constants['sorted_dataset'][constants['attributes']].itertuples(index=False):
            if eq_class == ():
                eq_class = row[0:len(self.quasi_identifiers)]
            elif row[0:len(self.quasi_identifiers)] != eq_class:
                variables, eq_class, eq_class_size = self.__update_eq_class(variables, eq_class, eq_class_size, row)

            if self.sensitive_attributes is not None:
                it = 0
                for attribute in self.sensitive_attributes:
                    value = row[len(self.quasi_identifiers)+it]
                    # Missing values count under None, as worth() keys them, apart from every text.
                    key = None if value is _MISSING else str(value)
                    if key in variables['sensitive_values'][attribute]:
                        variables['sensitive_values'][attribute][key] += 1
                    else:
                        variables['sensitive_values'][attribute][key] = 1
                    it += 1
            else:
                eq_class_size += 1

        # For accounting for the last equivalence class.
        variables, eq_class, eq_class_size = self.__update_eq_class(variables, eq_class, eq_class_size, row)
        prior_values = variables.pop('prior_values')

        dataset_size = constants['sorted_dataset'].shape[0]

        if dataset_size == 1:
            variables['dCR'] = (variables['dCR']/dataset_size) - 1
        else:
            variables['dCR'] = variables['dCR']/dataset_size

        sensitive_attributes = (
            self.sensitive_attributes 
            if self.sensitive_attributes is not None 
            else []
        )

        for case in [*sensitive_attributes, _RE_ID]:
            variables['bins'][case] = {
                bin_interval: count / dataset_size 
                for bin_interval, count in variables['bins'][case].items()
            }

        df_data = {
            'QID': str(self.quasi_identifiers),
            'dCR': variables['dCR'], 
            'pCR': variables['pCR'], 
            'Prior': 1 / dataset_size, 
            'Posterior': variables['pCR'] / dataset_size, 
            'Histogram': variables['bins'][_RE_ID]
        }

        # Each table is built once from its rows, so that its numeric columns get a number dtype.
        variables['re_id'] = pandas.DataFrame([df_data], columns=variables['re_id'].columns)

        if self.sensitive_attributes is not None:
            att_inf_rows = []
            worth_rows = []
            for attribute in self.sensitive_attributes:
                variables['CA'][attribute].update(d = variables['CA'][attribute]['d']/dataset_size)

                values_counts = prior_values[attribute]
                most_probable_count = max(values_counts.values())

                variables['CA'][attribute].update(p = variables['CA'][attribute]['p']/most_probable_count)

                if (variables['CA'][attribute]['d'] == 1) and (len(values_counts) == 1):
                    variables['CA'][attribute].update(d = variables['CA'][attribute]['d'] - 1)

                df_data = {
                    'QID': str(self.quasi_identifiers),
                    'Sensitive': attribute,
                    'dCA': variables['CA'][attribute]['d'],
                    'pCA': variables['CA'][attribute]['p'],
                    'Prior': most_probable_count / dataset_size,
                    'Posterior': (variables['CA'][attribute]['p'] * most_probable_count)/dataset_size,
                    'Histogram': variables['bins'][attribute]
                }

                att_inf_rows.append(df_data)

                if (self.worth_assignment is not None) and (attribute in self.worth_assignment):
                    prior_worth = {
                        value : (count/dataset_size) * self.worth_assignment[attribute][value]
                        for value, count in values_counts.items()
                        if value in self.worth_assignment[attribute]}

                    if len(prior_worth) > 0:
                        variables['CW'][attribute].update(prior = max(prior_worth.values()))

                    variables['CW'][attribute].update(posterior = variables['CW'][attribute]['posterior']/dataset_size)

                    df_data = {
                        'QID': str(self.quasi_identifiers),
                        'Sensitive': attribute,
                        'Prior Worth': variables['CW'][attribute]['prior'],
                        'Posterior Worth': variables['CW'][attribute]['posterior']
                    }

                    worth_rows.append(df_data)

            variables['att_inf'] = pandas.DataFrame(
                att_inf_rows, columns=variables['att_inf'].columns)
            if self.worth_assignment is not None:
                variables['information_worth'] = pandas.DataFrame(
                    worth_rows, columns=variables['information_worth'].columns)

        # The re-identification bins come first, under 're_id'. A sensitive attribute of that name
        # takes 're_id (sensitive)' instead, with ' (sensitive)' added again while that is taken.
        renamed = 're_id'
        while renamed in variables['bins']:
            renamed += ' (sensitive)'
        variables['bins'] = {'re_id': variables['bins'].pop(_RE_ID), **{
            renamed if key == 're_id' else key: bins for key, bins in variables['bins'].items()}}

        return variables

    def __setup(self):
        "self.__setup() --> ({sorted_dataset, attributes}, {re_id, dCR, pCR, bins})"
        "self.__setup() --> ({sorted_dataset, attributes}, {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA})"
        "self.__setup() --> ({sorted_dataset, attributes}, {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA, information_worth, CW})"

        sorted_dataset = self.dataset.sort_values(
            by=self.quasi_identifiers, axis='index', kind='mergesort')

        re_id = pandas.DataFrame(columns=['QID', 'dCR', 'pCR', 'Prior', 'Posterior', 'Histogram'])

        dCR = 0
        pCR = 0

        "bins --> {'re_id':{'(0, 1]':a,'(1, 2]':b,...,'(99, 100]':c},}"
        "bins --> {'re_id':{'(0, 1]':a,...,'(99, 100]':b},'attr_1':{'(0, 1]':c,...,'(99, 100]':d},}"
        "bins: '(x, y]' for the amount of rows whose chance is above x% and at most y%."
        bins = {}
        bins[_RE_ID] = {f"({i}, {i + 1}]": 0 for i in range(100)}

        "attributes --> self.quasi_identifiers"
        "attributes --> self.quasi_identifiers + self.sensitive_attributes"
        attributes = self.quasi_identifiers.copy()

        if self.sensitive_attributes is not None:
            att_inf = pandas.DataFrame(columns=['QID', 'Sensitive', 'dCA', 'pCA', 'Prior', 'Posterior', 'Histogram'])

            "sensitive_values --> {'attr_1':{'val_1':count_1,'val_2':count_2},'attr_2':{'val_1':count_1},}"
            "sensitive_values: attr_i from self.sensitive_attributes, val_j from attr_i, count_k from val_j."
            sensitive_values = {}

            "CA --> {'attr_1':{'d':x,'p':y},'attr_2':{'d':a,'p':b},}"
            "CA: attr_i from self.sensitive_attributes, 'd' for dCA value, 'p' for pCA value."
            CA = {}

            for attribute in self.sensitive_attributes:
                sensitive_values[attribute] = {}
                CA[attribute] = {'d': 0,'p': 0}
                bins[attribute] = {f"({i}, {i + 1}]": 0 for i in range(100)}
                attributes.append(attribute)

            if self.worth_assignment is not None:
                information_worth = pandas.DataFrame(columns=['QID', 'Sensitive', 'Prior Worth', 'Posterior Worth'])

                "CW --> {'attr_1':{'prior':prior_worth_1,'posterior':posterior_worth_1},'attr_2':{'prior':prior_worth_2,'posterior':posterior_worth_2},}"
                "CW: attr_i from self.sensitive_attributes, 'prior' for the prior worth, 'posterior' for the posterior worth."
                CW = {}

                for attribute in iter(self.worth_assignment):
                    CW[attribute] = {'prior': 0.0,'posterior': 0}

                return ({'sorted_dataset': sorted_dataset, 'attributes': attributes},
                        {'re_id': re_id, 'dCR': dCR, 'pCR': pCR, 'bins': bins,
                        'att_inf': att_inf, 'sensitive_values': sensitive_values, 'CA': CA,
                        'information_worth': information_worth, 'CW': CW})
            else:
                return ({'sorted_dataset': sorted_dataset, 'attributes': attributes},
                        {'re_id': re_id, 'dCR': dCR, 'pCR': pCR, 'bins': bins,
                        'att_inf': att_inf, 'sensitive_values': sensitive_values, 'CA': CA})
        else:
            return ({'sorted_dataset': sorted_dataset, 'attributes': attributes},
                    {'re_id': re_id, 'dCR': dCR, 'pCR': pCR, 'bins': bins,})

@dataclass
class BVMLongitudinal(BVM):
    "Bayes Vulnerability for Microdata class dedicated to longitudinal vulnerability assessment."

##### Constructor for longitudinal attacks.

    def __init__(self, datasets, identifiers):
        "BVM.longitudinal([pandas.DataFrame_1, pandas.DataFrame_2,], [identifier_1, identifier_2,]): Initializes BVM class for longitudinal attacks linked by unique identifier attributes."
        "identifier_1 is the unique identifier attribute for dataset pandas.DataFrame_1."
        "Each identifier is a string, or a list holding exactly one string."
        "pandas.DataFrame_1 is considered to be the focal dataset."
        "Raises TypeError for an argument or entry of the wrong type, or lists of unequal lengths."
        "Raises ValueError for an empty dataset or identifier, or an identifier not in its dataset."
        "Raises ValueError for a list of several identifiers for one dataset."

        message = ("A non-empty list of pandas DataFrames and a non-empty list of strings for the "
                   "identifying attributes, both with the same length, must be provided.")
        if (type(datasets) is not list or type(identifiers) is not list
                or len(datasets) != len(identifiers)):
            raise TypeError(message)
        # A list holding exactly one string stands for that string.
        identifiers = [
            identifier[0] if type(identifier) is list and len(identifier) == 1 else identifier
            for identifier in identifiers]
        for i in range(len(datasets)):
            if type(datasets[i]) is not pandas.DataFrame:
                raise TypeError(message)
            elif datasets[i].empty:
                raise ValueError(message)
            elif (type(identifiers[i]) is list and len(identifiers[i]) > 1
                    and all(type(identifier) is str for identifier in identifiers[i])):
                raise ValueError(f"{identifiers[i]} lists several identifying attributes: each "
                                 "dataset is linked by one, a string or a list holding one string.")
            elif type(identifiers[i]) is not str:
                raise TypeError(message)
            elif identifiers[i] == "":
                raise ValueError(message)
            elif identifiers[i] not in datasets[i].columns:
                raise ValueError(f"{i} is not an attribute of the respective dataset.")

        self.dataset = None
        self.datasets = datasets
        self.identifiers = identifiers
        self.quasi_identifiers = None
        self.all_quasi_identifiers = None
        self.sensitive_attributes = None
        self.worth_assignment = None

##### Public methods for longitudinal attacks.

    def ids(self):
        "self.ids()"
        "Displays the identifiers set by the user to link the datasets."

        i = 1
        for identifier in self.identifiers:
            print("Identifying attribute for dataset " + str(i) + ": " + identifier + ".")
            i = i + 1

    def qids(self, quasi_identifiers):
        "self.qids([['quasi_identifier_1_1','quasi_identifier_1_2',], ['quasi_identifier_2_1','quasi_identifier_2_2',],])"
        "quasi_identifier_1_1 is an attribute from dataset pandas.DataFrame_1 and quasi_identifier_2_1 is the equivalent attribute from dataset pandas.DataFrame_2."
        "If all attributes have the same label on all datasets, only one list of quasi-identifiers can be provided."
        "Raises TypeError for an argument or entry of the wrong type."
        "Raises ValueError for a quasi-identifier that is not an attribute of its dataset."

        types = "A list of strings or a list of lists of strings must be provided."
        not_found = " is not a string or is not an attribute of the respective dataset."
        if type(quasi_identifiers) is not list:
            raise TypeError(types)
        # If quasi_identifiers[0] is a list, all other entries must also be.
        if type(quasi_identifiers[0]) is list:
            i = 0
            for qid_list in quasi_identifiers:
                if type(qid_list) is not list:
                    raise TypeError(types)
                for qid in qid_list:
                    if type(qid) is not str:
                        raise TypeError(f"{qid}{not_found}")
                    elif qid not in self.datasets[i].columns:
                        raise ValueError(f"{qid}{not_found}")
                i = i + 1
        # If quasi_identifiers[0] is a string, all other entries must also be.
        elif type(quasi_identifiers[0]) is str:
            for qid in quasi_identifiers:
                if type(qid) is not str:
                    raise TypeError(f"{qid}{not_found}")
                for dataset in self.datasets:
                    if qid not in dataset.columns:
                        raise ValueError(f"{qid}{not_found}")
            # The same list for every dataset.
            quasi_identifiers = [quasi_identifiers] * len(self.datasets)

        self.quasi_identifiers = quasi_identifiers

    def sensitive(self, sensitive_attributes):
        "self.sensitive(['sensitive_attribute_1','sensitive_attribute_2',])"
        "All sensitive attributes are attributes from dataset pandas.DataFrame_1."
        "Raises TypeError unless given a list of strings."
        "Raises ValueError for one not in DataFrame_1, or one listed more than once."

        if type(sensitive_attributes) is not list:
            raise TypeError("A list of strings must be provided.")
        for s in sensitive_attributes:
            if type(s) is not str:
                raise TypeError("A list of strings must be provided.")
            elif s not in self.datasets[0].columns:
                raise ValueError(f"{s} is not an attribute of the focal dataset.")
            elif sensitive_attributes.count(s) > 1:
                raise ValueError(f"{s} is listed more than once.")

        self.sensitive_attributes = sensitive_attributes

    def assess(self):
        "self.assess()"
        "With two or more datasets, the later ones are left-joined onto the focal one."
        "A missing value and a row absent from a later dataset are two values of their own there."
        "Raises ValueError without quasi-identifiers, RuntimeError if an internal check fails."
        # Makes use of __setup(self), __compute(self, constants, variables), and __update_eq_class(self, variables, eq_class, eq_class_size, row) from parent class BVM().

        if self.quasi_identifiers is None:
            raise ValueError("One or more quasi-identifiers must be assigned.")
        else:
            if len(self.quasi_identifiers) > 0:

                self.__leftouterjoin()

                "constants --> {sorted_dataset, attributes}"
                "variables --> {re_id, dCR, pCR, bins}"
                "variables --> {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA}"
                constants, variables = self._BVM__setup()

                variables = self._BVM__compute(constants, variables)

                return variables

##### Private methods for longitudinal attacks.

    def __leftouterjoin(self):
        "self.__leftouterjoin()"
        # With two or more datasets, each quasi-identifier becomes the text of its values in all of
        # them, in order, joined by '#'. A row absent from a later dataset reads _JOINED_ABSENT.

        identifier = self.identifiers[0]
        quasi_identifiers = self.quasi_identifiers[0]
        joined_dataset = self.datasets[0]

        for i in range(1, len(self.datasets)):
            # Only the identifier and the quasi-identifiers, renamed as in the focal dataset, so
            # that no other column of a later dataset is merged.
            columns = [self.identifiers[i]] + self.quasi_identifiers[i]
            temp = self.datasets[i][columns].set_axis([identifier] + quasi_identifiers, axis=1)
            for column in quasi_identifiers:
                temp[column] = _joined_text(temp[column])

            # The merge suffixes the later quasi-identifiers so that they name no joined column.
            suffix = '#'
            while any(column + suffix in joined_dataset.columns for column in quasi_identifiers):
                suffix += '#'
            joined_dataset = pandas.merge(
                joined_dataset, temp, how='left', on=identifier, suffixes=(None, suffix))
            for column in quasi_identifiers:
                earlier = joined_dataset[column]
                if i == 1:
                    # The focal dataset's own values, not yet written as text.
                    earlier = _joined_text(earlier)
                later = joined_dataset.pop(column + suffix).fillna(_JOINED_ABSENT)
                joined_dataset[column] = earlier + '#' + later

        self.dataset = joined_dataset
        self.all_quasi_identifiers = self.quasi_identifiers
        self.quasi_identifiers = self.quasi_identifiers[0]
