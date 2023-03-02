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

import numpy
import pandas

class BVM():
    "Bayes Vulnerability for Microdata class dedicated to single-dataset vulnerability assessment."

##### Constructor for single-dataset attacks.

    def __init__(self, dataset):
        "BVM(pandas.DataFrame): Initializes BVM class for single-dataset attacks."

        try:
            if type(dataset) is not pandas.DataFrame:
                raise TypeError
            if dataset.empty:
                raise ValueError(dataset)

        except TypeError:
            print("The dataset must be a pandas DataFrame.")
        except ValueError:
            print("The dataset cannot be empty.")

        else:
            self.dataset = dataset
            self.identifiers = None
            self.quasi_identifiers = None
            self.sensitive_attributes = None
            self.worth_assignment = None

##### Public methods for single-dataset attacks.

    def ids(self, identifiers):
        "self.ids(['id_1',])"

        try:
            if type(identifiers) is not list:
                raise TypeError
            elif type(identifiers) is list:
                for i in identifiers:
                    if type(i) is not str:
                        raise TypeError
                    elif i not in self.dataset.columns:
                        raise ValueError(i)

        except TypeError:
            print("A list of strings must be provided.")
        except ValueError:
            print(i, " is not an attribute of the dataset.")

        else:
            self.identifiers = identifiers

    def qids(self, quasi_identifiers):
        "self.qids(['quasi_identifier_1','quasi_identifier_2',])"

        try:
            if type(quasi_identifiers) is not list:
                raise TypeError
            elif type(quasi_identifiers) is list:
                for qid in quasi_identifiers:
                    if type(qid) is not str:
                        raise TypeError
                    elif qid not in self.dataset.columns:
                        raise ValueError(qid)

        except TypeError:
            print("A list of strings must be provided.")
        except ValueError:
            print(qid, " is not an attribute of the dataset.")

        else:
            self.quasi_identifiers = quasi_identifiers

    def sensitive(self, sensitive_attributes):
        "self.sensitive(['sensitive_attribute_1','sensitive_attribute_2',])"

        try:
            if type(sensitive_attributes) is not list:
                raise TypeError
            elif type(sensitive_attributes) is list:
                for s in sensitive_attributes:
                    if type(s) is not str:
                        raise TypeError
                    elif s not in self.dataset.columns:
                        raise ValueError(s)

        except TypeError:
            print("A list of strings must be provided.")
        except ValueError:
            print(s, " is not an attribute of the dataset.")

        else:
            self.sensitive_attributes = sensitive_attributes

    def worth(self, sensitive_attribute, worth_assignment):
        "self.worth('sensitive_attribute', {'val_1':worth_1,'val_2':worth_2,})"

        # Must be run once for each sensitive attribute.

        try:
            if self.sensitive_attributes is None:
                raise AttributeError
            elif type(sensitive_attribute) is not str:
                raise TypeError
            elif sensitive_attribute not in self.sensitive_attributes:
                raise ValueError(s)
            elif type(worth_assignment) is not dict:
                raise TypeError

        except AttributeError:
            print("The sensitive attributes have not been defined yet.")
        except TypeError:
            print("A string and a dictionary must be provided.")
        except ValueError:
            print(s, " is not a defined sensitive attribute.")

        else:
            try:
                if any([True if worth < 0 else False for value, worth in worth_assignment.items()]):
                    raise TypeError

            except TypeError:
                print("Worth assignment cannot be negative!")

            else:
                if self.worth_assignment is None:
                    self.worth_assignment = {}
                self.worth_assignment[sensitive_attribute] = worth_assignment

    def assess(self):
        "self.assess()"

        try:
            if self.quasi_identifiers is None:
                raise TypeError

        except TypeError:
            print("One or more quasi-identifiers must be assigned.")

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
            b = round(100 * 1/class_size)
            variables['bins']['re_id'].update({str(b): variables['bins']['re_id'][str(b)] + class_size})

            for attribute in self.sensitive_attributes:
                "counts --> dict_values (dict view, not list) of counts for all possible values of attribute"
                counts = variables['sensitive_values'][attribute].values()

                "max_value --> number of entries for the most common value of attribute"
                max_value = max(counts)

                "possible_values --> number of possible values for attribute"
                possible_values = len(counts)

                try:
                    if class_size != sum(counts):
                        raise ValueError(class_size, counts, self.quasi_identifiers, attribute)

                except ValueError:
                    print("class_size (=" + str(class_size) + ") and counts (=" + str(sum(counts)) + ") error!\n" +
                          "QID: " + str(self.quasi_identifiers) + ". Sensitive attribute: " + attribute + ".")

                b = round(100 * max_value/class_size)
                variables['bins'][attribute].update({str(b): variables['bins'][attribute][str(b)] + class_size})

                variables['CA'][attribute].update(p = variables['CA'][attribute]['p'] + max_value)
                if possible_values == 1:
                    variables['CA'][attribute].update(d = variables['CA'][attribute]['d'] + max_value)
                    if max_value == 1:
                        class_size_one = True

                if (self.worth_assignment is not None) and (attribute in self.worth_assignment):
                    partition_worth = {value : count * self.worth_assignment[attribute][value] for value, count in {str(v) : c for v, c in variables['sensitive_values'][attribute].items()}.items() if value in self.worth_assignment[attribute]}
                    if len(partition_worth) > 0:
                        variables['CW'][attribute].update(posterior = variables['CW'][attribute]['posterior'] + max(partition_worth.values()))

                variables['sensitive_values'][attribute].clear()
        else:
            class_size = eq_class_size
            b = round(100 * 1/class_size)
            variables['bins']['re_id'].update({str(b): variables['bins']['re_id'][str(b)] + class_size})
            if class_size == 1:
                class_size_one = True

        if class_size_one:
            variables['dCR'] = variables['dCR'] + 1
            try:
                if class_size != 1:
                    raise ValueError(class_size, self.quasi_identifiers)

            except ValueError:
                print("class_size (=" + str(class_size) + ") and class_size_one error!\n" +
                      "QID: " + str(self.quasi_identifiers) + ".")

        # Updates eq_class to new equivalence class.
        eq_class = row[0:len(self.quasi_identifiers)]
        eq_class_size = 0

        return (variables, eq_class, eq_class_size)

    def __compute(self, constants, variables):
        "self.__compute(self, {re_id, dCR, pCR, bins}) --> ({sorted_dataset, attributes}, {re_id, dCR, pCR, bins})"
        "self.__compute(self, {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA}) --> ({sorted_dataset, attributes}, {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA})"
        "self.__compute(self, {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA, information_worth, CW}) --> ({sorted_dataset, attributes}, {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA, information_worth, CW})"

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
                    if str(value) in variables['sensitive_values'][attribute]:
                        variables['sensitive_values'][attribute].update({str(value): variables['sensitive_values'][attribute][str(value)] + 1})
                    else:
                        variables['sensitive_values'][attribute].update({str(value): 1})
                    it += 1
            else:
                eq_class_size += 1

        # For accounting for the last equivalence class.
        variables, eq_class, eq_class_size = self.__update_eq_class(variables, eq_class, eq_class_size, row)

        dataset_size = constants['sorted_dataset'].shape[0]

        if dataset_size == 1:
            variables['dCR'] = (variables['dCR']/dataset_size) - 1
        else:
            variables['dCR'] = variables['dCR']/dataset_size

        if self.sensitive_attributes is not None:
            for case in self.sensitive_attributes + ['re_id']:
                for i in range(101):
                    variables['bins'][case].update({str(i): variables['bins'][case][str(i)]/dataset_size})
        else:
            for i in range(101):
                variables['bins']['re_id'].update({str(i): variables['bins']['re_id'][str(i)]/dataset_size})

        d = {'QID': str(self.quasi_identifiers), 'dCR': variables['dCR'], 'pCR': variables['pCR'], 'Prior': 1/dataset_size,
             'Posterior': variables['pCR']/dataset_size, 'Histogram': str(variables['bins']['re_id'])}
        variables['re_id'] = pandas.concat([variables['re_id'], pandas.DataFrame(data = d, index=[0])], ignore_index = True)

        if self.sensitive_attributes is not None:
            for attribute in self.sensitive_attributes:
                variables['CA'][attribute].update(d = variables['CA'][attribute]['d']/dataset_size)

                if variables['CA'][attribute]['d'] == 1:
                    variables['CA'][attribute].update(d = variables['CA'][attribute]['d'] - 1)

                values_counts = constants['sorted_dataset'].groupby(attribute).size()
                most_probable_count = values_counts.max()

                variables['CA'][attribute].update(p = variables['CA'][attribute]['p']/most_probable_count)

                d = {'QID': str(self.quasi_identifiers), 'Sensitive': attribute, 'dCA': variables['CA'][attribute]['d'],
                     'pCA': variables['CA'][attribute]['p'], 'Prior': most_probable_count/dataset_size,
                     'Posterior': (variables['CA'][attribute]['p'] * most_probable_count)/dataset_size,
                     'Histogram': str(variables['bins'][attribute])}
                variables['att_inf'] = pandas.concat([variables['att_inf'], pandas.DataFrame(data = d, index=[0])],
                                                     ignore_index = True)

                if (self.worth_assignment is not None) and (attribute in self.worth_assignment):
                    prior_worth = {value : (count/dataset_size) * self.worth_assignment[attribute][value] for value, count in {str(v) : c for v, c in values_counts.to_dict().items()}.items() if value in self.worth_assignment[attribute]}

                    if len(prior_worth) > 0:
                        variables['CW'][attribute].update(prior = max(prior_worth.values()))

                    variables['CW'][attribute].update(posterior = variables['CW'][attribute]['posterior']/dataset_size)

                    d = {'QID': str(self.quasi_identifiers), 'Sensitive': attribute,
                         'Prior Worth': variables['CW'][attribute]['prior'],
                         'Posterior Worth': variables['CW'][attribute]['posterior']}
                    variables['information_worth'] = pandas.concat([variables['information_worth'], pandas.DataFrame(data = d, index=[0])],
                                                                   ignore_index = True)

        return variables

    def __setup(self):
        "self.__setup() --> ({sorted_dataset, attributes}, {re_id, dCR, pCR, bins})"
        "self.__setup() --> ({sorted_dataset, attributes}, {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA})"
        "self.__setup() --> ({sorted_dataset, attributes}, {re_id, dCR, pCR, bins, att_inf, sensitive_values, CA, information_worth, CW})"

        sorted_dataset = self.dataset.sort_values(by=self.quasi_identifiers, axis='index', inplace=False, kind='mergesort')

        re_id = pandas.DataFrame(columns=['QID', 'dCR', 'pCR', 'Prior', 'Posterior', 'Histogram'])

        dCR = 0
        pCR = 0

        "bins --> {'re_id':{'0%':a,'1%':b,'2%':c,...,'100%':d},}"
        "bins --> {'re_id':{'0%':a,'1%':b,'2%':c,...,'100%':d},'attr_1':{'0%':e,...,'100%':f},}"
        "bins: 'x%' for chance of re-identification or attribute-inference, y% for amount of rows with 'x%' chance."
        bins = {}
        bins['re_id'] = {}
        for i in range(101):
            bins['re_id'].update({str(i): 0})

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
                bins[attribute] = {}
                for i in range(101):
                    bins[attribute].update({str(i): 0})
                attributes.append(attribute)

            if self.worth_assignment is not None:
                information_worth = pandas.DataFrame(columns=['QID', 'Sensitive', 'Prior Worth', 'Posterior Worth'])

                "CW --> {'attr_1':{'prior':prior_worth_1,'posterior':posterior_worth_1},'attr_2':{'prior':prior_worth_2,'posterior':posterior_worth_2},}"
                "CW: attr_i from self.sensitive_attributes, 'prior' for the prior worth, 'posterior' for the posterior worth."
                CW = {}

                for attribute in iter(self.worth_assignment):
                    CW[attribute] = {'prior': 0,'posterior': 0}

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

class BVMLongitudinal(BVM):
    "Bayes Vulnerability for Microdata class dedicated to longitudinal vulnerability assessment."

##### Constructor for longitudinal attacks.

    def __init__(self, datasets, identifiers):
        "BVM.longitudinal([pandas.DataFrame_1, pandas.DataFrame_2,], [identifier_1, identifier_2,]): Initializes BVM class for longitudinal attacks linked by unique identifier attributes."
        "identifier_1 is the unique identifier attribute for dataset pandas.DataFrame_1."
        "pandas.DataFrame_1 is considered to be the focal dataset."

        try:
            if type(datasets) is not list or type(identifiers) is not list or len(datasets) != len(identifiers):
                raise TypeError
            else:
                i = 0
                for i in range(len(datasets)):
                    if type(datasets[i]) is not pandas.DataFrame or datasets[i].empty:
                        raise TypeError
                    elif type(identifiers[i]) is not str or identifiers[i] == "":
                        raise TypeError
                    elif identifiers[i] not in datasets[i].columns:
                        raise ValueError(i)
                    i = i + 1

        except TypeError:
            print("A non-empty list of pandas DataFrames and a non-empty list of strings for the identifying attributes, both with the same legth, must be provided.")
        except ValueError:
            print(i, " is not an attribute of the respective dataset.")

        else:
                self.dataset = None
                self.datasets = datasets
                self.identifiers = identifiers
                self.quasi_identifiers = None
                self.all_quasi_identifiers = None
                self.sensitive_attributes = None

##### Public methods for longitudinal attacks.

    def ids(self):
        "self.ids()"
        "Displays the identifiers set by the user to link the datasets."

        i = 1
        for identifier in self.identifiers:
            print("Indetifying attribute for dataset " + str(i) + ": " + identifier + ".")
            i = i + 1

    def qids(self, quasi_identifiers):
        "self.qids([['quasi_identifier_1_1','quasi_identifier_1_2',], ['quasi_identifier_2_1','quasi_identifier_2_2',],])"
        "quasi_identifier_1_1 is an attribute from dataset pandas.DataFrame_1 and quasi_identifier_2_1 is the equivalent attribute from dataset pandas.DataFrame_2."
        "If all attributes have the same label on all datasets, only one list of quasi-identifiers can be provided."

        try:
            if type(quasi_identifiers) is not list:
                raise TypeError
            elif type(quasi_identifiers) is list:
                # If quasi_identifiers[0] is a list, all other entries must also be.
                if type(quasi_identifiers[0]) is list:
                    i = 0
                    for qid_list in quasi_identifiers:
                        if type(qid_list) is not list:
                            raise TypeError
                        elif type(qid_list) is list:
                            for qid in qid_list:
                                if type(qid) is not str:
                                    raise ValueError(qid)
                                elif qid not in self.datasets[i].columns:
                                    raise ValueError(qid)
                        i = i + 1
                # If quasi_identifiers[0] is a string, all other entries must also be.
                elif type(quasi_identifiers[0]) is str:
                    for qid in quasi_identifiers:
                        i = 0
                        if type(qid) is not str:
                            raise ValueError(qid)
                        for dataset in self.datasets:
                            if qid not in dataset[i].columns:
                                raise ValueError(qid)
                            i = i + 1

        except TypeError:
            print("A list of strings or a list of lists of strings must be provided.")
        except ValueError:
            print(qid, " is not a string or is not an attribute of the respective dataset.")

        else:
            self.quasi_identifiers = quasi_identifiers

    def sensitive(self, sensitive_attributes):
        "self.sensitive(['sensitive_attribute_1','sensitive_attribute_2',])"
        "All sensitive attributes are attributes from dataset pandas.DataFrame_1."

        try:
            if type(sensitive_attributes) is not list:
                raise TypeError
            elif type(sensitive_attributes) is list:
                for s in sensitive_attributes:
                    if type(s) is not str:
                        raise TypeError
                    elif s not in self.datasets[0].columns:
                        raise ValueError(s)

        except TypeError:
            print("A list of strings must be provided.")
        except ValueError:
            print(s, " is not an attribute of the focal dataset.")

        else:
            self.sensitive_attributes = sensitive_attributes

    def assess(self):
        "self.assess()"
        # Makes use of __setup(self), __compute(self, constants, variables), and __update_eq_class(self, variables, eq_class, eq_class_size, row) from parent class BVM().

        try:
            if self.quasi_identifiers is None:
                raise TypeError

        except TypeError:
            print("One or more quasi-identifiers must be assigned.")

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

        joined_dataset = self.datasets[0]

        default_columns = [self.identifiers[0]] + self.quasi_identifiers[0]
        if self.sensitive_attributes is not None:
            default_columns.extend(self.sensitive_attributes[0])

        i = 1
        for dataset in self.datasets[1:]:
            columns = [self.identifiers[i]] + self.quasi_identifiers[i]
            temp = dataset.rename(columns=dict(zip(columns, default_columns)))

            joined_dataset = pandas.merge(joined_dataset, temp, how='left', on=self.identifiers[0])
            for column in default_columns[1:len(self.quasi_identifiers[0])+1]:
                joined_dataset[column] = joined_dataset[column+"_x"].map(str) + "#" + joined_dataset[column+"_y"].map(str)
                joined_dataset = joined_dataset.drop(columns=[column+"_x", column+"_y"])

        self.dataset = joined_dataset
        self.all_quasi_identifiers = self.quasi_identifiers
        self.quasi_identifiers = self.quasi_identifiers[0]
