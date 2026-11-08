# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2021-2026 Gabriel Henrique Lopes Gomes Alves Nunes

# Invalid input raises TypeError when an argument has the wrong type or shape, and ValueError when
# its type is right but its value is not. Each test checks the exception type and its whole message.

import re

import pandas
import pytest

from bvmlib.bvm import BVM, BVMLongitudinal

STRINGS = "A list of strings must be provided."
STRING_AND_DICT = "A string and a dictionary must be provided."
NO_QIDS = "One or more quasi-identifiers must be assigned."
DATASETS = ("A non-empty list of pandas DataFrames and a non-empty list of strings for the "
            "identifying attributes, both with the same length, must be provided.")
QID_LISTS = "A list of strings or a list of lists of strings must be provided."
NOT_FOUND = " is not a string or is not an attribute of the respective dataset."

SETTERS = ["ids", "qids", "sensitive"]


def exactly(message):
    "A pattern that matches the whole message and nothing else."
    return "^" + re.escape(message) + "$"


def table():
    return pandas.DataFrame({"id": [1, 2], "a": [1, 2], "s": ["x", "y"]})


def years():
    "Two datasets: the focal one, and a later one with other column names."
    first = pandas.DataFrame({"id": [1, 2], "a": [1, 2], "s": ["x", "y"]})
    second = pandas.DataFrame({"key": [1, 2], "b": [3, 4], "t": ["u", "v"]})
    return first, second


def longitudinal():
    first, second = years()
    return BVMLongitudinal([first, second], ["id", "key"])


# BVM


@pytest.mark.parametrize("dataset", [[[1, 2]], {"a": [1, 2]}, pandas.Series([1, 2]), None])
def test_bvm_rejects_a_dataset_that_is_not_a_dataframe(dataset):
    with pytest.raises(TypeError, match=exactly("The dataset must be a pandas DataFrame.")):
        BVM(dataset)


@pytest.mark.parametrize("dataset", [pandas.DataFrame(), pandas.DataFrame({"a": []})])
def test_bvm_rejects_an_empty_dataset(dataset):
    with pytest.raises(ValueError, match=exactly("The dataset cannot be empty.")):
        BVM(dataset)


@pytest.mark.parametrize("setter", SETTERS)
@pytest.mark.parametrize("names", ["a", ("a",), None])
def test_setters_reject_an_argument_that_is_not_a_list(setter, names):
    with pytest.raises(TypeError, match=exactly(STRINGS)):
        getattr(BVM(table()), setter)(names)


@pytest.mark.parametrize("setter", SETTERS)
@pytest.mark.parametrize("names", [[1], ["a", 2], [["a"]]])
def test_setters_reject_a_name_that_is_not_a_string(setter, names):
    with pytest.raises(TypeError, match=exactly(STRINGS)):
        getattr(BVM(table()), setter)(names)


@pytest.mark.parametrize("setter", SETTERS)
def test_setters_reject_a_name_that_is_not_an_attribute(setter):
    with pytest.raises(ValueError, match=exactly("b is not an attribute of the dataset.")):
        getattr(BVM(table()), setter)(["a", "b"])



@pytest.mark.parametrize("names", [["s", "s"], ["s", "a", "s"]])
def test_sensitive_rejects_a_name_listed_twice(names):
    with pytest.raises(ValueError, match=exactly("s is listed more than once.")):
        BVM(table()).sensitive(names)

def test_a_rejected_call_keeps_the_earlier_quasi_identifiers():
    bvm = BVM(table())
    bvm.qids(["a"])
    with pytest.raises(ValueError):
        bvm.qids(["b"])
    # On "a" alone, each of the two rows is alone in its class.
    row = bvm.assess()["re_id"].iloc[0]
    assert row["QID"] == "['a']"
    assert row["pCR"] == 2
    assert row["dCR"] == pytest.approx(1.0)


def test_worth_needs_the_sensitive_attributes_first():
    bvm = BVM(table())
    message = exactly("The sensitive attributes have not been defined yet.")
    with pytest.raises(ValueError, match=message):
        bvm.worth("s", {"x": 1})


def test_worth_rejects_an_attribute_that_is_not_a_string():
    bvm = BVM(table())
    bvm.sensitive(["s"])
    with pytest.raises(TypeError, match=exactly(STRING_AND_DICT)):
        bvm.worth(["s"], {"x": 1})


@pytest.mark.parametrize("attribute", ["a", "b"])
def test_worth_rejects_an_attribute_that_is_not_sensitive(attribute):
    # "a" is a column of the table, "b" is not; neither is a sensitive attribute.
    bvm = BVM(table())
    bvm.sensitive(["s"])
    message = exactly(attribute + " is not a defined sensitive attribute.")
    with pytest.raises(ValueError, match=message):
        bvm.worth(attribute, {"x": 1})


@pytest.mark.parametrize("assignment", [[("x", 1)], None, 1])
def test_worth_rejects_an_assignment_that_is_not_a_dict(assignment):
    bvm = BVM(table())
    bvm.sensitive(["s"])
    with pytest.raises(TypeError, match=exactly(STRING_AND_DICT)):
        bvm.worth("s", assignment)


def test_worth_rejects_a_negative_worth_and_keeps_none():
    bvm = BVM(table())
    bvm.qids(["a"])
    bvm.sensitive(["s"])
    with pytest.raises(ValueError, match=exactly("Worth assignment cannot be negative!")):
        bvm.worth("s", {"x": 1, "y": -0.5})
    assert "information_worth" not in bvm.assess()


def test_assess_needs_quasi_identifiers():
    bvm = BVM(table())
    bvm.sensitive(["s"])
    with pytest.raises(ValueError, match=exactly(NO_QIDS)):
        bvm.assess()


# BVMLongitudinal


def test_longitudinal_rejects_datasets_that_are_not_a_list():
    first, second = years()
    with pytest.raises(TypeError, match=exactly(DATASETS)):
        BVMLongitudinal((first, second), ["id", "key"])


def test_longitudinal_rejects_identifiers_that_are_not_a_list():
    first, second = years()
    with pytest.raises(TypeError, match=exactly(DATASETS)):
        BVMLongitudinal([first, second], "id")


def test_longitudinal_rejects_lists_of_different_lengths():
    first, second = years()
    with pytest.raises(TypeError, match=exactly(DATASETS)):
        BVMLongitudinal([first, second], ["id"])


def test_longitudinal_rejects_a_dataset_that_is_not_a_dataframe():
    first, second = years()
    with pytest.raises(TypeError, match=exactly(DATASETS)):
        BVMLongitudinal([first, second.to_dict()], ["id", "key"])


def test_longitudinal_rejects_an_empty_dataset():
    first, second = years()
    with pytest.raises(ValueError, match=exactly(DATASETS)):
        BVMLongitudinal([first, second.iloc[0:0]], ["id", "key"])


def test_longitudinal_rejects_an_identifier_that_is_not_a_string():
    first, second = years()
    with pytest.raises(TypeError, match=exactly(DATASETS)):
        BVMLongitudinal([first, second], ["id", 0])


def test_longitudinal_rejects_an_empty_identifier():
    first, second = years()
    with pytest.raises(ValueError, match=exactly(DATASETS)):
        BVMLongitudinal([first, second], ["id", ""])


def test_longitudinal_rejects_an_identifier_that_is_not_an_attribute():
    # "id" is a column of the first dataset only. The message names the dataset's position, 1.
    first, second = years()
    message = exactly("1 is not an attribute of the respective dataset.")
    with pytest.raises(ValueError, match=message):
        BVMLongitudinal([first, second], ["id", "id"])


@pytest.mark.parametrize("names", ["a", ("a",), None])
def test_longitudinal_qids_reject_an_argument_that_is_not_a_list(names):
    with pytest.raises(TypeError, match=exactly(QID_LISTS)):
        longitudinal().qids(names)


def test_longitudinal_qids_reject_a_list_of_lists_with_an_entry_that_is_not_a_list():
    with pytest.raises(TypeError, match=exactly(QID_LISTS)):
        longitudinal().qids([["a"], "b"])


def test_longitudinal_qids_reject_a_name_that_is_not_a_string():
    with pytest.raises(TypeError, match=exactly("1" + NOT_FOUND)):
        longitudinal().qids([["a"], [1]])


def test_longitudinal_qids_reject_a_name_that_is_not_an_attribute_of_its_dataset():
    # "a" is a column of the first dataset, not of the second.
    with pytest.raises(ValueError, match=exactly("a" + NOT_FOUND)):
        longitudinal().qids([["a"], ["a"]])


@pytest.mark.parametrize("names", ["s", ("s",), None])
def test_longitudinal_sensitive_rejects_an_argument_that_is_not_a_list(names):
    with pytest.raises(TypeError, match=exactly(STRINGS)):
        longitudinal().sensitive(names)


def test_longitudinal_sensitive_rejects_a_name_that_is_not_a_string():
    with pytest.raises(TypeError, match=exactly(STRINGS)):
        longitudinal().sensitive(["s", 1])


def test_longitudinal_sensitive_rejects_a_name_not_in_the_focal_dataset():
    # "t" is a column of the second dataset only.
    message = exactly("t is not an attribute of the focal dataset.")
    with pytest.raises(ValueError, match=message):
        longitudinal().sensitive(["t"])



def test_longitudinal_sensitive_rejects_a_name_listed_twice():
    with pytest.raises(ValueError, match=exactly("s is listed more than once.")):
        longitudinal().sensitive(["s", "s"])


def test_longitudinal_ids_reports_each_identifier(capsys):
    longitudinal().ids()
    assert capsys.readouterr().out == ("Identifying attribute for dataset 1: id.\n"
                                       "Identifying attribute for dataset 2: key.\n")

def test_longitudinal_assess_needs_quasi_identifiers():
    with pytest.raises(ValueError, match=exactly(NO_QIDS)):
        longitudinal().assess()
