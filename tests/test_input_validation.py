# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2021-2026 Gabriel Henrique Lopes Gomes Alves Nunes

# Invalid input raises TypeError for an argument or entry of the wrong type, and ValueError for the
# rest, among them BVMLongitudinal's datasets and identifiers given as empty lists or lists of
# different lengths, and a list of several identifiers for one dataset. Each test of an error
# checks the exception type and its whole message.

import re

import numpy
import pandas
import pytest

from bvmlib.bvm import BVM, BVMLongitudinal

STRINGS = "A list of strings must be provided."
STRING_AND_DICT = "A string and a dictionary must be provided."
NO_QIDS = "The quasi-identifiers have not been defined yet."
NO_SENSITIVE_YET = "The sensitive attributes have not been defined yet."
DATASETS = ("A non-empty list of pandas DataFrames and a non-empty list of identifying "
            "attributes, each a string or a list holding one string, both with the same "
            "length, must be provided.")
QID_LISTS = "A list of strings or a list of lists of strings must be provided."
LIST_PER_DATASET = ("A non-empty list of quasi-identifiers for each dataset, all with the same "
                    "length, must be provided.")
TWICE = " is listed more than once."
BOTH = (" is both a sensitive attribute and a quasi-identifier of dataset 1, which "
        "BVMLongitudinal cannot assess with two or more datasets.")
# Not a string. Compared with "a" or "s", it gives an array, whose truth value is ambiguous.
ARRAY = numpy.array(["a", "s"])

SETTERS = ["ids", "qids", "sensitive"]


def exactly(message):
    "A pattern that matches the whole message and nothing else."
    return "^" + re.escape(message) + "$"


def twice_for(name, dataset):
    "BVMLongitudinal's message for a name listed twice in the list for a dataset."
    return f"{name} is listed more than once for dataset {dataset}."


def identifier_of(name, dataset):
    "BVMLongitudinal's message for a dataset's identifier among its quasi-identifiers."
    return (f"{name} is both the identifying attribute and a quasi-identifier of dataset "
            f"{dataset}, which BVMLongitudinal cannot assess with two or more datasets.")


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


def named_alike(count):
    "count datasets with the same column names, for a flat list of quasi-identifiers."
    return BVMLongitudinal([table() for _ in range(count)], ["id"] * count)


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
@pytest.mark.parametrize("names", [[1], ["a", 2], [["a"]], ["a", ARRAY]])
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


@pytest.mark.parametrize("names", [["a", "a"], ["a", "s", "a"]])
def test_qids_rejects_a_name_listed_twice(names):
    with pytest.raises(ValueError, match=exactly("a" + TWICE)):
        BVM(table()).qids(names)


def test_qids_accepts_an_empty_list_and_assess_returns_none():
    # The empty list replaces the earlier one: no quasi-identifiers, nothing to assess.
    bvm = BVM(table())
    bvm.qids(["a"])
    bvm.qids([])
    bvm.sensitive(["s"])
    assert bvm.assess() is None


def test_sensitive_accepts_an_empty_list_as_no_sensitive_attributes():
    # The empty list replaces the earlier one: re-identification only, as without sensitive().
    bvm = BVM(table())
    bvm.qids(["a"])
    bvm.sensitive(["s"])
    bvm.sensitive([])
    with pytest.raises(ValueError, match=exactly(NO_SENSITIVE_YET)):
        bvm.worth("s", {"x": 1})
    plain = BVM(table())
    plain.qids(["a"])
    results, expected = bvm.assess(), plain.assess()
    assert list(results) == list(expected) == ["re_id", "dCR", "pCR", "bins"]
    pandas.testing.assert_frame_equal(results["re_id"], expected["re_id"])


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


def expect_a_and_s(results):
    "Results on a, or on a and b, with s: each of the two rows alone in its class, s x and y."
    row = results["re_id"].iloc[0]
    assert row["QID"] == "['a']"
    assert row["pCR"] == 2
    assert row["dCR"] == pytest.approx(1.0)
    assert list(results["att_inf"]["Sensitive"]) == ["s"]
    row = results["att_inf"].iloc[0]
    assert row["dCA"] == pytest.approx(1.0)
    assert row["pCA"] == pytest.approx(2.0)
    assert row["Prior"] == pytest.approx(0.5)
    assert row["Posterior"] == pytest.approx(1.0)


def test_later_changes_to_the_callers_lists_change_nothing():
    bvm = BVM(table())
    quasi_identifiers = ["a"]
    sensitive_attributes = ["s"]
    bvm.qids(quasi_identifiers)
    bvm.sensitive(sensitive_attributes)
    # Both would fail the checks: b is not an attribute, and s is listed twice.
    quasi_identifiers.append("b")
    sensitive_attributes.append("s")
    expect_a_and_s(bvm.assess())


def test_worth_needs_the_sensitive_attributes_first():
    bvm = BVM(table())
    with pytest.raises(ValueError, match=exactly(NO_SENSITIVE_YET)):
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
    with pytest.raises(ValueError, match=exactly("Worth assignments cannot be negative.")):
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
    with pytest.raises(ValueError, match=exactly(DATASETS)):
        BVMLongitudinal([first, second], ["id"])


def test_longitudinal_rejects_empty_lists():
    with pytest.raises(ValueError, match=exactly(DATASETS)):
        BVMLongitudinal([], [])


def test_longitudinal_names_the_first_dataset_at_fault():
    # Each fault is in dataset 1 of 2: not a DataFrame, empty, or without its identifier.
    first, second = years()
    with pytest.raises(TypeError, match=exactly("Dataset 1 must be a pandas DataFrame.")):
        BVMLongitudinal([first.to_dict(), second], ["id", "key"])
    with pytest.raises(ValueError, match=exactly("Dataset 1 cannot be empty.")):
        BVMLongitudinal([first.iloc[0:0], second], ["id", "key"])
    with pytest.raises(ValueError, match=exactly("key is not an attribute of dataset 1.")):
        BVMLongitudinal([first, second], ["key", "key"])


def test_longitudinal_keeps_its_own_list_of_datasets():
    # A dataset added to the caller's list afterwards is not part of the assessment: a is a column
    # of the first dataset only, and each of its two rows is a class of its own.
    first, second = years()
    datasets = [first]
    bvm = BVMLongitudinal(datasets, ["id"])
    datasets.append(second)
    bvm.qids(["a"])
    row = bvm.assess()["re_id"].iloc[0]
    assert row["pCR"] == 2
    assert row["dCR"] == pytest.approx(1.0)


def test_longitudinal_rejects_a_dataset_that_is_not_a_dataframe():
    first, second = years()
    with pytest.raises(TypeError, match=exactly("Dataset 2 must be a pandas DataFrame.")):
        BVMLongitudinal([first, second.to_dict()], ["id", "key"])


def test_longitudinal_rejects_an_empty_dataset():
    first, second = years()
    with pytest.raises(ValueError, match=exactly("Dataset 2 cannot be empty.")):
        BVMLongitudinal([first, second.iloc[0:0]], ["id", "key"])


def test_longitudinal_rejects_an_identifier_that_is_not_a_string():
    first, second = years()
    with pytest.raises(TypeError, match=exactly(DATASETS)):
        BVMLongitudinal([first, second], ["id", 0])


def test_longitudinal_checks_an_empty_identifier_like_any_name():
    first, second = years()
    with pytest.raises(ValueError, match=exactly(" is not an attribute of dataset 2.")):
        BVMLongitudinal([first, second], ["id", ""])
    # A column named "" is an identifier like any other. On a and b, each row is a class of its own.
    bvm = BVMLongitudinal([first.rename(columns={"id": ""}), second], ["", "key"])
    bvm.qids([["a"], ["b"]])
    row = bvm.assess()["re_id"].iloc[0]
    assert row["pCR"] == 2
    assert row["dCR"] == pytest.approx(1.0)


def test_longitudinal_rejects_an_identifier_that_is_not_an_attribute():
    # "id" is a column of the first dataset only.
    first, second = years()
    message = exactly("id is not an attribute of dataset 2.")
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
    with pytest.raises(TypeError, match=exactly(QID_LISTS)):
        longitudinal().qids([["a"], [1]])


@pytest.mark.parametrize("names", [[["a", ARRAY], ["a", "s"]], ["a", ARRAY]],
                         ids=["nested", "flat"])
def test_longitudinal_qids_reject_an_array_after_a_name(names):
    with pytest.raises(TypeError, match=exactly(QID_LISTS)):
        named_alike(2).qids(names)


@pytest.mark.parametrize("names, name", [([["zz"], ["b"]], "zz"), (["key"], "key")],
                         ids=["nested", "flat"])
def test_longitudinal_qids_name_the_first_dataset_without_a_name(names, name):
    # Dataset 1 has neither zz nor key; key is a column of dataset 2.
    with pytest.raises(ValueError, match=exactly(name + " is not an attribute of dataset 1.")):
        longitudinal().qids(names)


def test_longitudinal_qids_name_the_first_of_several_datasets_without_a_name():
    # A flat list: zz is a column of dataset 1 only, so datasets 2 and 3 both lack it.
    first = pandas.DataFrame({"id": [1, 2], "zz": [1, 2]})
    other = pandas.DataFrame({"id": [1, 2], "a": [3, 4]})
    bvm = BVMLongitudinal([first, other, other], ["id"] * 3)
    with pytest.raises(ValueError, match=exactly("zz is not an attribute of dataset 2.")):
        bvm.qids(["zz"])


def test_longitudinal_qids_reject_a_name_that_is_not_an_attribute_of_its_dataset():
    # "a" is a column of the first dataset, not of the second.
    with pytest.raises(ValueError, match=exactly("a is not an attribute of dataset 2.")):
        longitudinal().qids([["a"], ["a"]])


@pytest.mark.parametrize("names", [[1], [1, "a"], [None], [("a",)]], ids=repr)
def test_longitudinal_qids_reject_a_first_entry_that_is_neither_a_list_nor_a_string(names):
    with pytest.raises(TypeError, match=exactly(QID_LISTS)):
        longitudinal().qids(names)


@pytest.mark.parametrize("count", [1, 2, 3])
def test_longitudinal_qids_accept_an_empty_list_and_assess_returns_none(count):
    # The empty list replaces the earlier one: no quasi-identifiers, nothing to assess.
    bvm = named_alike(count)
    bvm.qids(["a"])
    bvm.qids([])
    bvm.sensitive(["s"])
    assert bvm.assess() is None


@pytest.mark.parametrize("names", [[[], []], [[], ["b"]]], ids=repr)
def test_longitudinal_qids_reject_empty_lists_for_the_datasets(names):
    with pytest.raises(ValueError, match=exactly(LIST_PER_DATASET)):
        longitudinal().qids(names)


@pytest.mark.parametrize("names", [[["a"]], [["a"], ["b"], ["b"]], [["a"], ["b"], []]], ids=repr)
def test_longitudinal_qids_reject_a_number_of_lists_other_than_of_datasets(names):
    # Two datasets, so two lists.
    with pytest.raises(ValueError, match=exactly(LIST_PER_DATASET)):
        longitudinal().qids(names)


@pytest.mark.parametrize("names", [[["a", "s"], ["b"]], [["a"], ["b", "t"]], [["a"], []]],
                         ids=repr)
def test_longitudinal_qids_reject_lists_of_unequal_lengths(names):
    with pytest.raises(ValueError, match=exactly(LIST_PER_DATASET)):
        longitudinal().qids(names)


@pytest.mark.parametrize("names, name, dataset", [
    ([["a", "a"], ["b", "t"]], "a", 1),
    ([["a", "s"], ["b", "b"]], "b", 2),
], ids=repr)
def test_longitudinal_qids_reject_a_name_listed_twice_in_a_list(names, name, dataset):
    with pytest.raises(ValueError, match=exactly(twice_for(name, dataset))):
        longitudinal().qids(names)


@pytest.mark.parametrize("count, names, dataset", [
    (1, [["a", "a"]], 1),
    (1, ["a", "a"], 1),
    # A flat list is every dataset's list, so the first is named.
    (2, ["a", "s", "a"], 1),
    (2, [["a", "s"], ["a", "a"]], 2),
], ids=repr)
def test_longitudinal_qids_reject_a_name_listed_twice_for_datasets_named_alike(count, names,
                                                                               dataset):
    with pytest.raises(ValueError, match=exactly(twice_for("a", dataset))):
        named_alike(count).qids(names)


@pytest.mark.parametrize("names, name, dataset", [
    ([["a", "id"], ["b", "t"]], "id", 1),
    ([["a", "s"], ["b", "key"]], "key", 2),
    ([["id"], ["key"]], "id", 1),
    ([["id", "a"], ["b", "t"]], "id", 1),
], ids=repr)
def test_longitudinal_qids_reject_a_datasets_identifier_among_its_own(names, name, dataset):
    with pytest.raises(ValueError, match=exactly(identifier_of(name, dataset))):
        longitudinal().qids(names)


def test_longitudinal_qids_reject_an_identifier_in_a_flat_list():
    with pytest.raises(ValueError, match=exactly(identifier_of("id", 1))):
        named_alike(2).qids(["a", "id"])
    with pytest.raises(ValueError, match=exactly(identifier_of("id", 1))):
        named_alike(2).qids(["id", "a"])
    # key is a column of both datasets, and the identifier of the second only, then of the first
    # only.
    first = pandas.DataFrame({"id": [1, 2], "key": [5, 6], "a": [1, 2]})
    second = pandas.DataFrame({"key": [1, 2], "a": [3, 4]})
    with pytest.raises(ValueError, match=exactly(identifier_of("key", 2))):
        BVMLongitudinal([first, second], ["id", "key"]).qids(["a", "key"])
    with pytest.raises(ValueError, match=exactly(identifier_of("key", 1))):
        BVMLongitudinal([second, first], ["key", "id"]).qids(["a", "key"])


@pytest.mark.parametrize("names, dataset", [([["a"], ["a"], ["id"]], 3), (["a", "id"], 1)],
                         ids=repr)
def test_three_datasets_reject_an_identifier_among_the_quasi_identifiers(names, dataset):
    with pytest.raises(ValueError, match=exactly(identifier_of("id", dataset))):
        named_alike(3).qids(names)


def test_a_rejected_call_keeps_the_earlier_longitudinal_quasi_identifiers():
    bvm = longitudinal()
    bvm.qids([["a"], ["b"]])
    with pytest.raises(ValueError):
        bvm.qids([["a", "s"], ["b"]])
    # On a and b, the classes are (1, 3) and (2, 4): each row is alone in its class.
    row = bvm.assess()["re_id"].iloc[0]
    assert row["QID"] == "['a']"
    assert row["pCR"] == 2
    assert row["dCR"] == pytest.approx(1.0)


def test_a_call_rejected_for_an_overlap_keeps_the_earlier_lists():
    # On a and b, the classes are (1, 3) and (2, 4).
    bvm = longitudinal()
    bvm.qids([["a"], ["b"]])
    bvm.sensitive(["s"])
    with pytest.raises(ValueError, match=exactly("a" + BOTH)):
        bvm.sensitive(["s", "a"])
    with pytest.raises(ValueError, match=exactly("s" + BOTH)):
        bvm.qids([["a", "s"], ["b", "t"]])
    expect_a_and_s(bvm.assess())


def test_later_changes_to_the_callers_longitudinal_lists_change_nothing():
    bvm = longitudinal()
    quasi_identifiers = [["a"], ["b"]]
    sensitive_attributes = ["s"]
    bvm.qids(quasi_identifiers)
    bvm.sensitive(sensitive_attributes)
    # Each would fail the checks: lists of unequal lengths, the second dataset's identifier
    # among its quasi-identifiers, a sensitive attribute among the focal ones.
    quasi_identifiers[0].append("s")
    quasi_identifiers[1][0] = "key"
    sensitive_attributes.append("a")
    expect_a_and_s(bvm.assess())

    # A flat list, given for both datasets.
    bvm = named_alike(2)
    quasi_identifiers = ["a"]
    bvm.qids(quasi_identifiers)
    quasi_identifiers.append("id")
    row = bvm.assess()["re_id"].iloc[0]
    assert row["QID"] == "['a']"
    assert row["pCR"] == 2


@pytest.mark.parametrize("names", ["s", ("s",), None])
def test_longitudinal_sensitive_rejects_an_argument_that_is_not_a_list(names):
    with pytest.raises(TypeError, match=exactly(STRINGS)):
        longitudinal().sensitive(names)


@pytest.mark.parametrize("names", [["s", 1], ["s", ARRAY]], ids=["number", "array"])
def test_longitudinal_sensitive_rejects_a_name_that_is_not_a_string(names):
    with pytest.raises(TypeError, match=exactly(STRINGS)):
        longitudinal().sensitive(names)


def test_longitudinal_sensitive_rejects_a_name_not_in_the_focal_dataset():
    # "t" is a column of the second dataset only.
    message = exactly("t is not an attribute of dataset 1.")
    with pytest.raises(ValueError, match=message):
        longitudinal().sensitive(["t"])


def test_longitudinal_sensitive_rejects_a_name_listed_twice():
    with pytest.raises(ValueError, match=exactly(twice_for("s", 1))):
        longitudinal().sensitive(["s", "s"])


@pytest.mark.parametrize("count", [1, 2])
def test_longitudinal_sensitive_accepts_an_empty_list_as_no_sensitive_attributes(count):
    # The empty list replaces the earlier one: re-identification only, as without sensitive().
    bvm = named_alike(count)
    bvm.qids(["a"])
    bvm.sensitive(["s"])
    bvm.sensitive([])
    with pytest.raises(ValueError, match=exactly(NO_SENSITIVE_YET)):
        bvm.worth("s", {"x": 1})
    plain = named_alike(count)
    plain.qids(["a"])
    results, expected = bvm.assess(), plain.assess()
    assert list(results) == list(expected) == ["re_id", "dCR", "pCR", "bins"]
    pandas.testing.assert_frame_equal(results["re_id"], expected["re_id"])


@pytest.mark.parametrize("sensitive_first", [False, True], ids=["qids_first", "sensitive_first"])
def test_longitudinal_rejects_a_sensitive_attribute_among_flat_quasi_identifiers(sensitive_first):
    bvm = named_alike(2)
    if sensitive_first:
        bvm.sensitive(["s"])
        with pytest.raises(ValueError, match=exactly("s" + BOTH)):
            bvm.qids(["a", "s"])
    else:
        bvm.qids(["a", "s"])
        with pytest.raises(ValueError, match=exactly("s" + BOTH)):
            bvm.sensitive(["s"])


def test_longitudinal_ids_reports_each_identifier(capsys):
    longitudinal().ids()
    assert capsys.readouterr().out == ("Identifying attribute for dataset 1: id.\n"
                                       "Identifying attribute for dataset 2: key.\n")


def test_longitudinal_assess_needs_quasi_identifiers():
    with pytest.raises(ValueError, match=exactly(NO_QIDS)):
        longitudinal().assess()
