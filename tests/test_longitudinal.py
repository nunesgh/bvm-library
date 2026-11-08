# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2021-2026 Gabriel Henrique Lopes Gomes Alves Nunes

# BVMLongitudinal. With two or more datasets, the later ones are left-joined onto the focal one by
# their identifiers, and the rows' classes are those of the lists of each quasi-identifier's values
# in all the datasets, each value counted by its text, str(value). In each position a missing value
# (pandas.isna) is one value of its own and a row absent from a later dataset another, neither
# equal to any real value. Expected values are worked out by hand, except on random tables, whose
# results must equal BVM's on the table of the text join, text_join below.

import random
import re

import pandas
import pytest

from bvmlib.bvm import BVM, BVMLongitudinal

NAN = float("nan")

LABELS = ["(" + str(k - 1) + ", " + str(k) + "]" for k in range(1, 101)]

DATASETS = ("A non-empty list of pandas DataFrames and a non-empty list of identifying "
            "attributes, each a string or a list holding one string, both with the same "
            "length, must be provided.")
NOT_FOUND = " is not a string or is not an attribute of the respective dataset."


def histogram(fractions):
    "The full 100-bin histogram with the given fractions and 0 in every other bin."
    assert set(fractions) <= set(LABELS)
    return {label: fractions.get(label, 0) for label in LABELS}


def exactly(message):
    "A pattern that matches the whole message and nothing else."
    return "^" + re.escape(message) + "$"


def text(values):
    "A column of dtype object, so that pandas keeps each value as it is."
    return pandas.Series(values, dtype=object)


def assess(datasets, identifiers, qids, sensitive=None, worth=None):
    bvm = BVMLongitudinal(datasets, identifiers)
    bvm.qids(qids)
    if sensitive is not None:
        bvm.sensitive(sensitive)
    for attribute, assignment in (worth or {}).items():
        bvm.worth(attribute, assignment)
    return bvm.assess()


def expect_re_id(results, dCR, pCR, rows, bins):
    assert len(results["re_id"]) == 1
    row = results["re_id"].iloc[0]
    assert row["pCR"] == pCR
    assert row["dCR"] == pytest.approx(dCR)
    assert row["Prior"] == pytest.approx(1 / rows)
    assert row["Posterior"] == pytest.approx(pCR / rows)
    assert row["Histogram"] == pytest.approx(histogram(bins))


def expect_att_inf(results, attribute, dCA, pCA, prior, posterior, bins):
    rows = results["att_inf"][results["att_inf"]["Sensitive"] == attribute]
    assert len(rows) == 1
    row = rows.iloc[0]
    assert row["dCA"] == pytest.approx(dCA)
    assert row["pCA"] == pytest.approx(pCA)
    assert row["Prior"] == pytest.approx(prior)
    assert row["Posterior"] == pytest.approx(posterior)
    assert row["Histogram"] == pytest.approx(histogram(bins))


def expect_same_results(actual, expected):
    assert list(actual) == list(expected)
    for key in expected:
        if isinstance(expected[key], pandas.DataFrame):
            pandas.testing.assert_frame_equal(actual[key], expected[key], check_exact=True)
        else:
            assert actual[key] == expected[key]


# Three datasets, each with its own names. s overall: a 3, b 1, of 4 rows.
FOCAL = pandas.DataFrame({"id": [1, 2, 3, 4], "q": [1, 1, 1, 2], "s": ["a", "b", "a", "a"]})
SECOND = pandas.DataFrame({"key": [4, 3, 2, 1], "r": [5, 5, 5, 5]})
THIRD = pandas.DataFrame({"code": [1, 2, 3, 4], "t": [7, 7, 8, 8]})


def test_two_datasets_with_other_names():
    # Classes: (1, 5) ids 1 to 3, (2, 5) id 4.
    results = assess([FOCAL, SECOND], ["id", "key"], [["q"], ["r"]])
    expect_re_id(results, dCR=1 / 4, pCR=2, rows=4, bins={"(33, 34]": 3 / 4, "(99, 100]": 1 / 4})


def test_three_datasets_with_other_names():
    # Classes: (1, 5, 7) ids 1 and 2, (1, 5, 8) id 3, (2, 5, 8) id 4. s: {a, b}, {a}, {a}.
    results = assess([FOCAL, SECOND, THIRD], ["id", "key", "code"], [["q"], ["r"], ["t"]], ["s"])
    bins = {"(49, 50]": 2 / 4, "(99, 100]": 2 / 4}
    expect_re_id(results, dCR=2 / 4, pCR=3, rows=4, bins=bins)
    expect_att_inf(results, "s", dCA=2 / 4, pCA=1, prior=3 / 4, posterior=3 / 4, bins=bins)


# One flat list of quasi-identifiers, for datasets that use the same names. By id, the second
# dataset holds q 9 for all and r: y, y, x, x.
SAME_FIRST = pandas.DataFrame({"id": [1, 2, 3, 4], "q": [1, 1, 2, 2], "r": ["x", "y", "x", "x"],
                               "s": ["a", "a", "a", "a"]})
SAME_SECOND = pandas.DataFrame({"id": [4, 3, 2, 1], "q": [9, 9, 9, 9], "r": ["x", "x", "y", "y"]})


def test_a_flat_list_of_quasi_identifiers():
    # Classes: (1 9, x y) id 1, (1 9, y y) id 2, (2 9, x x) ids 3 and 4.
    flat = assess([SAME_FIRST, SAME_SECOND], ["id", "id"], ["q", "r"])
    expect_re_id(flat, dCR=2 / 4, pCR=3, rows=4, bins={"(99, 100]": 2 / 4, "(49, 50]": 2 / 4})
    assert flat["re_id"].iloc[0]["QID"] == "['q', 'r']"

    nested = assess([SAME_FIRST, SAME_SECOND], ["id", "id"], [["q", "r"], ["q", "r"]])
    expect_same_results(flat, nested)


def test_a_flat_list_of_quasi_identifiers_for_three_datasets():
    # By id, the third dataset holds q 0, absent, 0, 1 and r z, absent, z, z. Every row is a class
    # of its own: ids 3 and 4, alike in the first two, differ by q in the third.
    third = pandas.DataFrame({"id": [3, 4, 1], "q": [0, 1, 0], "r": ["z", "z", "z"]})
    datasets = [SAME_FIRST, SAME_SECOND, third]
    flat = assess(datasets, [["id"]] * 3, ["q", "r"])
    expect_re_id(flat, dCR=1, pCR=4, rows=4, bins={"(99, 100]": 1})
    expect_same_results(flat, assess(datasets, ["id"] * 3, [["q", "r"]] * 3))


@pytest.mark.parametrize("names, error, message", [
    (["q", 1], TypeError, "1" + NOT_FOUND),
    (["q", ["r"]], TypeError, "['r']" + NOT_FOUND),
    # s is a column of the first dataset only.
    (["q", "s"], ValueError, "s" + NOT_FOUND),
])
def test_a_flat_list_with_an_invalid_name(names, error, message):
    bvm = BVMLongitudinal([SAME_FIRST, SAME_SECOND], ["id", "id"])
    with pytest.raises(error, match=exactly(message)):
        bvm.qids(names)


# Identifiers as lists, the shape of the 2014-2017 notebook's call.


def test_an_identifier_given_as_a_list_of_one_string():
    # Classes by q: 1 ids 1 to 3, s {a, b, a}; 2 id 4, s {a}.
    results = assess([FOCAL], [["id"]], [["q"]], ["s"])
    expect_re_id(results, dCR=1 / 4, pCR=2, rows=4, bins={"(33, 34]": 3 / 4, "(99, 100]": 1 / 4})
    expect_att_inf(results, "s", dCA=1 / 4, pCA=1, prior=3 / 4, posterior=3 / 4,
                   bins={"(66, 67]": 3 / 4, "(99, 100]": 1 / 4})
    expect_same_results(results, assess([FOCAL], ["id"], [["q"]], ["s"]))

    identifiers = [["id"], "key", ["code"]]
    mixed = assess([FOCAL, SECOND, THIRD], identifiers, [["q"], ["r"], ["t"]], ["s"])
    expect_same_results(mixed, assess([FOCAL, SECOND, THIRD], ["id", "key", "code"],
                                      [["q"], ["r"], ["t"]], ["s"]))
    # Guard: the caller's list is left as it was.
    assert identifiers == [["id"], "key", ["code"]]


def test_ids_reports_an_identifier_given_as_a_list(capsys):
    BVMLongitudinal([FOCAL, SECOND], [["id"], ["key"]]).ids()
    assert capsys.readouterr().out == ("Identifying attribute for dataset 1: id.\n"
                                       "Identifying attribute for dataset 2: key.\n")


def test_a_list_of_several_identifiers_is_refused():
    message = ("['key', 'r'] lists several identifying attributes: each dataset is linked by one, "
               "a string or a list holding one string.")
    with pytest.raises(ValueError, match=exactly(message)):
        BVMLongitudinal([FOCAL, SECOND], ["id", ["key", "r"]])


@pytest.mark.parametrize("identifier, error, message", [
    ([], TypeError, DATASETS),
    ([["id"]], TypeError, DATASETS),
    ([1], TypeError, DATASETS),
    (["id", 1], TypeError, DATASETS),
    ([""], ValueError, DATASETS),
    (["r"], ValueError, "0 is not an attribute of the respective dataset."),
])
def test_other_lists_are_refused_as_identifiers(identifier, error, message):
    with pytest.raises(error, match=exactly(message)):
        BVMLongitudinal([FOCAL], [identifier])


# Missing values and absent rows.


def test_a_missing_value_and_an_absent_row_are_two_values():
    # Classes: (x, missing) ids 1 to 3, NaN and None alike; (x, absent) ids 4 and 5.
    first = pandas.DataFrame({"id": [1, 2, 3, 4, 5], "q": ["x", "x", "x", "x", "x"]})
    second = pandas.DataFrame({"id": [1, 2, 3], "q": text([NAN, None, NAN])})
    results = assess([first, second], ["id", "id"], [["q"], ["q"]])
    expect_re_id(results, dCR=0, pCR=2, rows=5, bins={"(33, 34]": 3 / 5, "(49, 50]": 2 / 5})


@pytest.mark.parametrize("dtype, value, missing", [
    ("float64", 1.0, NAN),
    (object, "1", None),
    ("Int64", 1, pandas.NA),
    ("string", "1", pandas.NA),
    ("datetime64[ns]", pandas.Timestamp("2020-01-01"), pandas.NaT),
], ids=["NaN", "None", "Int64 NA", "string NA", "NaT"])
def test_each_kind_of_missing_value_is_apart_from_absent_rows(dtype, value, missing):
    # Classes: (value, value) id 1, (value, missing) id 2, (missing, missing) ids 3 and 5,
    # (missing, absent) id 4.
    first = pandas.DataFrame({"id": [1, 2, 3, 4, 5], "q": pandas.Series(
        [value, value, missing, missing, missing], dtype=dtype)})
    second = pandas.DataFrame({"id": [1, 2, 3, 5], "q": pandas.Series(
        [value, missing, missing, missing], dtype=dtype)})
    results = assess([first, second], ["id", "id"], [["q"], ["q"]])
    expect_re_id(results, dCR=3 / 5, pCR=4, rows=5, bins={"(49, 50]": 2 / 5, "(99, 100]": 3 / 5})


def test_missing_values_and_absent_rows_are_apart_from_the_texts_nan_and_none():
    # In the focal dataset: (missing, y) ids 1 and 2, ("nan", y) id 3, ("None", y) id 4.
    first = pandas.DataFrame({"id": [1, 2, 3, 4], "q": text([NAN, None, "nan", "None"])})
    second = pandas.DataFrame({"id": [1, 2, 3, 4], "q": ["y", "y", "y", "y"]})
    results = assess([first, second], ["id", "id"], [["q"], ["q"]])
    expect_re_id(results, dCR=2 / 4, pCR=3, rows=4, bins={"(49, 50]": 2 / 4, "(99, 100]": 2 / 4})

    # In the later one: (x, missing) ids 1 and 3, (x, "nan") id 2, (x, "None") id 4, (x, absent)
    # id 5.
    first = pandas.DataFrame({"id": [1, 2, 3, 4, 5], "q": ["x", "x", "x", "x", "x"]})
    second = pandas.DataFrame({"id": [1, 2, 3, 4], "q": text([NAN, "nan", None, "None"])})
    results = assess([first, second], ["id", "id"], [["q"], ["q"]])
    expect_re_id(results, dCR=3 / 5, pCR=4, rows=5, bins={"(49, 50]": 2 / 5, "(99, 100]": 3 / 5})


def test_missing_values_and_absent_rows_are_apart_from_any_text():
    # Texts that hold a backslash: (\missing, \absent) id 1, (missing, \absent) id 2, (\absent,
    # \absent) id 3, (\absent, absent) id 4, all four classes apart.
    first = pandas.DataFrame({"id": [1, 2, 3, 4], "q": text(["\\missing", NAN, "\\absent",
                                                              "\\absent"])})
    second = pandas.DataFrame({"id": [1, 2, 3], "q": ["\\absent", "\\absent", "\\absent"]})
    results = assess([first, second], ["id", "id"], [["q"], ["q"]])
    expect_re_id(results, dCR=1, pCR=4, rows=4, bins={"(99, 100]": 1})


def test_missing_values_and_absent_rows_are_apart_from_the_texts_missing_and_absent():
    # ("missing", z) id 1, (missing, z) id 2, (y, "absent") id 3, (y, absent) id 4, all apart.
    first = pandas.DataFrame({"id": [1, 2, 3, 4], "q": text(["missing", NAN, "y", "y"])})
    second = pandas.DataFrame({"id": [1, 2, 3], "q": ["z", "z", "absent"]})
    results = assess([first, second], ["id", "id"], [["q"], ["q"]])
    expect_re_id(results, dCR=1, pCR=4, rows=4, bins={"(99, 100]": 1})


def test_values_holding_a_hash_never_join_into_the_same_value():
    # Classes: ("a#b", "c") ids 1 and 5, ("a", "b#c") id 2, ("a\", "#b") id 3, ("a\#", "b") id 4.
    first = pandas.DataFrame({"id": [1, 2, 3, 4, 5], "q": ["a#b", "a", "a\\", "a\\#", "a#b"]})
    second = pandas.DataFrame({"id": [1, 2, 3, 4, 5], "q": ["c", "b#c", "#b", "b", "c"]})
    results = assess([first, second], ["id", "id"], [["q"], ["q"]])
    expect_re_id(results, dCR=3 / 5, pCR=4, rows=5, bins={"(49, 50]": 2 / 5, "(99, 100]": 3 / 5})


def test_no_two_pairs_of_values_join_into_the_same_value():
    # Every pair of 14 values, each a missing value or a text of at most two characters from "a",
    # "#" and "\", among them ("\", "#") and ("#\", ""); then each value with the second absent.
    # Every one of the 14 * 14 + 14 rows is a class of its own.
    values = [""] + list("a#\\") + [x + y for x in "a#\\" for y in "a#\\"] + [NAN]
    pairs = [(x, y) for x in values for y in values]
    first = pandas.DataFrame({"id": range(len(pairs) + len(values)),
                              "q": text([x for x, _ in pairs] + values)})
    second = pandas.DataFrame({"id": range(len(pairs)), "q": text([y for _, y in pairs])})
    results = assess([first, second], ["id", "id"], [["q"], ["q"]])
    expect_re_id(results, dCR=1, pCR=14 * 14 + 14, rows=14 * 14 + 14, bins={"(99, 100]": 1})


def test_a_categorical_quasi_identifier_counts_by_its_text():
    # Classes: (x, u) id 1, (x, v) id 2, (y, v) ids 3 and 4.
    first = pandas.DataFrame({"id": [1, 2, 3, 4], "q": pandas.Categorical(["x", "x", "y", "y"])})
    second = pandas.DataFrame({"id": [1, 2, 3, 4], "q": pandas.Categorical(["u", "v", "v", "v"])})
    results = assess([first, second], ["id", "id"], [["q"], ["q"]])
    expect_re_id(results, dCR=2 / 4, pCR=3, rows=4, bins={"(99, 100]": 2 / 4, "(49, 50]": 2 / 4})


# Without missing values, absent rows, or the texts "nan", "None" and "#", the classes are those of
# the text "<first>#<second>...".


def test_classes_without_missing_values_are_those_of_the_text_join():
    # The second dataset's r holds 1 and "1", one text. Texts: "1#1#0.5" ids 1 and 2, "1#2#0.5"
    # id 3, "2#2#0.5" id 4, "2#1#1.5" ids 5 and 6. s: {a, b}, {a}, {a}, {a, b}; overall a 4, b 2.
    first = pandas.DataFrame({"id": [1, 2, 3, 4, 5, 6], "q": [1, 1, 1, 2, 2, 2],
                              "s": ["a", "b", "a", "a", "a", "b"]})
    second = pandas.DataFrame({"key": [6, 5, 4, 3, 2, 1], "r": text([1, "1", 2, 2, 1, 1])})
    third = pandas.DataFrame({"code": [1, 2, 3, 4, 5, 6], "t": [0.5, 0.5, 0.5, 0.5, 1.5, 1.5]})

    # Worth: Prior max(4/6 * 1, 2/6 * 3) = 1; Posterior (max(1, 3) + 1 + 1 + max(1, 3)) / 6.
    results = assess([first, second, third], ["id", "key", "code"], [["q"], ["r"], ["t"]], ["s"],
                     {"s": {"a": 1, "b": 3}})
    bins = {"(49, 50]": 4 / 6, "(99, 100]": 2 / 6}
    expect_re_id(results, dCR=2 / 6, pCR=4, rows=6, bins=bins)
    expect_att_inf(results, "s", dCA=2 / 6, pCA=1, prior=4 / 6, posterior=4 / 6, bins=bins)
    row = results["information_worth"].iloc[0]
    assert row["Prior Worth"] == pytest.approx(1)
    assert row["Posterior Worth"] == pytest.approx(8 / 6)


def text_join(datasets, identifiers, qids):
    "The table the text join gives: each quasi-identifier as '<first>#<second>...'."
    joined = datasets[0]
    for dataset, identifier, names in zip(datasets[1:], identifiers[1:], qids[1:]):
        later = dataset[[identifier] + names].set_axis([identifiers[0]] + qids[0], axis=1)
        joined = pandas.merge(joined, later, how="left", on=identifiers[0])
        for name in qids[0]:
            joined[name] = joined[name + "_x"].map(str) + "#" + joined[name + "_y"].map(str)
            joined = joined.drop(columns=[name + "_x", name + "_y"])
    return joined


@pytest.mark.parametrize("seed", range(30))
def test_results_without_missing_values_equal_those_of_the_text_join(seed):
    # Random tables in which every focal identifier is in every later dataset, some twice, and no
    # value is missing or holds "#": the results equal BVM's on the text join's table.
    rng = random.Random(seed)
    pools = [[1, 2, 3], [0.5, 1.5, -2.0], ["a", "b", "c\\", "\\d"], [1, "1", 2, "x"]]
    names = ["q", "r"]
    rows = rng.randint(1, 30)
    focal = pandas.DataFrame({"id": range(rows), "s": [rng.choice("xyz") for _ in range(rows)],
                              **{name: [rng.choice(pools[k]) for _ in range(rows)]
                                 for k, name in enumerate(names)}})
    datasets, identifiers, qids = [focal], ["id"], [names]
    for i in range(1, rng.randint(2, 4)):
        keys = list(range(rows)) + [rng.randrange(rows + 3) for _ in range(rng.randint(0, 5))]
        rng.shuffle(keys)
        later_names = [name + str(i) for name in names]
        datasets.append(pandas.DataFrame({"key" + str(i): keys, **{
            name: [rng.choice(pools[rng.randrange(4)]) for _ in keys] for name in later_names}}))
        identifiers.append("key" + str(i))
        qids.append(later_names)
    worth = {"s": {"x": 0.1, "y": 0.7, "z": 0.3}}

    expected = BVM(text_join(datasets, identifiers, qids))
    expected.qids(names)
    expected.sensitive(["s"])
    expected.worth("s", worth["s"])
    expect_same_results(assess(datasets, identifiers, qids, ["s"], worth), expected.assess())


# Columns named alike.


def test_a_later_dataset_may_hold_columns_named_like_the_focal_ones():
    # The later dataset's own s, extra, q and id are not joined. Classes: (1, 5) id 1, (1, 6) id 2,
    # (2, 7) ids 3 and 4. s: {a}, {b}, {a, a}; overall a 3, b 1. extra is 0 throughout.
    first = pandas.DataFrame({"id": [1, 2, 3, 4], "q": [1, 1, 2, 2], "s": ["a", "b", "a", "a"],
                              "extra": [0, 0, 0, 0]})
    second = pandas.DataFrame({"key": [1, 2, 3, 4], "r": [5, 6, 7, 7], "s": ["z", "z", "z", "z"],
                               "extra": [1, 1, 1, 1], "q": [0, 0, 0, 0], "id": [9, 9, 9, 9]})
    results = assess([first, second], ["id", "key"], [["q"], ["r"]], ["s", "extra"])
    expect_re_id(results, dCR=2 / 4, pCR=3, rows=4, bins={"(99, 100]": 2 / 4, "(49, 50]": 2 / 4})
    expect_att_inf(results, "s", dCA=1, pCA=4 / 3, prior=3 / 4, posterior=1,
                   bins={"(99, 100]": 1})
    expect_att_inf(results, "extra", dCA=0, pCA=1, prior=1, posterior=1, bins={"(99, 100]": 1})


def test_the_focal_dataset_may_hold_columns_of_any_name():
    # Columns named after the second quasi-identifier, q, not the first, p. Classes: (0 6, 1 5)
    # ids 1 and 2, (0 6, 2 5) id 3. q_x and q# are 0 throughout.
    first = pandas.DataFrame({"id": [1, 2, 3], "p": [0, 0, 0], "q": [1, 1, 2], "q_x": [0, 0, 0],
                              "q_y": [0, 0, 0], "q#": [0, 0, 0], "q##": [0, 0, 0]})
    second = pandas.DataFrame({"id": [1, 2, 3], "p": [6, 6, 6], "q": [5, 5, 5]})
    results = assess([first, second], ["id", "id"], [["p", "q"], ["p", "q"]], ["q_x", "q#"])
    expect_re_id(results, dCR=1 / 3, pCR=2, rows=3, bins={"(49, 50]": 2 / 3, "(99, 100]": 1 / 3})
    for attribute in ["q_x", "q#"]:
        expect_att_inf(results, attribute, dCA=0, pCA=1, prior=1, posterior=1,
                       bins={"(99, 100]": 1})


def test_datasets_taken_from_one_larger_table():
    # Each year's rows of one table, so that neither dataset's index is 0, 1, 2, ... By id, the
    # second year holds q 5, 5, 5 and no row for id 4, and an id 9 not in the first. Classes:
    # (1, 5) ids 1 to 3, (1, absent) id 4.
    table = pandas.DataFrame({"year": [1, 2, 1, 2, 2, 1, 2, 1], "id": [1, 3, 2, 2, 9, 3, 1, 4],
                              "q": [1, 5, 1, 5, 7, 1, 5, 1]})
    first = table[table["year"] == 1]
    second = table[table["year"] == 2]
    results = assess([first, second], ["id", "id"], [["q"], ["q"]])
    expect_re_id(results, dCR=1 / 4, pCR=2, rows=4, bins={"(33, 34]": 3 / 4, "(99, 100]": 1 / 4})


# The 2014-2017 notebook's call shape: identifiers as lists of one string, the focal dataset's
# names apart from the later ones', two sensitive attributes. By student, need 0 0 1 0 0 1 and
# transport a b a a b b; overall need 0 4, transport a 3, b 3, of 6 rows.
YEAR_1 = pandas.DataFrame({"student": [1, 2, 3, 4, 5, 6], "city": [10, 10, 10, 10, 20, 20],
                           "school": [1, 1, 2, 2, 3, 3], "need": [0, 0, 1, 0, 0, 1],
                           "transport": ["a", "b", "a", "a", "b", "b"]})
# Students 1 to 6 as in the first year but student 2's school, and student 7.
YEAR_2 = pandas.DataFrame({"person": [6, 5, 4, 3, 2, 1, 7],
                           "city_code": [20, 20, 10, 10, 10, 10, 30],
                           "school_code": [3, 3, 2, 2, 5, 1, 9]})
# Student 5 is absent, student 6 has missing values.
YEAR_3 = pandas.DataFrame({"person": [1, 2, 3, 4, 6], "city_code": [10, 10, 10, 10, NAN],
                           "school_code": [1, 5, 2, 2, NAN]})
# Students 5 and 6 are absent, student 4 changes school.
YEAR_4 = pandas.DataFrame({"person": [1, 2, 3, 4], "city_code": [10, 10, 10, 10],
                           "school_code": [1, 5, 2, 4]})

NOTEBOOK = {
    # Classes: (10, 1) students 1 and 2, (10, 2) 3 and 4, (20, 3) 5 and 6.
    1: {"re_id": {"dCR": 0, "pCR": 3, "bins": {"(49, 50]": 1}},
        "need": {"dCA": 2 / 6, "pCA": 1, "prior": 4 / 6, "posterior": 4 / 6,
                 "bins": {"(99, 100]": 2 / 6, "(49, 50]": 4 / 6}},
        "transport": {"dCA": 4 / 6, "pCA": 5 / 3, "prior": 3 / 6, "posterior": 5 / 6,
                      "bins": {"(49, 50]": 2 / 6, "(99, 100]": 4 / 6}}},
    # Classes: students 1, 2, 3 and 4, 5 and 6.
    2: {"re_id": {"dCR": 2 / 6, "pCR": 4, "bins": {"(99, 100]": 2 / 6, "(49, 50]": 4 / 6}},
        "need": {"dCA": 2 / 6, "pCA": 1, "prior": 4 / 6, "posterior": 4 / 6,
                 "bins": {"(99, 100]": 2 / 6, "(49, 50]": 4 / 6}},
        "transport": {"dCA": 1, "pCA": 2, "prior": 3 / 6, "posterior": 1,
                      "bins": {"(99, 100]": 1}}},
    # Classes: students 1, 2, 3 and 4, 5 (absent), 6 (missing).
    3: {"re_id": {"dCR": 4 / 6, "pCR": 5, "bins": {"(99, 100]": 4 / 6, "(49, 50]": 2 / 6}},
        "need": {"dCA": 4 / 6, "pCA": 5 / 4, "prior": 4 / 6, "posterior": 5 / 6,
                 "bins": {"(99, 100]": 4 / 6, "(49, 50]": 2 / 6}},
        "transport": {"dCA": 1, "pCA": 2, "prior": 3 / 6, "posterior": 1,
                      "bins": {"(99, 100]": 1}}},
    # Every student a class of their own.
    4: {"re_id": {"dCR": 1, "pCR": 6, "bins": {"(99, 100]": 1}},
        "need": {"dCA": 1, "pCA": 3 / 2, "prior": 4 / 6, "posterior": 1,
                 "bins": {"(99, 100]": 1}},
        "transport": {"dCA": 1, "pCA": 2, "prior": 3 / 6, "posterior": 1,
                      "bins": {"(99, 100]": 1}}},
}


@pytest.mark.parametrize("years", [1, 2, 3, 4])
def test_the_notebooks_call_shape(years):
    first_ids = ["student"]
    first_qids = ["city", "school"]
    first_sensitive = ["need", "transport"]
    later_ids = ["person"]
    later_qids = ["city_code", "school_code"]
    datasets = [YEAR_1, YEAR_2, YEAR_3, YEAR_4][:years]
    copies = [dataset.copy() for dataset in datasets]

    bvm = BVMLongitudinal(datasets, [first_ids] + [later_ids] * (years - 1))
    bvm.qids([first_qids] + [later_qids] * (years - 1))
    bvm.sensitive(first_sensitive)
    results = bvm.assess()

    expected = NOTEBOOK[years]
    expect_re_id(results, rows=6, **expected["re_id"])
    assert results["re_id"].iloc[0]["QID"] == "['city', 'school']"
    for attribute in first_sensitive:
        expect_att_inf(results, attribute, **expected[attribute])
    # Guard: assess() leaves the caller's datasets as they were.
    for dataset, copy in zip(datasets, copies):
        pandas.testing.assert_frame_equal(dataset, copy)


# Assessing more than once.


@pytest.mark.parametrize("datasets, identifiers, qids", [
    ([FOCAL], ["id"], [["q"]]),
    ([FOCAL], [["id"]], ["q"]),
    ([FOCAL, SECOND, THIRD], ["id", "key", "code"], [["q"], ["r"], ["t"]]),
    ([SAME_FIRST, SAME_SECOND], ["id", "id"], ["q", "r"]),
], ids=["one_dataset", "one_dataset_flat", "three_datasets", "two_datasets_flat"])
def test_a_second_assessment_gives_the_same_results(datasets, identifiers, qids):
    bvm = BVMLongitudinal(datasets, identifiers)
    bvm.qids(qids)
    bvm.sensitive(["s"])
    bvm.worth("s", {"a": 1, "b": 2})
    first = bvm.assess()
    expect_same_results(bvm.assess(), first)


def test_each_assessment_of_three_datasets():
    # As in test_three_datasets_with_other_names. Worth: Prior max(3/4 * 1, 1/4 * 2) = 3/4,
    # Posterior (max(1 * 1, 1 * 2) + 1 + 1) / 4 = 1.
    bvm = BVMLongitudinal([FOCAL, SECOND, THIRD], ["id", "key", "code"])
    bvm.qids([["q"], ["r"], ["t"]])
    bvm.sensitive(["s"])
    bvm.worth("s", {"a": 1, "b": 2})
    bins = {"(49, 50]": 2 / 4, "(99, 100]": 2 / 4}
    for _ in range(2):
        results = bvm.assess()
        expect_re_id(results, dCR=2 / 4, pCR=3, rows=4, bins=bins)
        expect_att_inf(results, "s", dCA=2 / 4, pCA=1, prior=3 / 4, posterior=3 / 4, bins=bins)
        row = results["information_worth"].iloc[0]
        assert row["Prior Worth"] == pytest.approx(3 / 4)
        assert row["Posterior Worth"] == pytest.approx(1)


def test_quasi_identifiers_set_again_after_an_assessment():
    # First q and r, as in test_a_flat_list_of_quasi_identifiers; then q alone, whose classes are
    # (1, 9) ids 1 and 2, (2, 9) ids 3 and 4.
    bvm = BVMLongitudinal([SAME_FIRST, SAME_SECOND], ["id", "id"])
    bvm.qids(["q", "r"])
    bins = {"(99, 100]": 2 / 4, "(49, 50]": 2 / 4}
    expect_re_id(bvm.assess(), dCR=2 / 4, pCR=3, rows=4, bins=bins)
    bvm.qids([["q"], ["q"]])
    results = bvm.assess()
    expect_re_id(results, dCR=0, pCR=2, rows=4, bins={"(49, 50]": 1})
    assert results["re_id"].iloc[0]["QID"] == "['q']"
