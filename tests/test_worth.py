# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2021-2026 Gabriel Henrique Lopes Gomes Alves Nunes

# Information worth. A worth assignment gives a sensitive value a worth by the value's text,
# str(value), and missing values (pandas.isna) the worth under the key None, if any. With n rows:
# Prior Worth is the largest count(v) / n * worth(v) over the values v with a worth, and Posterior
# Worth the sum over the classes of the largest count(v) * worth(v) within the class, over n; each
# is 0 when no value has a worth. Every expected value is worked out by hand.

import re
from fractions import Fraction

import numpy
import pandas
import pytest

from bvmlib.bvm import BVM, BVMLongitudinal

NAN = float("nan")
INF = float("inf")
NA = pandas.NA

LABELS = ["(" + str(k - 1) + ", " + str(k) + "]" for k in range(1, 101)]


def histogram(fractions):
    "The full 100-bin histogram with the given fractions and 0 in every other bin."
    assert set(fractions) <= set(LABELS)
    return {label: fractions.get(label, 0) for label in LABELS}


def exactly(message):
    "A pattern that matches the whole message and nothing else."
    return "^" + re.escape(message) + "$"


def assess(frame, qids, sensitive, worth=None):
    bvm = BVM(frame)
    bvm.qids(qids)
    bvm.sensitive(sensitive)
    for attribute, assignment in (worth or {}).items():
        bvm.worth(attribute, assignment)
    return bvm.assess()


def only_row(table, attribute):
    table = table[table["Sensitive"] == attribute]
    assert len(table) == 1
    return table.iloc[0]


def expect_worth(results, attribute, prior, posterior):
    row = only_row(results["information_worth"], attribute)
    assert row["Prior Worth"] == pytest.approx(prior)
    assert row["Posterior Worth"] == pytest.approx(posterior)


# Classes by q: 1 {a, a, b}, 2 {b, c}, 3 {a}. s overall: a 3, b 2, c 1, of 6 rows.
TABLE = pandas.DataFrame({"q": [1, 1, 1, 2, 2, 3], "s": ["a", "a", "b", "b", "c", "a"],
                          "t": ["x", "y", "x", "y", "x", "y"]})


def test_prior_and_posterior_worth():
    # Prior: max(3/6 * 1, 2/6 * 3, 1/6 * 2) = 1. Posterior: (max(2 * 1, 1 * 3) + max(1 * 3, 1 * 2)
    # + 1 * 1) / 6 = 7/6.
    results = assess(TABLE, ["q"], ["s"], {"s": {"a": 1, "b": 3, "c": 2}})
    expect_worth(results, "s", prior=1, posterior=7 / 6)


def test_values_without_a_worth_count_for_nothing():
    # Only c: Prior 1/6 * 6 = 1. Posterior: only class 2 holds c, 1 * 6, over 6.
    expect_worth(assess(TABLE, ["q"], ["s"], {"s": {"c": 6}}), "s", prior=1, posterior=1)

    # No value of s has a worth: both are 0.
    expect_worth(assess(TABLE, ["q"], ["s"], {"s": {"d": 6}}), "s", prior=0, posterior=0)


def test_only_attributes_with_a_worth_assignment_have_a_row():
    # t per class: 1 {x, y, x}, 2 {y, x}, 3 {y}; overall x 3, y 3. Prior: max(3/6 * 1, 3/6 * 2)
    # = 1. Posterior: (max(2 * 1, 1 * 2) + max(1 * 2, 1 * 1) + 1 * 2) / 6 = 1.
    results = assess(TABLE, ["q"], ["s", "t"], {"t": {"x": 1, "y": 2}})
    assert list(results["information_worth"]["Sensitive"]) == ["t"]
    expect_worth(results, "t", prior=1, posterior=1)


def test_a_worth_of_zero():
    # a counts for nothing. Prior: max(3/6 * 0, 2/6 * 1) = 1/3. Posterior: (1 + 1 + 0) / 6.
    results = assess(TABLE, ["q"], ["s"], {"s": {"a": 0, "b": 1}})
    expect_worth(results, "s", prior=1 / 3, posterior=2 / 6)

    # Every worth 0, missing values' included: a row of zeros.
    frame = TABLE.assign(s=pandas.Series(["a", None, "b", "b", "c", "a"], dtype=object))
    results = assess(frame, ["q"], ["s"], {"s": {"a": 0, "b": 0, "c": 0, None: 0}})
    expect_worth(results, "s", prior=0, posterior=0)


# Missing values

# Classes by q: 1 {a, missing, missing}, 2 {missing, b}. s overall: a 1, b 1, missing 3, of 5 rows.
MISSING_KINDS = [
    pandas.Series(["a", None, None, None, "b"], dtype=object),
    pandas.Series(["a", NAN, NAN, NAN, "b"], dtype=object),
    pandas.Series(["a", NA, None, NAN, "b"], dtype=object),
    pandas.Series(pandas.array(["a", NA, NA, NA, "b"], dtype="string")),
]
MISSING_IDS = ["none", "nan", "mixed", "string_dtype"]


@pytest.mark.parametrize("column", MISSING_KINDS, ids=MISSING_IDS)
def test_missing_values_have_no_worth_without_a_none_key(column):
    frame = pandas.DataFrame({"q": [1, 1, 1, 2, 2], "s": column})
    # Prior: max(1/5 * 2, 1/5 * 1) = 2/5. Posterior: (1 * 2 + 1 * 1) / 5 = 3/5.
    results = assess(frame, ["q"], ["s"], {"s": {"a": 2, "b": 1}})
    expect_worth(results, "s", prior=2 / 5, posterior=3 / 5)


@pytest.mark.parametrize("column", MISSING_KINDS, ids=MISSING_IDS)
def test_missing_values_take_the_worth_under_none(column):
    frame = pandas.DataFrame({"q": [1, 1, 1, 2, 2], "s": column})
    # Prior: max(1/5 * 2, 1/5 * 1, 3/5 * 2) = 6/5. Posterior: (max(1 * 2, 2 * 2)
    # + max(1 * 2, 1 * 1)) / 5 = 6/5.
    results = assess(frame, ["q"], ["s"], {"s": {"a": 2, "b": 1, None: 2}})
    expect_worth(results, "s", prior=6 / 5, posterior=6 / 5)

    # Only missing values have a worth. Prior: 3/5 * 1. Posterior: (2 * 1 + 1 * 1) / 5.
    results = assess(frame, ["q"], ["s"], {"s": {None: 1}})
    expect_worth(results, "s", prior=3 / 5, posterior=3 / 5)


@pytest.mark.parametrize("text", ["nan", "None", "<NA>", "NaT", ""])
@pytest.mark.parametrize("column", MISSING_KINDS, ids=MISSING_IDS)
def test_a_text_key_gives_missing_values_no_worth(column, text):
    frame = pandas.DataFrame({"q": [1, 1, 1, 2, 2], "s": column})
    expect_worth(assess(frame, ["q"], ["s"], {"s": {text: 5}}), "s", prior=0, posterior=0)


# Classes by q: 1 {"nan", missing, missing, missing}, 2 {"nan", "nan", missing}.
# s overall: the text "nan" 3, missing 4, of 7 rows.
NAN_TEXT = pandas.DataFrame({
    "q": [1, 1, 1, 1, 2, 2, 2],
    "s": pandas.Series(["nan", NAN, NAN, NAN, "nan", "nan", NAN], dtype=object),
})
# Rows in three orders: within each class, the text first, a missing value first, or the text
# first in class 1 and a missing value first in class 2.
ORDERS = [list(range(7)), list(range(6, -1, -1)), [0, 1, 2, 3, 6, 4, 5]]


@pytest.mark.parametrize("order", ORDERS, ids=["text_first", "missing_first", "mixed"])
def test_the_text_nan_and_missing_values_are_two_values(order):
    frame = NAN_TEXT.iloc[order].reset_index(drop=True)

    # The text alone. Prior: 3/7 * 1. Posterior: (1 * 1 + 2 * 1) / 7.
    expect_worth(assess(frame, ["q"], ["s"], {"s": {"nan": 1}}), "s", prior=3 / 7,
                 posterior=3 / 7)

    # Missing values alone. Prior: 4/7 * 1. Posterior: (3 * 1 + 1 * 1) / 7.
    expect_worth(assess(frame, ["q"], ["s"], {"s": {None: 1}}), "s", prior=4 / 7,
                 posterior=4 / 7)

    # Both. Prior: max(3/7 * 2, 4/7 * 1) = 6/7. Posterior: (max(1 * 2, 3 * 1)
    # + max(2 * 2, 1 * 1)) / 7 = 1.
    expect_worth(assess(frame, ["q"], ["s"], {"s": {"nan": 2, None: 1}}), "s", prior=6 / 7,
                 posterior=1)


# Classes by q: 1 {1, missing}, 2 {2, 2, missing}. s overall: 1 once, 2 twice, missing twice, of 5.
INTEGERS = [
    pandas.Series(pandas.array([1, NA, 2, 2, NA], dtype="Int64")),
    pandas.Series([1, None, 2, 2, None], dtype=object),
    pandas.Series([1, NAN, 2, 2, NAN], dtype=object),
]


@pytest.mark.parametrize("column", INTEGERS, ids=["Int64", "object_none", "object_nan"])
def test_integers_with_missing_values_are_matched_by_their_text(column):
    frame = pandas.DataFrame({"q": [1, 1, 2, 2, 2], "s": column})

    # Prior: max(1/5 * 3, 2/5 * 1) = 3/5. Posterior: (1 * 3 + 2 * 1) / 5 = 1.
    expect_worth(assess(frame, ["q"], ["s"], {"s": {"1": 3, "2": 1}}), "s", prior=3 / 5,
                 posterior=1)

    # Prior: max(3/5, 2/5, 2/5 * 2.5) = 1. Posterior: (max(3, 2.5) + max(2, 2.5)) / 5 = 11/10.
    results = assess(frame, ["q"], ["s"], {"s": {"1": 3, "2": 1, None: 2.5}})
    expect_worth(results, "s", prior=1, posterior=11 / 10)


def test_dates_with_missing_values_are_matched_by_their_text():
    # Classes by q: 1 {2020-01-01, missing}, 2 {2021-06-30, missing}. s overall: each date once,
    # missing twice, of 4 rows.
    frame = pandas.DataFrame({
        "q": [1, 1, 2, 2],
        "s": pandas.to_datetime(pandas.Series(["2020-01-01", None, "2021-06-30", None])),
    })
    worth = {"2020-01-01 00:00:00": 4, "2021-06-30 00:00:00": 1}

    # Prior: max(1/4 * 4, 1/4 * 1) = 1. Posterior: (4 + 1) / 4.
    expect_worth(assess(frame, ["q"], ["s"], {"s": worth}), "s", prior=1, posterior=5 / 4)

    # Prior: max(1, 1/4, 2/4 * 3) = 3/2. Posterior: (max(4, 3) + max(1, 3)) / 4 = 7/4.
    results = assess(frame, ["q"], ["s"], {"s": {**worth, None: 3}})
    expect_worth(results, "s", prior=3 / 2, posterior=7 / 4)

    # The text of a missing date gives it no worth.
    expect_worth(assess(frame, ["q"], ["s"], {"s": {"NaT": 3}}), "s", prior=0, posterior=0)


# Invalid worth assignments


def test_worth_accepts_numbers_of_other_types():
    # numpy numbers, as read from a pandas table, and a Fraction: the worths of
    # test_prior_and_posterior_worth, with the same results.
    worths = {"a": pandas.Series([1]).iloc[0], "b": pandas.Series([3.0]).iloc[0],
              "c": Fraction(2)}
    expect_worth(assess(TABLE, ["q"], ["s"], {"s": worths}), "s", prior=1, posterior=7 / 6)


def test_worths_of_every_kind_give_float_results():
    # Each worth is stored as a float, so a small numpy integer cannot overflow (2 * 100 in int8),
    # and a float32 or a Fraction gives float64 results. Prior: a, 3 / 6 * 100. Posterior: class 1
    # a 2 * 100, class 2 b or c 0.5, class 3 a 100, over 6.
    worths = {"a": numpy.int8(100), "b": numpy.float32(0.5), "c": Fraction(1, 2)}
    results = assess(TABLE, ["q"], ["s"], {"s": worths})
    expect_worth(results, "s", prior=50, posterior=300.5 / 6)
    table = results["information_worth"]
    assert table["Prior Worth"].dtype == "float64"
    assert table["Posterior Worth"].dtype == "float64"


@pytest.mark.parametrize("worth", ["1", None, 1j, [1], NA], ids=repr)
def test_worth_rejects_a_worth_that_is_not_a_number(worth):
    bvm = BVM(TABLE)
    bvm.sensitive(["s"])
    with pytest.raises(TypeError, match=exactly("Worth assignments must be numbers.")):
        bvm.worth("s", {"a": 1, "b": worth})


@pytest.mark.parametrize("worth", [NAN, INF, pandas.Series([NAN]).iloc[0],
                                   pandas.Series([INF]).iloc[0]],
                         ids=["nan", "inf", "numpy_nan", "numpy_inf"])
def test_worth_rejects_a_worth_that_is_not_finite(worth):
    bvm = BVM(TABLE)
    bvm.sensitive(["s"])
    with pytest.raises(ValueError, match=exactly("Worth assignments must be finite.")):
        bvm.worth("s", {"a": 1, "b": worth})


def test_worth_rejects_minus_infinity_as_negative():
    bvm = BVM(TABLE)
    bvm.sensitive(["s"])
    with pytest.raises(ValueError, match=exactly("Worth assignments cannot be negative.")):
        bvm.worth("s", {"a": 1, "b": -INF})


@pytest.mark.parametrize("key", [1, 1.0, NAN, NA, True, ("a",), b"a"], ids=repr)
def test_worth_rejects_a_key_that_is_neither_a_string_nor_none(key):
    bvm = BVM(TABLE)
    bvm.sensitive(["s"])
    message = "Worth assignment keys must be strings, or None for missing values."
    with pytest.raises(TypeError, match=exactly(message)):
        bvm.worth("s", {"a": 1, key: 2})


def test_worth_accepts_keys_of_a_subclass_of_str():
    # numpy's strings, as read from an array of text: the worths of test_prior_and_posterior_worth,
    # with the same results.
    keys = list(pandas.Series(["a", "b", "c"]).to_numpy(dtype=str))
    # Guard: each key is a str, but not of type str itself.
    assert all(isinstance(key, str) and type(key) is not str for key in keys)
    worths = dict(zip(keys, [1, 3, 2]))
    expect_worth(assess(TABLE, ["q"], ["s"], {"s": worths}), "s", prior=1, posterior=7 / 6)


def test_worth_keeps_its_own_copy_of_the_assignment():
    bvm = BVM(TABLE)
    bvm.qids(["q"])
    bvm.sensitive(["s"])
    assignment = {"b": 3}
    bvm.worth("s", assignment)
    # Later changes to the caller's dictionary, one of which worth() would refuse.
    assignment["a"] = 100
    assignment["b"] = -1
    # As for {"b": 3} alone. Prior: 2/6 * 3 = 1. Posterior: (1 * 3 + 1 * 3) / 6 = 1.
    expect_worth(bvm.assess(), "s", prior=1, posterior=1)


@pytest.mark.parametrize("assignment, error", [
    ({"a": "2"}, TypeError),
    ({"a": 2, None: None}, TypeError),
    ({"a": 2, 1: 2}, TypeError),
    ({"a": 2, "b": -1}, ValueError),
    ({"a": 2, "b": NAN}, ValueError),
    ({"a": 2, "b": INF}, ValueError),
], ids=["text", "none", "key", "negative", "nan", "inf"])
def test_a_rejected_worth_call_keeps_the_earlier_assignment(assignment, error):
    bvm = BVM(TABLE)
    bvm.qids(["q"])
    bvm.sensitive(["s"])
    bvm.worth("s", {"b": 3})
    with pytest.raises(error):
        bvm.worth("s", assignment)
    # As for {"b": 3} alone. Prior: 2/6 * 3 = 1. Posterior: (1 * 3 + 1 * 3) / 6 = 1.
    expect_worth(bvm.assess(), "s", prior=1, posterior=1)


def test_a_rejected_first_worth_call_assigns_nothing():
    bvm = BVM(TABLE)
    bvm.qids(["q"])
    bvm.sensitive(["s"])
    with pytest.raises(TypeError):
        bvm.worth("s", {"a": "1"})
    assert "information_worth" not in bvm.assess()


# BVMLongitudinal

# The later dataset holds every identifier of the focal dataset and no column named like a
# sensitive attribute. The join's quasi-identifier "q#r": "1#7" ids 1 and 2, "2#7" id 3, "2#8"
# ids 4 and 5. s per class: "1#7" {a, b}, "2#7" {a}, "2#8" {a, b}; s overall: a 3, b 2, of 5 rows.
FOCAL = pandas.DataFrame({"id": [1, 2, 3, 4, 5], "q": [1, 1, 2, 2, 2],
                          "s": ["a", "b", "a", "a", "b"]})
LATER = pandas.DataFrame({"key": [5, 4, 3, 2, 1], "r": [8, 8, 7, 7, 7]})


def longitudinal(worth=None):
    bvm = BVMLongitudinal([FOCAL, LATER], ["id", "key"])
    bvm.qids([["q"], ["r"]])
    bvm.sensitive(["s"])
    for attribute, assignment in (worth or {}).items():
        bvm.worth(attribute, assignment)
    return bvm.assess()


def test_longitudinal_attribute_inference_without_worth():
    results = longitudinal()
    assert "information_worth" not in results

    row = results["re_id"].iloc[0]
    assert row["dCR"] == pytest.approx(1 / 5)
    assert row["pCR"] == 3

    # Only class "2#7" holds one value. pCA: (1 + 1 + 1) rows over the 3 the Prior guesses.
    row = only_row(results["att_inf"], "s")
    assert row["dCA"] == pytest.approx(1 / 5)
    assert row["pCA"] == pytest.approx(1)
    assert row["Prior"] == pytest.approx(3 / 5)
    assert row["Posterior"] == pytest.approx(3 / 5)
    assert row["Histogram"] == pytest.approx(histogram({"(49, 50]": 4 / 5, "(99, 100]": 1 / 5}))


def test_longitudinal_attribute_inference_with_worth():
    # Prior: max(3/5 * 1, 2/5 * 2) = 4/5. Posterior: (max(1, 2) + 1 + max(1, 2)) / 5 = 1.
    results = longitudinal({"s": {"a": 1, "b": 2}})
    expect_worth(results, "s", prior=4 / 5, posterior=1)
    assert only_row(results["att_inf"], "s")["Prior"] == pytest.approx(3 / 5)


def test_longitudinal_worth_with_one_dataset():
    # Classes by q: 1 {a, b}, 2 {a, a, b}. Prior: max(3/5 * 1, 2/5 * 2) = 4/5. Posterior:
    # (max(1, 2) + max(2 * 1, 1 * 2)) / 5 = 4/5.
    bvm = BVMLongitudinal([FOCAL], ["id"])
    bvm.qids([["q"]])
    bvm.sensitive(["s"])
    bvm.worth("s", {"a": 1, "b": 2})
    expect_worth(bvm.assess(), "s", prior=4 / 5, posterior=4 / 5)
