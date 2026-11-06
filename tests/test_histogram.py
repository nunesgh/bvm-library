# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2021-2026 Gabriel Henrique Lopes Gomes Alves Nunes

# The histogram rule from GitHub issue #4, as PR #5 implements it: 100 bins "(0, 1]" to
# "(99, 100]", a probability p goes to the bin (k - 1, k] with k = ceil(100 p), and each bin
# holds the fraction of the table's rows whose p falls in it. Every expected bin below is worked
# out by hand.

import pandas
import pytest

from bvmlib.bvm import BVM

LABELS = ["(" + str(k - 1) + ", " + str(k) + "]" for k in range(1, 101)]


def assess(columns, qids, sensitive=None):
    bvm = BVM(pandas.DataFrame(columns))
    bvm.qids(qids)
    if sensitive is not None:
        bvm.sensitive(sensitive)
    return bvm.assess()


def re_id_histogram(results):
    assert len(results["re_id"]) == 1
    return results["re_id"].loc[0, "Histogram"]


def att_inf_histogram(results, attribute):
    rows = results["att_inf"][results["att_inf"]["Sensitive"] == attribute]
    assert len(rows) == 1
    return rows["Histogram"].iloc[0]


def histogram(fractions):
    "The full 100-bin histogram with the given fractions and 0 in every other bin."
    assert set(fractions) <= set(LABELS)
    return {label: fractions.get(label, 0) for label in LABELS}


# Classes by q: q=1 has 2 rows, q=2 has 3 rows, q=3 has 1 row. Rows are deliberately unsorted.
# Most frequent value per class: s1 is 1 of 2, 2 of 3, 1 of 1; s2 is 2 of 2, 1 of 3, 1 of 1.
MIXED = {
    "q": [1, 2, 3, 2, 1, 2],
    "s1": ["a", "a", "c", "a", "b", "b"],
    "s2": ["x", "x", "x", "y", "x", "z"],
}
MIXED_RE_ID = histogram({"(99, 100]": 1 / 6, "(49, 50]": 2 / 6, "(33, 34]": 3 / 6})
MIXED_S1 = histogram({"(49, 50]": 2 / 6, "(66, 67]": 3 / 6, "(99, 100]": 1 / 6})
MIXED_S2 = histogram({"(99, 100]": 3 / 6, "(33, 34]": 3 / 6})

# Two quasi-identifiers. Classes (age, gender): (25, F) 3 rows, (25, M) 2, (49, F) 3, (49, M) 1,
# (60, M) 1.
TWO_QIDS = {
    "age": [25, 25, 25, 25, 25, 49, 49, 49, 49, 60],
    "gender": ["F", "F", "F", "M", "M", "F", "F", "F", "M", "M"],
    "grade": ["A", "A", "C", "B", "B", "C", "C", "E", "D", "D"],
    "disability": [False, True, True, True, False, True, True, False, False, False],
}

ONE_ROW = {"q": [7], "s": ["a"]}


def test_labels_are_the_100_intervals_in_order():
    assert LABELS[:3] == ["(0, 1]", "(1, 2]", "(2, 3]"]
    assert LABELS[-1] == "(99, 100]"
    assert len(LABELS) == 100

    results = assess(MIXED, ["q"])
    assert list(re_id_histogram(results)) == LABELS

    results = assess(MIXED, ["q"], ["s1", "s2"])
    assert list(re_id_histogram(results)) == LABELS
    assert list(att_inf_histogram(results, "s1")) == LABELS
    assert list(att_inf_histogram(results, "s2")) == LABELS


def test_histogram_is_a_dict_in_both_result_tables():
    results = assess(MIXED, ["q"], ["s1", "s2"])
    assert type(re_id_histogram(results)) is dict
    assert type(att_inf_histogram(results, "s1")) is dict
    assert type(att_inf_histogram(results, "s2")) is dict

    assert type(re_id_histogram(assess(MIXED, ["q"]))) is dict


@pytest.mark.parametrize("columns, qids, sensitive", [
    (MIXED, ["q"], ["s1", "s2"]),
    (TWO_QIDS, ["age", "gender"], ["grade", "disability"]),
    (ONE_ROW, ["q"], ["s"]),
], ids=["mixed", "two_qids", "one_row"])
def test_values_add_up_to_one(columns, qids, sensitive):
    assert sum(re_id_histogram(assess(columns, qids)).values()) == pytest.approx(1)

    results = assess(columns, qids, sensitive)
    assert sum(re_id_histogram(results).values()) == pytest.approx(1)
    for attribute in sensitive:
        assert sum(att_inf_histogram(results, attribute).values()) == pytest.approx(1)


def test_re_identification_without_sensitive_attributes():
    assert re_id_histogram(assess(MIXED, ["q"])) == pytest.approx(MIXED_RE_ID)


def test_re_identification_with_sensitive_attributes():
    results = assess(MIXED, ["q"], ["s1", "s2"])
    assert re_id_histogram(results) == pytest.approx(MIXED_RE_ID)


def test_attribute_inference_per_sensitive_attribute():
    results = assess(MIXED, ["q"], ["s1", "s2"])
    assert att_inf_histogram(results, "s1") == pytest.approx(MIXED_S1)
    assert att_inf_histogram(results, "s2") == pytest.approx(MIXED_S2)


def test_two_quasi_identifiers():
    expected_re_id = histogram({"(33, 34]": 6 / 10, "(49, 50]": 2 / 10, "(99, 100]": 2 / 10})
    # grade: 2/3, 1, 2/3, 1, 1. disability: 2/3, 1/2, 2/3, 1, 1.
    expected_grade = histogram({"(66, 67]": 6 / 10, "(99, 100]": 4 / 10})
    expected_disability = histogram(
        {"(66, 67]": 6 / 10, "(49, 50]": 2 / 10, "(99, 100]": 2 / 10})

    assert re_id_histogram(assess(TWO_QIDS, ["age", "gender"])) == pytest.approx(expected_re_id)

    results = assess(TWO_QIDS, ["age", "gender"], ["grade", "disability"])
    assert re_id_histogram(results) == pytest.approx(expected_re_id)
    assert att_inf_histogram(results, "grade") == pytest.approx(expected_grade)
    assert att_inf_histogram(results, "disability") == pytest.approx(expected_disability)


@pytest.mark.parametrize("with_sensitive", [False, True], ids=["qids_only", "with_sensitive"])
def test_re_identification_exact_edges(with_sensitive):
    # Class sizes 1, 2, 4 and 100: p = 1, 1/2, 1/4 and 1/100, each the top edge of its bin.
    sizes = {"one": 1, "two": 2, "four": 4, "hundred": 100}
    q = [name for name, size in sizes.items() for _ in range(size)]
    columns = {"q": q, "s": ["same"] * len(q)}
    expected = histogram({
        "(99, 100]": 1 / 107, "(49, 50]": 2 / 107, "(24, 25]": 4 / 107, "(0, 1]": 100 / 107,
    })

    results = assess(columns, ["q"], ["s"] if with_sensitive else None)
    assert re_id_histogram(results) == pytest.approx(expected)


@pytest.mark.parametrize("with_sensitive", [False, True], ids=["qids_only", "with_sensitive"])
def test_re_identification_around_one_percent(with_sensitive):
    # p = 1/200 and 1/101 are below 1%, so in (0, 1]; p = 1/99 is just above it, so in (1, 2].
    sizes = {"two_hundred": 200, "hundred_one": 101, "ninety_nine": 99}
    q = [name for name, size in sizes.items() for _ in range(size)]
    columns = {"q": q, "s": ["same"] * len(q)}
    expected = histogram({"(0, 1]": 301 / 400, "(1, 2]": 99 / 400})

    results = assess(columns, ["q"], ["s"] if with_sensitive else None)
    assert re_id_histogram(results) == pytest.approx(expected)


def test_one_third_is_just_above_an_edge():
    columns = {"q": [1, 1, 1], "s": ["a", "b", "c"]}
    expected = histogram({"(33, 34]": 1})

    assert re_id_histogram(assess(columns, ["q"])) == pytest.approx(expected)

    results = assess(columns, ["q"], ["s"])
    assert re_id_histogram(results) == pytest.approx(expected)
    assert att_inf_histogram(results, "s") == pytest.approx(expected)


def test_attribute_inference_exact_edges():
    # Classes: "c1" 100 distinct values (p = 1/100), "c2" one each of a and b (p = 1/2),
    # "c3" 4 equal values (p = 1).
    q = ["c1"] * 100 + ["c2"] * 2 + ["c3"] * 4
    s = [str(i) for i in range(100)] + ["a", "b"] + ["a"] * 4
    expected = histogram({"(0, 1]": 100 / 106, "(49, 50]": 2 / 106, "(99, 100]": 4 / 106})

    results = assess({"q": q, "s": s}, ["q"], ["s"])
    assert att_inf_histogram(results, "s") == pytest.approx(expected)


@pytest.mark.parametrize("count, size, label", [
    # Below 1%, the case GitHub issue #4 reports.
    (1, 200, "(0, 1]"),
    # 100 * (7 / 100) is 7.000000000000001 in floating point.
    (7, 100, "(6, 7]"),
    # 100p = 99.00497..., under 0.005 above 99: rounding to 2 decimals would move it down a bin.
    (199, 201, "(99, 100]"),
], ids=["1_of_200", "7_of_100", "199_of_201"])
def test_attribute_inference_in_one_class(count, size, label):
    # One class of `size` rows: `count` rows share "a", the rest are distinct, so p = count/size.
    columns = {"q": [0] * size, "s": ["a"] * count + [str(i) for i in range(size - count)]}

    results = assess(columns, ["q"], ["s"])
    assert att_inf_histogram(results, "s") == pytest.approx(histogram({label: 1}))
    # Re-identification: p = 1/size, at most 1/100.
    assert re_id_histogram(results) == pytest.approx(histogram({"(0, 1]": 1}))


def test_one_row_table():
    expected = histogram({"(99, 100]": 1})

    assert re_id_histogram(assess(ONE_ROW, ["q"])) == pytest.approx(expected)

    results = assess(ONE_ROW, ["q"], ["s"])
    assert list(re_id_histogram(results)) == LABELS
    assert re_id_histogram(results) == pytest.approx(expected)
    assert att_inf_histogram(results, "s") == pytest.approx(expected)
