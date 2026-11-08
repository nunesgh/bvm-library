# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2021-2026 Gabriel Henrique Lopes Gomes Alves Nunes

# The attribute-inference Prior counts sensitive values by their text, as each equivalence class
# does: -0.0 and 0.0 are two values, 1 and "1" one, and missing values one of their own. Numeric
# result columns have number dtypes. The bins keep re-identification under re_id, and a sensitive
# attribute of that name takes another key. Every expected value is worked out by hand.

import random
import warnings

import pandas
import pytest

from bvmlib.bvm import BVM

LABELS = ["(" + str(k - 1) + ", " + str(k) + "]" for k in range(1, 101)]


def histogram(fractions):
    "The full 100-bin histogram with the given fractions and 0 in every other bin."
    assert set(fractions) <= set(LABELS)
    return {label: fractions.get(label, 0) for label in LABELS}


def assess(frame, qids, sensitive=None, worth=None):
    bvm = BVM(frame)
    bvm.qids(qids)
    if sensitive is not None:
        bvm.sensitive(sensitive)
    for attribute, assignment in (worth or {}).items():
        bvm.worth(attribute, assignment)
    return bvm.assess()


def only_row(table, attribute=None):
    if attribute is not None:
        table = table[table["Sensitive"] == attribute]
    assert len(table) == 1
    return table.iloc[0]


def expect_att_inf(results, attribute, dCA, pCA, prior, posterior, bins):
    row = only_row(results["att_inf"], attribute)
    assert row["dCA"] == pytest.approx(dCA)
    assert row["pCA"] == pytest.approx(pCA)
    assert row["Prior"] == pytest.approx(prior)
    assert row["Posterior"] == pytest.approx(posterior)
    assert row["Histogram"] == pytest.approx(histogram(bins))


# The Prior by text

EQUAL_BUT_TWO_TEXTS = [
    pandas.Series([-0.0, 0.0], dtype="float64"),
    pandas.Series([-0.0, 0.0], dtype=object),
    pandas.Series([1, 1.0], dtype=object),
]
TEXT_IDS = ["zeros_float", "zeros_object", "int_and_float"]


@pytest.mark.parametrize("pair", EQUAL_BUT_TWO_TEXTS, ids=TEXT_IDS)
def test_equal_values_with_two_texts_are_two_values_in_one_class(pair):
    # One class of 3 rows: the first value once, the second twice, so 2 of 3 by text.
    # Prior: the second value, 2 of 3. pCA: 2 rows classified over the 2 the Prior guesses.
    frame = pandas.DataFrame({"q": [1, 1, 1], "s": pair[[0, 1, 1]].reset_index(drop=True)})
    expect_att_inf(assess(frame, ["q"], ["s"]), "s", dCA=0, pCA=1, prior=2 / 3,
                   posterior=2 / 3, bins={"(66, 67]": 1})


@pytest.mark.parametrize("pair", EQUAL_BUT_TWO_TEXTS, ids=TEXT_IDS)
def test_equal_values_with_two_texts_are_two_values_across_classes(pair):
    # Two classes of 1 row, one value each: every row is inferred, and the attribute is not
    # constant, so dCA stays 1. Prior: 1 of 2. pCA: 2 rows classified over 1.
    frame = pandas.DataFrame({"q": [1, 2], "s": pair})
    expect_att_inf(assess(frame, ["q"], ["s"]), "s", dCA=1, pCA=2, prior=1 / 2,
                   posterior=1, bins={"(99, 100]": 1})


def test_an_integer_and_its_text_are_one_value():
    # One class of 2 rows with one value by text: inferred, but constant, so dCA is 0.
    frame = pandas.DataFrame({"q": [1, 1], "s": pandas.Series([1, "1"], dtype=object)})
    expect_att_inf(assess(frame, ["q"], ["s"]), "s", dCA=0, pCA=1, prior=1, posterior=1,
                   bins={"(99, 100]": 1})

    # Two classes of 1 row: the same value in both, so the attribute is constant and dCA is 0.
    frame = pandas.DataFrame({"q": [1, 2], "s": pandas.Series([1, "1"], dtype=object)})
    expect_att_inf(assess(frame, ["q"], ["s"]), "s", dCA=0, pCA=1, prior=1, posterior=1,
                   bins={"(99, 100]": 1})


def test_a_constant_categorical_with_an_unused_category_is_constant():
    # Two classes of 1 row, both "x": constant, so dCA is 0, whatever the unused category.
    frame = pandas.DataFrame({"q": [1, 2],
                              "s": pandas.Categorical(["x", "x"], categories=["x", "y"])})
    expect_att_inf(assess(frame, ["q"], ["s"]), "s", dCA=0, pCA=1, prior=1, posterior=1,
                   bins={"(99, 100]": 1})


def text_counts(column):
    "Each value's count by its text, with every missing value under one key of its own."
    counts = {}
    for value in column:
        key = None if pandas.isna(value) else str(value)
        counts[key] = counts.get(key, 0) + 1
    return counts


@pytest.mark.parametrize("seed", range(20))
def test_posterior_is_never_below_prior(seed):
    # Values that are equal with different texts (0.0, -0.0; True, 1, 1.0), that share a text
    # (1, "1"), and missing values.
    rng = random.Random(seed)
    pool = [0.0, -0.0, 1, 1.0, "1", True, "a", None, float("nan")]
    rows = 30
    frame = pandas.DataFrame({
        "q1": [rng.randrange(4) for _ in range(rows)],
        "q2": [rng.randrange(3) for _ in range(rows)],
        "s1": pandas.Series([rng.choice(pool) for _ in range(rows)], dtype=object),
        "s2": pandas.Series([rng.choice(pool[:4]) for _ in range(rows)], dtype=object),
    })
    for qids in [["q1"], ["q1", "q2"]]:
        results = assess(frame, qids, ["s1", "s2"])
        for attribute in ["s1", "s2"]:
            row = only_row(results["att_inf"], attribute)
            assert row["Prior"] == pytest.approx(
                max(text_counts(frame[attribute]).values()) / rows)
            assert row["pCA"] >= 1
            assert row["Posterior"] >= row["Prior"]


# Number dtypes

FRAME = pandas.DataFrame({"q": [1, 1, 2], "s": ["a", "b", "a"], "t": [1.5, 1.5, 2.5]})


def expect_text(column):
    assert pandas.api.types.is_string_dtype(column)
    assert all(type(value) is str for value in column)


def test_re_identification_columns_have_number_dtypes():
    for sensitive in [None, ["s"]]:
        table = assess(FRAME, ["q"], sensitive)["re_id"]
        assert list(table.columns) == ["QID", "dCR", "pCR", "Prior", "Posterior", "Histogram"]
        expect_text(table["QID"])
        assert pandas.api.types.is_integer_dtype(table["pCR"])
        for name in ["dCR", "Prior", "Posterior"]:
            assert pandas.api.types.is_float_dtype(table[name])
        assert all(type(value) is dict for value in table["Histogram"])

        # Classes: q=1 2 rows, q=2 1 row.
        row = only_row(table)
        assert row["QID"] == "['q']"
        assert row["dCR"] == pytest.approx(1 / 3)
        assert row["pCR"] == 2
        assert row["Prior"] == pytest.approx(1 / 3)
        assert row["Posterior"] == pytest.approx(2 / 3)


def test_attribute_inference_and_worth_columns_have_number_dtypes():
    results = assess(FRAME, ["q"], ["s", "t"], worth={"s": {"a": 1, "b": 2}, "t": {"9": 1}})

    table = results["att_inf"]
    assert list(table.columns) == ["QID", "Sensitive", "dCA", "pCA", "Prior", "Posterior",
                                   "Histogram"]
    expect_text(table["QID"])
    expect_text(table["Sensitive"])
    for name in ["dCA", "pCA", "Prior", "Posterior"]:
        assert pandas.api.types.is_float_dtype(table[name])
    assert all(type(value) is dict for value in table["Histogram"])
    # s per class: q=1 {a, b}, q=2 {a}; overall a 2, b 1.
    expect_att_inf(results, "s", dCA=1 / 3, pCA=1, prior=2 / 3, posterior=2 / 3,
                   bins={"(49, 50]": 2 / 3, "(99, 100]": 1 / 3})
    # t per class: q=1 {1.5, 1.5}, q=2 {2.5}; overall 1.5 2, 2.5 1.
    expect_att_inf(results, "t", dCA=1, pCA=3 / 2, prior=2 / 3, posterior=1,
                   bins={"(99, 100]": 1})

    table = results["information_worth"]
    assert list(table.columns) == ["QID", "Sensitive", "Prior Worth", "Posterior Worth"]
    expect_text(table["QID"])
    expect_text(table["Sensitive"])
    for name in ["Prior Worth", "Posterior Worth"]:
        assert pandas.api.types.is_float_dtype(table[name])
    # s: Prior Worth max(2/3 * 1, 1/3 * 2); Posterior Worth (max(1, 2) + 1) / 3.
    row = only_row(table, "s")
    assert row["Prior Worth"] == pytest.approx(2 / 3)
    assert row["Posterior Worth"] == pytest.approx(1)
    # t: no value of t has a worth.
    row = only_row(table, "t")
    assert row["Prior Worth"] == 0
    assert row["Posterior Worth"] == 0

    # The same when the one row has no worth at all.
    table = assess(FRAME, ["q"], ["t"], worth={"t": {"9": 1}})["information_worth"]
    for name in ["Prior Worth", "Posterior Worth"]:
        assert pandas.api.types.is_float_dtype(table[name])


def test_assess_warns_nothing():
    # Covers all three tables, and a categorical sensitive attribute with an unused category.
    frame = FRAME.assign(c=pandas.Categorical(["x", "x", "y"], categories=["x", "y", "z"]))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assess(frame, ["q"], ["s", "c"], worth={"s": {"a": 1}})
        assess(frame, ["q"])


def test_results_keep_their_keys():
    assert list(assess(FRAME, ["q"])) == ["re_id", "dCR", "pCR", "bins"]
    assert list(assess(FRAME, ["q"], ["s"])) == [
        "re_id", "dCR", "pCR", "bins", "att_inf", "sensitive_values", "CA"]
    assert list(assess(FRAME, ["q"], ["s"], worth={"s": {"a": 1}})) == [
        "re_id", "dCR", "pCR", "bins", "att_inf", "sensitive_values", "CA",
        "information_worth", "CW"]

    # A worth for an attribute no longer sensitive: no row, and the table keeps its columns.
    bvm = BVM(FRAME)
    bvm.qids(["q"])
    bvm.sensitive(["s"])
    bvm.worth("s", {"a": 1})
    bvm.sensitive(["t"])
    table = bvm.assess()["information_worth"]
    assert list(table.columns) == ["QID", "Sensitive", "Prior Worth", "Posterior Worth"]
    assert len(table) == 0


# A sensitive attribute named re_id

def test_bins_hold_re_identification_first_then_each_sensitive_attribute():
    results = assess(FRAME, ["q"], ["t", "s"])
    assert list(results["bins"]) == ["re_id", "t", "s"]
    # Classes: q=1 2 rows, q=2 1 row. t per class {1.5, 1.5}, {2.5}; s {a, b}, {a}.
    assert results["bins"]["re_id"] == pytest.approx(
        histogram({"(49, 50]": 2 / 3, "(99, 100]": 1 / 3}))
    assert results["bins"]["t"] == pytest.approx(histogram({"(99, 100]": 1}))
    assert results["bins"]["s"] == pytest.approx(
        histogram({"(49, 50]": 2 / 3, "(99, 100]": 1 / 3}))


def test_a_sensitive_attribute_named_re_id_takes_another_key_in_bins():
    # Classes: q=1 rows 0 and 1, both "a"; q=2 row 2, "b".
    frame = pandas.DataFrame({"q": [1, 1, 2], "re_id": ["a", "a", "b"]})
    results = assess(frame, ["q"], ["re_id"])
    re_id_bins = histogram({"(49, 50]": 2 / 3, "(99, 100]": 1 / 3})

    row = only_row(results["re_id"])
    assert row["dCR"] == pytest.approx(1 / 3)
    assert row["pCR"] == 2
    assert row["Histogram"] == pytest.approx(re_id_bins)
    assert sum(row["Histogram"].values()) == pytest.approx(1)

    # Each class holds one value: every row inferred. Prior: "a", 2 of 3. pCA: 3 rows over 2.
    expect_att_inf(results, "re_id", dCA=1, pCA=3 / 2, prior=2 / 3, posterior=1,
                   bins={"(99, 100]": 1})

    # Re-identification keeps "re_id" in bins, and the attribute takes "re_id (sensitive)".
    assert list(results["bins"]) == ["re_id", "re_id (sensitive)"]
    assert results["bins"]["re_id"] == pytest.approx(re_id_bins)
    assert results["bins"]["re_id (sensitive)"] == pytest.approx(histogram({"(99, 100]": 1}))


def test_only_an_attribute_named_re_id_takes_another_key_in_bins():
    # Classes: q=1 rows 0 to 2, q=2 row 3. Re-identification: 3 rows at 1/3, 1 row at 1.
    frame = pandas.DataFrame({"q": [1, 1, 1, 2], "re_id": ["a", "a", "a", "b"],
                              "re_id (sensitive)": ["x", "x", "y", "y"]})
    re_id_bins = histogram({"(33, 34]": 3 / 4, "(99, 100]": 1 / 4})
    # re_id per class {a: 3}, {b: 1}: every row at 1.
    re_id_attribute_bins = histogram({"(99, 100]": 1})
    # re_id (sensitive) per class {x: 2, y: 1}, {y: 1}: 3 rows at 2/3, 1 row at 1.
    other_bins = histogram({"(66, 67]": 3 / 4, "(99, 100]": 1 / 4})

    # Without a collision, the attribute keeps its own name.
    results = assess(frame, ["q"], ["re_id (sensitive)"])
    assert list(results["bins"]) == ["re_id", "re_id (sensitive)"]
    assert results["bins"]["re_id"] == pytest.approx(re_id_bins)
    assert results["bins"]["re_id (sensitive)"] == pytest.approx(other_bins)

    # With both sensitive, the one named re_id takes "re_id (sensitive) (sensitive)", in its place.
    results = assess(frame, ["q"], ["re_id", "re_id (sensitive)"])
    assert list(results["bins"]) == [
        "re_id", "re_id (sensitive) (sensitive)", "re_id (sensitive)"]
    assert results["bins"]["re_id"] == pytest.approx(re_id_bins)
    assert results["bins"]["re_id (sensitive) (sensitive)"] == pytest.approx(
        re_id_attribute_bins)
    assert results["bins"]["re_id (sensitive)"] == pytest.approx(other_bins)
