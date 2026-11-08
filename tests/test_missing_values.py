# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2021-2026 Gabriel Henrique Lopes Gomes Alves Nunes

# Missing values, GitHub issue #2: in BVM, all the values pandas.isna treats as missing (NaN, None,
# pd.NA, NaT) in a quasi-identifier or sensitive attribute are one value of their own, apart from
# every real value. Tests check values worked out by hand, the oracle, or both. The oracle: a table
# and its copy with each column's missing values filled with a value found nowhere else in that
# column give the same results.

import random

import pandas
import pytest

from bvmlib.bvm import BVM, BVMLongitudinal

NAN = float("nan")
NA = pandas.NA

LABELS = ["(" + str(k - 1) + ", " + str(k) + "]" for k in range(1, 101)]


def histogram(fractions):
    "The full 100-bin histogram with the given fractions and 0 in every other bin."
    assert set(fractions) <= set(LABELS)
    return {label: fractions.get(label, 0) for label in LABELS}


def assess(frame, qids, sensitive=None):
    bvm = BVM(frame)
    bvm.qids(qids)
    if sensitive is not None:
        bvm.sensitive(sensitive)
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


def filled(frame):
    "The oracle's table: each column's missing values become one value found nowhere else in it."
    frame = frame.copy()
    for name in frame.columns:
        column = frame[name]
        present = column.dropna()
        if len(present) == len(column):
            continue
        # Of the column's own kind: a later date, a larger number, or a new string.
        if column.dtype.kind == "M":
            fill = pandas.Timestamp("2000-01-01")
            if len(present) > 0:
                fill = present.max() + pandas.Timedelta(1, unit="D")
        elif pandas.api.types.is_numeric_dtype(column):
            fill = present.max() + 1 if len(present) > 0 else 0
        else:
            fill = "missing"
            while fill in set(present):
                fill += "_"
        frame[name] = column.fillna(fill)
        assert not frame[name].isna().any()
    return frame


def same(actual, expected):
    if isinstance(expected, str):
        assert actual == expected
    else:
        assert actual == pytest.approx(expected)


def expect_as_filled(frame, qids, sensitive=None):
    "The oracle: the results equal those for the table with its missing values filled."
    actual = assess(frame, qids, sensitive)
    expected = assess(filled(frame), qids, sensitive)

    assert sorted(actual) == sorted(expected)
    same(actual["dCR"], expected["dCR"])
    same(actual["pCR"], expected["pCR"])
    assert list(actual["bins"]) == list(expected["bins"])
    for case in expected["bins"]:
        same(actual["bins"][case], expected["bins"][case])
    for attribute in expected.get("CA", {}):
        same(actual["CA"][attribute], expected["CA"][attribute])
    for table in ["re_id", "att_inf"]:
        if table in expected:
            assert list(actual[table].columns) == list(expected[table].columns)
            assert len(actual[table]) == len(expected[table])
            for got, want in zip(actual[table].to_dict("records"),
                                 expected[table].to_dict("records")):
                for column in want:
                    same(got[column], want[column])
    return actual


def test_numeric_quasi_identifier_with_nan():
    # Classes: 30 has 2 rows, 40 has 1, missing has 3.
    frame = pandas.DataFrame({"age": [30, NAN, 30, NAN, 40, NAN]})
    results = expect_as_filled(frame, ["age"])
    expect_re_id(results, dCR=1 / 6, pCR=3, rows=6,
                 bins={"(49, 50]": 2 / 6, "(99, 100]": 1 / 6, "(33, 34]": 3 / 6})


def test_object_columns_with_none():
    # Classes by q: "a" rows 0 and 4, "b" row 2, missing rows 1, 3 and 5.
    # s per class: "a" {missing, x}, "b" {missing}, missing {x, missing, y}.
    # s overall: missing 3, x 2, y 1.
    frame = pandas.DataFrame({
        "q": pandas.Series(["a", None, "b", None, "a", None], dtype=object),
        "s": pandas.Series([None, "x", None, None, "x", "y"], dtype=object),
    })
    bins = {"(49, 50]": 2 / 6, "(99, 100]": 1 / 6, "(33, 34]": 3 / 6}

    expect_re_id(expect_as_filled(frame, ["q"]), dCR=1 / 6, pCR=3, rows=6, bins=bins)

    results = expect_as_filled(frame, ["q"], ["s"])
    expect_re_id(results, dCR=1 / 6, pCR=3, rows=6, bins=bins)
    expect_att_inf(results, "s", dCA=1 / 6, pCA=1, prior=3 / 6, posterior=3 / 6, bins=bins)


def test_none_nan_and_na_mixed_in_one_column():
    # Classes by q: "a" rows 0 and 5, missing rows 1 to 4.
    # s per class: "a" {missing, missing}, missing {missing, x, missing, x}.
    # s overall: missing 4, x 2.
    frame = pandas.DataFrame({
        "q": pandas.Series(["a", None, NAN, None, NAN, "a"], dtype=object),
        "s": pandas.Series([None, NAN, "x", NA, "x", NAN], dtype=object),
    })
    re_id_bins = {"(49, 50]": 2 / 6, "(24, 25]": 4 / 6}

    expect_re_id(expect_as_filled(frame, ["q"]), dCR=0, pCR=2, rows=6, bins=re_id_bins)

    results = expect_as_filled(frame, ["q"], ["s"])
    expect_re_id(results, dCR=0, pCR=2, rows=6, bins=re_id_bins)
    expect_att_inf(results, "s", dCA=2 / 6, pCA=1, prior=4 / 6, posterior=4 / 6,
                   bins={"(99, 100]": 2 / 6, "(49, 50]": 4 / 6})


def test_nullable_integers_with_na():
    # Classes by q: 1 rows 0 and 4, 2 row 2, missing rows 1 and 3.
    # s per class: 1 {7, 8}, 2 {missing}, missing {missing, 7}. s overall: 7 2, missing 2, 8 1.
    frame = pandas.DataFrame({
        "q": pandas.array([1, NA, 2, NA, 1], dtype="Int64"),
        "s": pandas.array([7, NA, NA, 7, 8], dtype="Int64"),
    })
    bins = {"(49, 50]": 4 / 5, "(99, 100]": 1 / 5}

    expect_re_id(expect_as_filled(frame, ["q"]), dCR=1 / 5, pCR=3, rows=5, bins=bins)

    results = expect_as_filled(frame, ["q"], ["s"])
    expect_re_id(results, dCR=1 / 5, pCR=3, rows=5, bins=bins)
    expect_att_inf(results, "s", dCA=1 / 5, pCA=3 / 2, prior=2 / 5, posterior=3 / 5, bins=bins)


def test_pandas_string_columns_with_missing_values():
    # Classes by q: "a" rows 0 and 4, "b" row 2, missing rows 1 and 3.
    # s per class: "a" {x, missing}, "b" {missing}, missing {missing, x}. s overall: missing 3, x 2.
    frame = pandas.DataFrame({
        "q": pandas.array(["a", NA, "b", NA, "a"], dtype="string"),
        "s": pandas.array(["x", NA, NA, "x", NA], dtype="string"),
    })
    bins = {"(49, 50]": 4 / 5, "(99, 100]": 1 / 5}

    expect_re_id(expect_as_filled(frame, ["q"]), dCR=1 / 5, pCR=3, rows=5, bins=bins)

    results = expect_as_filled(frame, ["q"], ["s"])
    expect_re_id(results, dCR=1 / 5, pCR=3, rows=5, bins=bins)
    expect_att_inf(results, "s", dCA=1 / 5, pCA=1, prior=3 / 5, posterior=3 / 5, bins=bins)


def test_dates_with_nat():
    # Classes by q: 2020 rows 0 and 2, missing rows 1 and 3. s: 2020 {missing, missing},
    # missing {2021, missing}. s overall: missing 3, 2021 1.
    frame = pandas.DataFrame({
        "q": pandas.to_datetime(pandas.Series(["2020-01-01", None, "2020-01-01", None])),
        "s": pandas.to_datetime(pandas.Series([None, "2021-01-01", None, None])),
    })

    results = expect_as_filled(frame, ["q"], ["s"])
    expect_re_id(results, dCR=0, pCR=2, rows=4, bins={"(49, 50]": 1})
    expect_att_inf(results, "s", dCA=2 / 4, pCA=1, prior=3 / 4, posterior=3 / 4,
                   bins={"(99, 100]": 2 / 4, "(49, 50]": 2 / 4})


def test_missing_values_in_two_quasi_identifiers():
    # Classes (a, b): (1, missing) rows 0 and 2, (missing, 2) rows 1 and 3, (missing, missing)
    # row 4, (1, 2) row 5.
    frame = pandas.DataFrame({
        "a": [1, NAN, 1, NAN, NAN, 1],
        "b": [NAN, 2, NAN, 2, NAN, 2],
    })
    results = expect_as_filled(frame, ["a", "b"])
    expect_re_id(results, dCR=2 / 6, pCR=4, rows=6,
                 bins={"(49, 50]": 4 / 6, "(99, 100]": 2 / 6})


def test_missing_values_in_a_quasi_identifier_only():
    # Classes by q: 1 rows 0 and 2, missing rows 1 and 3. Each class holds s "a" once, "b" once.
    frame = pandas.DataFrame({"q": [1, NAN, 1, NAN], "s": ["a", "a", "b", "b"]})

    results = expect_as_filled(frame, ["q"], ["s"])
    expect_re_id(results, dCR=0, pCR=2, rows=4, bins={"(49, 50]": 1})
    expect_att_inf(results, "s", dCA=0, pCA=1, prior=2 / 4, posterior=2 / 4,
                   bins={"(49, 50]": 1})


def test_missing_values_in_a_sensitive_attribute():
    # Classes by q: 1 rows 0 to 2, 2 rows 3 and 4, 3 row 5.
    # s per class: 1 {missing, missing, 5}, 2 {5, missing}, 3 {missing}. s overall: missing 4, 5 2.
    frame = pandas.DataFrame({
        "q": [1, 1, 1, 2, 2, 3],
        "s": [NAN, NAN, 5, 5, NAN, NAN],
    })

    results = expect_as_filled(frame, ["q"], ["s"])
    expect_re_id(results, dCR=1 / 6, pCR=3, rows=6,
                 bins={"(33, 34]": 3 / 6, "(49, 50]": 2 / 6, "(99, 100]": 1 / 6})
    # pCA: 2 + 1 + 1 classified rows over the 4 the prior guesses right.
    expect_att_inf(results, "s", dCA=1 / 6, pCA=4 / 4, prior=4 / 6, posterior=4 / 6,
                   bins={"(66, 67]": 3 / 6, "(49, 50]": 2 / 6, "(99, 100]": 1 / 6})


@pytest.mark.parametrize("text, missing", [
    ("nan", NAN), ("None", None), ("<NA>", NA), ("NaT", pandas.NaT), ("", None),
    ("missing", None),
], ids=["nan", "None", "NA", "NaT", "empty", "missing"])
def test_real_strings_beside_missing_values_stay_two_values(text, missing):
    # One class of 4 rows: "x" once, and either the missing value or the text twice.
    for values in [[text, missing, missing, "x"], [text, missing, text, "x"]]:
        frame = pandas.DataFrame({"q": [1, 1, 1, 1], "s": pandas.Series(values, dtype=object)})

        results = expect_as_filled(frame, ["q"], ["s"])
        expect_att_inf(results, "s", dCA=0, pCA=1, prior=2 / 4, posterior=2 / 4,
                       bins={"(49, 50]": 1})

        # As a quasi-identifier: classes of 2 rows, 1 row and 1 row ("x").
        results = expect_as_filled(frame, ["s"])
        expect_re_id(results, dCR=2 / 4, pCR=3, rows=4,
                     bins={"(49, 50]": 2 / 4, "(99, 100]": 2 / 4})


def test_every_value_missing():
    # One class of 3 rows, and s has one value, so dCA is 0 as for any constant attribute.
    frame = pandas.DataFrame({
        "q": [NAN, NAN, NAN],
        "s": pandas.Series([None, None, None], dtype=object),
    })
    results = expect_as_filled(frame, ["q"], ["s"])
    expect_re_id(results, dCR=0, pCR=1, rows=3, bins={"(33, 34]": 1})
    expect_att_inf(results, "s", dCA=0, pCA=1, prior=1, posterior=1, bins={"(99, 100]": 1})

    # Only the sensitive attribute missing: classes 1 (2 rows) and 2 (1 row).
    frame = pandas.DataFrame({"q": [1, 1, 2], "s": [NAN, NAN, NAN]})
    results = expect_as_filled(frame, ["q"], ["s"])
    expect_re_id(results, dCR=1 / 3, pCR=2, rows=3,
                 bins={"(49, 50]": 2 / 3, "(99, 100]": 1 / 3})
    expect_att_inf(results, "s", dCA=0, pCA=1, prior=1, posterior=1, bins={"(99, 100]": 1})


def test_one_row_table_with_missing_values():
    frame = pandas.DataFrame({"q": [NAN], "s": [NAN]})
    results = expect_as_filled(frame, ["q"], ["s"])
    expect_re_id(results, dCR=0, pCR=1, rows=1, bins={"(99, 100]": 1})
    expect_att_inf(results, "s", dCA=0, pCA=1, prior=1, posterior=1, bins={"(99, 100]": 1})


def test_guard_values_equal_under_eq_stay_one_class_beside_missing_values():
    # Guard: -0.0 == 0.0 and 1 == 1.0, so each pair is one class, even when the column holds a
    # missing value, which is a second one.
    frame = pandas.DataFrame({"q": [-0.0, 0.0, NAN]})
    expect_re_id(expect_as_filled(frame, ["q"]), dCR=1 / 3, pCR=2, rows=3,
                 bins={"(49, 50]": 2 / 3, "(99, 100]": 1 / 3})
    frame = pandas.DataFrame({"q": pandas.Series([1, 1.0, None], dtype=object)})
    expect_re_id(assess(frame, ["q"]), dCR=1 / 3, pCR=2, rows=3,
                 bins={"(49, 50]": 2 / 3, "(99, 100]": 1 / 3})


def test_real_text_beside_missing_values_in_a_later_sensitive_attribute():
    # As the real-strings test, with the text in the second sensitive attribute.
    frame = pandas.DataFrame({"q": [1, 1, 1, 1], "a": ["p"] * 4,
                              "s": pandas.Series(["nan", NAN, NAN, "x"], dtype=object)})
    results = expect_as_filled(frame, ["q"], ["a", "s"])
    expect_att_inf(results, "s", dCA=0, pCA=1, prior=2 / 4, posterior=2 / 4, bins={"(49, 50]": 1})


def test_categorical_sensitive_attribute_with_missing_values_and_an_unused_category():
    # Classes by q: 1 {x, missing}, 2 {missing, missing}. s overall: missing 3, x 1.
    frame = pandas.DataFrame({"q": [1, 1, 2, 2],
                              "s": pandas.Categorical(["x", NAN, NAN, NAN], categories=["x", "y"])})
    expect_att_inf(assess(frame, ["q"], ["s"]), "s", dCA=2 / 4, pCA=1, prior=3 / 4,
                   posterior=3 / 4, bins={"(49, 50]": 2 / 4, "(99, 100]": 2 / 4})


def random_table(seed, rows=60):
    "A column of each kind with a quarter of its values missing, and one with none missing."
    rng = random.Random(seed)

    def draw(values, missing):
        return [rng.choice(missing) if rng.random() < 0.25 else rng.choice(values)
                for _ in range(rows)]

    # The real values include -1, 0, "" and "missing", which a fixed stand-in could equal.
    text = ["", "a", "b", "nan", "None", "missing"]
    return pandas.DataFrame({
        "float": pandas.Series(draw([-1.0, 0.0, 1.5, 2.5], [NAN]), dtype="float64"),
        "int": pandas.array(draw([-1, 0, 1, 2], [NA]), dtype="Int64"),
        "text": pandas.Series(draw(text, [None, NAN, NA]), dtype=object),
        "string": pandas.array(draw(["", "a", "<NA>", "b"], [NA]), dtype="string"),
        "date": pandas.to_datetime(pandas.Series(draw(["2020-01-01", "2021-06-30"], [None]))),
        "complete": [rng.choice(["a", "b", "c"]) for _ in range(rows)],
    })


@pytest.mark.parametrize("seed", [1, 2, 3])
@pytest.mark.parametrize("qids, sensitive", [
    (["float"], ["text"]),
    (["int", "text"], ["float", "string"]),
    (["string", "date"], ["int", "date"]),
    (["text"], ["text", "float"]),
    (["float", "int", "text", "string", "date"], None),
    (["float", "text"], ["complete"]),
], ids=["float", "int_text", "string_date", "qid_also_sensitive", "five_qids", "complete"])
def test_results_equal_those_of_the_filled_table(seed, qids, sensitive):
    expect_as_filled(random_table(seed), qids, sensitive)


def test_guard_table_without_missing_values():
    # Guard, with no missing value. Classes by q: 1 {a, b}, 2 {a, a, b}, 3 {c}.
    # s overall: a 3, b 2, c 1. Real strings named like missing values are ordinary values.
    frame = pandas.DataFrame({
        "q": [1, 2, 3, 2, 1, 2],
        "s": ["a", "a", "c", "a", "b", "b"],
        "t": ["nan", "None", "nan", "None", "<NA>", "None"],
    })

    results = assess(frame, ["q"], ["s", "t"])
    bins = {"(49, 50]": 2 / 6, "(33, 34]": 3 / 6, "(99, 100]": 1 / 6}
    expect_re_id(results, dCR=1 / 6, pCR=3, rows=6, bins=bins)
    expect_att_inf(results, "s", dCA=1 / 6, pCA=4 / 3, prior=3 / 6, posterior=4 / 6,
                   bins={"(49, 50]": 2 / 6, "(66, 67]": 3 / 6, "(99, 100]": 1 / 6})
    # t per class: 1 {nan, <NA>}, 2 {None, None, None}, 3 {nan}. t overall: None 3.
    expect_att_inf(results, "t", dCA=4 / 6, pCA=5 / 3, prior=3 / 6, posterior=5 / 6,
                   bins={"(49, 50]": 2 / 6, "(99, 100]": 4 / 6})


def test_guard_input_table_is_not_modified():
    # Guard: assess() leaves the caller's table as it was.
    frame = pandas.DataFrame({
        "float": [2.5, NAN, 1.5, NAN],
        "text": pandas.Series([None, "a", NAN, "a"], dtype=object),
        "int": pandas.array([NA, 1, 1, NA], dtype="Int64"),
        "string": pandas.array(["b", NA, NA, "a"], dtype="string"),
    })
    copy = frame.copy()
    assess(frame, ["float", "text"], ["int", "string"])
    pandas.testing.assert_frame_equal(frame, copy)
    assert [repr(value) for value in frame["text"]] == ["None", "'a'", "nan", "'a'"]


def test_guard_longitudinal_join_writes_missing_values_as_text():
    # Guard. The join writes each quasi-identifier as the text "<first>#<second>", where a
    # missing value and an unmatched row both read "nan".
    # Classes: "1.0#nan" ids 1 and 3, "nan#3.0" id 2, "2.0#nan" id 4 (not in the second table).
    first = pandas.DataFrame({"id": [1, 2, 3, 4], "q": [1.0, NAN, 1.0, 2.0]})
    second = pandas.DataFrame({"id": [1, 2, 3, 5], "q": [NAN, 3.0, NAN, 2.0]})
    longitudinal = BVMLongitudinal([first, second], ["id", "id"])
    longitudinal.qids([["q"], ["q"]])

    expect_re_id(longitudinal.assess(), dCR=2 / 4, pCR=3, rows=4,
                 bins={"(49, 50]": 2 / 4, "(99, 100]": 2 / 4})
