from __future__ import annotations

import json
from pathlib import Path
from typing import TypeAlias

from chilldkg_ref import chilldkg, encpedpop

ErrorInfo: TypeAlias = "dict[str, int | str | ErrorInfo]"


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def bytes_list_to_hex(lst: list[bytes]) -> list[str]:
    return [l_i.hex().upper() for l_i in lst]


def hex_list_to_bytes(lst: list[str]) -> list[bytes]:
    return [bytes.fromhex(l_i) for l_i in lst]


def write_json(filename: Path, data: dict) -> None:
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)


def exception_asdict(e: Exception) -> dict:
    error_info: ErrorInfo = {"type": e.__class__.__name__}

    for key, value in e.__dict__.items():
        if isinstance(value, (str, int)):
            error_info[key] = value
        elif isinstance(value, bytes):
            error_info[key] = bytes_to_hex(value)
        elif isinstance(value, encpedpop.ParticipantInvestigationData):
            continue
        else:
            raise NotImplementedError(
                f"Conversion for type {type(value).__name__} is not implemented"
            )

    # the last argument might contain the error message
    if len(e.args) > 0 and isinstance(e.args[-1], str):
        error_info.setdefault("message", e.args[-1])

    return error_info


def expect_exception(try_fn, expected_exception):
    try:
        try_fn()
    except expected_exception as e:
        return exception_asdict(e)
    except Exception as e:
        raise AssertionError(f"Wrong exception raised: {type(e).__name__}")
    else:
        raise AssertionError("Expected exception")


def expect_faulty_exception(try_fn, expected_exception, expected_participant_id):
    error = expect_exception(try_fn, expected_exception)
    actual = error.get("participant_id")
    assert actual == expected_participant_id, (
        f"expected faulty participant {expected_participant_id}, got {actual}"
    )
    return error


def params_asdict(params: chilldkg.SessionParams) -> dict:
    return {"hostpubkeys": bytes_list_to_hex(params.hostpubkeys), "t": params.t}


def tg_id(t: int, n: int) -> str:
    return f"{t}of{n}"


def threshold_info_asdict(threshold_info: chilldkg.ThresholdInfo) -> dict:
    return {
        "t": threshold_info.t,
        "thresh_pk": bytes_to_hex(threshold_info.thresh_pk),
        "pubshares": bytes_list_to_hex(threshold_info.pubshares),
    }


INPUT_VALIDATION_DESCRIPTION = [
    "",
    "For each input validation error test case:",
    "  Proceed as for error test cases. These test cases pass a fixed-size argument of",
    "  wrong length (e.g., a host secret key that is not 32 bytes or a signature in pmsgs2",
    "  that is not 64 bytes), for which the reference implementation raises ValueError.",
    "  Implementations whose types rule out such arguments (e.g., fixed-size byte arrays)",
    "  may skip them. Wrong lengths that depend on t or n (e.g., of cmsg1 or pmsgs1) are",
    "  covered by the error test cases (LengthDoesNotMatchParamsError).",
]


def split_input_validation_cases(groups):
    # Move the error test cases that expect a plain ValueError, which is raised
    # for fixed-size arguments of wrong length, to a separate list, so that
    # implementations can skip them as a whole.
    for group in groups:
        error_cases = group["error_tests"]
        group["error_tests"] = [
            case for case in error_cases if case["error"]["type"] != "ValueError"
        ]
        group["input_validation_error_tests"] = [
            case for case in error_cases if case["error"]["type"] == "ValueError"
        ]


def assign_tc_ids(groups):
    tc_id = 1
    for group in groups:
        for key in (
            "valid_tests",
            "error_tests",
            "input_validation_error_tests",
        ):
            for i, case in enumerate(group.get(key, [])):
                assert "tc_id" not in case
                group[key][i] = {"tc_id": tc_id, **case}
                tc_id += 1


# functions below are used to test JSON vectors with chilldkg_ref
# in tests.py


def assert_raises(try_fn, expected_error: dict):
    try:
        try_fn()
    except Exception as e:
        assert expected_error == exception_asdict(e)
    else:
        raise AssertionError("Expected exception")


def params_from_dict(params: dict) -> chilldkg.SessionParams:
    return chilldkg.SessionParams(
        hex_list_to_bytes(params["hostpubkeys"]),
        params["t"],
    )
