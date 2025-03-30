from __future__ import annotations
import json
from typing import List, Union, Dict, Sequence

from secp256k1lab.secp256k1 import Scalar, GE

from chilldkg_ref.chilldkg import (
    SessionParams,
    ParticipantMsg1,
    ParticipantMsg2,
    CoordinatorMsg1,
    CoordinatorMsg2,
    DKGOutput,
    CoordinatorInvestigationMsg,
)
from chilldkg_ref.vss import VSSCommitment
import chilldkg_ref.simplpedpop as simplpedpop
import chilldkg_ref.encpedpop as encpedpop
import chilldkg_ref.chilldkg as chilldkg

ErrorInfo = Dict[str, Union[int, str, "ErrorInfo"]]


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def bytes_list_to_hex(lst: Sequence[bytes]) -> List[str]:
    return [l_i.hex().upper() for l_i in lst]


def hex_list_to_bytes(lst: List[str]) -> List[bytes]:
    return [bytes.fromhex(l_i) for l_i in lst]


def write_json(filename: str, data: dict) -> None:
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
            error_info[key] = pinv_data_asdict(value)
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


def params_asdict(params: SessionParams) -> dict:
    return {"hostpubkeys": bytes_list_to_hex(params.hostpubkeys), "t": params.t}


def pmsg1_asdict(pmsg1: ParticipantMsg1) -> dict:
    enc_pmsg = pmsg1.enc_pmsg
    simpl_pmsg = enc_pmsg.simpl_pmsg

    result = {
        "simpl_pmsg": {
            "com": bytes_to_hex(simpl_pmsg.com.to_bytes()),
            "pop": bytes_to_hex(pmsg1.enc_pmsg.simpl_pmsg.pop),
        },
        "pubnonce": bytes_to_hex(enc_pmsg.pubnonce),
        "enc_shares": [str(share).upper() for share in enc_pmsg.enc_shares],
    }
    return result


def pmsg2_asdict(pmsg2: ParticipantMsg2) -> dict:
    return {"sig": bytes_to_hex(pmsg2.sig)}


def pinv_data_asdict(pinv_data: encpedpop.ParticipantInvestigationData) -> dict:
    secshare = pinv_data.simpl_bstate.secshare.to_bytes()
    pubshare = pinv_data.simpl_bstate.pubshare.to_bytes_compressed_with_infinity()
    enc_secshare = pinv_data.enc_secshare.to_bytes()
    pads = [pad.to_bytes() for pad in pinv_data.pads]
    return {
        "simpl_bstate": {
            "n": pinv_data.simpl_bstate.n,
            "idx": pinv_data.simpl_bstate.idx,
            "secshare": bytes_to_hex(secshare),
            "pubshare": bytes_to_hex(pubshare),
        },
        "enc_secshare": bytes_to_hex(enc_secshare),
        "pads": bytes_list_to_hex(pads),
    }


def cmsg1_asdict(cmsg1: CoordinatorMsg1) -> dict:
    enc_cmsg = cmsg1.enc_cmsg
    simpl_cmsg = enc_cmsg.simpl_cmsg

    coms_to_secrets = [
        ge.to_bytes_compressed_with_infinity() for ge in simpl_cmsg.coms_to_secrets
    ]
    sum_coms_to_nonconst_terms = [
        ge.to_bytes_compressed_with_infinity()
        for ge in simpl_cmsg.sum_coms_to_nonconst_terms
    ]
    result = {
        "simpl_cmsg": {
            "coms_to_secrets": bytes_list_to_hex(coms_to_secrets),
            "sum_coms_to_nonconst_terms": bytes_list_to_hex(sum_coms_to_nonconst_terms),
            "pops": bytes_list_to_hex(simpl_cmsg.pops),
        },
        "pubnonces": bytes_list_to_hex(enc_cmsg.pubnonces),
        "enc_secshares": [str(share).upper() for share in cmsg1.enc_secshares],
    }
    return result


def cmsg2_asdict(cmsg2: CoordinatorMsg2) -> dict:
    return {"cert": bytes_to_hex(cmsg2.cert)}


def dkg_output_asdict(dkg_output: DKGOutput) -> dict:
    secshare = bytes_to_hex(dkg_output.secshare) if dkg_output.secshare else None
    return {
        "secshare": secshare,
        "threshold_pubkey": bytes_to_hex(dkg_output.threshold_pubkey),
        "pubshares": bytes_list_to_hex(dkg_output.pubshares),
    }


def cinv_msg_asdict(cinv_msg: CoordinatorInvestigationMsg) -> dict:
    enc_cinv = cinv_msg.enc_cinv
    enc_partial_secshares = [
        share.to_bytes() for share in enc_cinv.enc_partial_secshares
    ]
    partial_pubshares = [
        pubshare.to_bytes_compressed_with_infinity()
        for pubshare in enc_cinv.partial_pubshares
    ]
    return {
        "enc_partial_secshares": bytes_list_to_hex(enc_partial_secshares),
        "partial_pubshares": bytes_list_to_hex(partial_pubshares),
    }


# functions below are used to test JSON vectors with chilldkg_ref
# in tests.py


def assert_raises(try_fn, expected_error: dict):
    try:
        try_fn()
    except Exception as e:
        assert expected_error == exception_asdict(e)
    else:
        raise AssertionError("Expected exception")


def params_from_dict(params: dict) -> SessionParams:
    return SessionParams(
        hex_list_to_bytes(params["hostpubkeys"]),
        params["t"],
    )


def pmsg1_from_dict(pmsg1: dict) -> ParticipantMsg1:
    pop = simplpedpop.Pop(bytes.fromhex(pmsg1["simpl_pmsg"]["pop"]))
    com = bytes.fromhex(pmsg1["simpl_pmsg"]["com"])
    pubnonce = bytes.fromhex(pmsg1["pubnonce"])
    enc_shares = hex_list_to_bytes(pmsg1["enc_shares"])

    t, remainder = divmod(len(com), 33)
    if remainder != 0:
        raise ValueError
    simpl_pmsg = simplpedpop.ParticipantMsg(VSSCommitment.from_bytes_and_t(com, t), pop)

    enc_pmsg = encpedpop.ParticipantMsg(
        simpl_pmsg, pubnonce, [Scalar.from_bytes(share) for share in enc_shares]
    )

    return chilldkg.ParticipantMsg1(enc_pmsg)


def pmsg2_from_dict(pmsg2: dict) -> ParticipantMsg2:
    sig = bytes.fromhex(pmsg2["sig"])
    return chilldkg.ParticipantMsg2(sig)


def cmsg1_from_dict(cmsg1: dict) -> CoordinatorMsg1:
    coms_to_secrets = [
        GE.from_bytes_with_infinity(b)
        for b in hex_list_to_bytes(cmsg1["simpl_cmsg"]["coms_to_secrets"])
    ]
    sum_coms_to_nonconst_terms = [
        GE.from_bytes_with_infinity(b)
        for b in hex_list_to_bytes(cmsg1["simpl_cmsg"]["sum_coms_to_nonconst_terms"])
    ]
    pops = [simplpedpop.Pop(b) for b in hex_list_to_bytes(cmsg1["simpl_cmsg"]["pops"])]
    pubnonces = hex_list_to_bytes(cmsg1["pubnonces"])
    enc_secshares = [
        Scalar.from_bytes(share) for share in hex_list_to_bytes(cmsg1["enc_secshares"])
    ]

    simpl_cmsg = simplpedpop.CoordinatorMsg(
        coms_to_secrets, sum_coms_to_nonconst_terms, pops
    )
    enc_cmsg = encpedpop.CoordinatorMsg(simpl_cmsg, pubnonces)
    return chilldkg.CoordinatorMsg1(enc_cmsg, enc_secshares)


def cmsg2_from_dict(cmsg2: dict) -> CoordinatorMsg2:
    cert = bytes.fromhex(cmsg2["cert"])
    return chilldkg.CoordinatorMsg2(cert)


def cinv_msg_from_dict(cinv_msg: dict) -> CoordinatorInvestigationMsg:
    enc_partial_secshares = [
        Scalar.from_bytes(share)
        for share in hex_list_to_bytes(cinv_msg["enc_partial_secshares"])
    ]
    partial_pubshares = [
        GE.from_bytes_with_infinity(b)
        for b in hex_list_to_bytes(cinv_msg["partial_pubshares"])
    ]
    enc_cinv = encpedpop.CoordinatorInvestigationMsg(
        enc_partial_secshares, partial_pubshares
    )
    return chilldkg.CoordinatorInvestigationMsg(enc_cinv)
