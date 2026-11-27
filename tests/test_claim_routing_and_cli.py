"""Policy boundaries for the example and input errors for the installed CLI."""

import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from verasnap_verify import Check, CheckStatus, Signer, Status, VerificationResult

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "verify_claim_photo.py"
claim_route = runpy.run_path(str(EXAMPLE))["claim_route"]


@pytest.mark.parametrize(
    "status, media_verified, signer_code, expected_account, route",
    [
        (Status.ANCHOR_VERIFIED, True, "known", "policy-1", "fast track"),
        (Status.ANCHOR_VERIFIED, False, "known", "policy-1", "normal review"),
        (Status.ANCHOR_VERIFIED, True, "known_unattested", "policy-1", "normal review"),
        (Status.ANCHOR_VERIFIED, True, "known", "policy-2", "normal review"),
        (Status.ANCHOR_VERIFIED, True, "known", None, "normal review"),
        (Status.PARTIALLY_VERIFIED, True, "known", "policy-1", "normal review"),
        (Status.HASH_MISMATCH, False, "known", "policy-1", "refer"),
    ],
)
def test_claim_route(status, media_verified, signer_code, expected_account, route):
    result = VerificationResult(
        status=status,
        checks=[Check("signer_key", CheckStatus.PASSED, signer_code, "")],
        summary="",
        signer=Signer(account_ref="policy-1"),
        media_verified=media_verified,
    )
    assert claim_route(result, expected_account).split(":", 1)[0] == route


@pytest.mark.parametrize("missing", ["proof", "media", "trust"])
def test_missing_input_exit_code(tmp_path, missing):
    proof = tmp_path / "proof.json"
    arguments = ["verify", str(proof)]
    if missing != "proof":
        proof.write_text("{}")
        arguments.extend([f"--{missing}", str(tmp_path / missing)])

    run = subprocess.run(
        [sys.executable, "-m", "verasnap_verify.cli", *arguments],
        capture_output=True, text=True, check=False,
    )
    assert run.returncode == 3
    assert run.stdout == ""
    assert run.stderr.startswith("error:")
    assert "Traceback" not in run.stderr
