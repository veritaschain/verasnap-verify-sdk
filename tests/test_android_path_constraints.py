"""Defensive parser/path checks; no forged signed chains or enrollment attempts.

Path-policy tests replace fields only on in-memory parsed test certificates.
Existing enrollment tests exercise real signature validation and device samples.
"""

from dataclasses import replace
from pathlib import Path

import pytest
from asn1crypto import core, x509 as a_x509

from attest_helpers import NOW, AndroidFixture
from verasnap_verify import _der
from verasnap_verify.enroll import AndroidPolicy, EnrollmentError
from verasnap_verify.enroll import android as module
from verasnap_verify.enroll.android import (
    OID_KEY_DESCRIPTION,
    _AttCert,
    _certificate_extensions,
    _check_path_constraints,
    verify_android_attestation,
)


def extension(oid, raw, *, critical=False):
    """A standalone extension value, not a certificate or signed payload."""
    value = a_x509.Extension()
    value["extn_id"] = oid
    value["critical"] = critical
    value["extn_value"] = core.ParsableOctetString(raw)
    return value


def basic(ca=True, path_length=None):
    return extension("basic_constraints", a_x509.BasicConstraints({
        "ca": ca, "path_len_constraint": path_length,
    }).dump(), critical=True)


def usage(*values):
    return extension("key_usage", a_x509.KeyUsage(set(values)).dump(), critical=True)


@pytest.fixture
def path():
    fixture = AndroidFixture()
    return [_AttCert.load(raw) for raw in fixture.chain(b"c" * 32)]


def constrained(cert, **changes):
    return replace(cert, constraints=replace(cert.constraints, **changes))


def rejected(path, anchor=None, *, message, code="attestation_chain_invalid"):
    with pytest.raises(EnrollmentError, match=message) as error:
        _check_path_constraints(path, anchor or path[-1])
    assert error.value.code == code


def test_valid_test_path_and_optional_key_usage(path):
    _check_path_constraints(path, path[-1])
    path[0] = constrained(path[0], key_usage=frozenset({"digital_signature"}))
    path[1] = constrained(path[1], key_usage=frozenset({"key_cert_sign"}))
    _check_path_constraints(path, path[-1])


def test_issuer_name_must_link_to_next_subject(path):
    path[0] = replace(path[0], issuer_name=a_x509.Name.build({"common_name": "Wrong issuer"}))
    rejected(path, message="issuer name does not match")


def test_root_name_must_match_configured_anchor(path):
    anchor = path[-1]
    path[-1] = replace(path[-1], subject_name=a_x509.Name.build({"common_name": "Different root"}))
    rejected(path, anchor, message="root subject")


@pytest.mark.parametrize("position", [1, 2])
def test_every_issuer_including_configured_anchor_requires_ca(path, position):
    path[position] = constrained(path[position], ca=False)
    rejected(path, message="is not a CA")


@pytest.mark.parametrize("position", [1, 2])
def test_issuer_key_usage_must_allow_certificate_signatures(path, position):
    path[position] = constrained(path[position], key_usage=frozenset({"digital_signature"}))
    rejected(path, message="cannot sign certificates")


def test_leaf_key_usage_must_allow_digital_signatures(path):
    path[0] = constrained(path[0], key_usage=frozenset({"key_agreement"}))
    rejected(path, message="does not permit digital signatures", code="attestation_key_type")


def test_path_length_zero_allows_a_leaf_but_no_intermediate(path):
    path[1] = constrained(path[1], path_length=0)
    _check_path_constraints(path, constrained(path[-1], path_length=1))
    rejected(path, constrained(path[-1], path_length=0), message="path length exceeded")


def test_path_length_counts_all_non_self_issued_intermediates(path):
    upper_name = a_x509.Name.build({"common_name": "Unit-only upper issuer"})
    upper = replace(path[1], tbs=b"unit-only-upper-record", subject_name=upper_name)
    lower = replace(path[1], issuer_name=upper_name)
    longer = [path[0], lower, upper, path[-1]]
    rejected(longer, constrained(path[-1], path_length=1), message="path length exceeded")
    _check_path_constraints(longer, constrained(path[-1], path_length=2))


def test_path_length_excludes_self_issued_rollover_certificates(path):
    upper = replace(path[1], tbs=b"unit-only-self-issued-record", subject_name=path[-1].subject_name)
    # The existing intermediate's issuer is the root's name, also the rollover
    # certificate's subject. No new certificate or signature is manufactured.
    _check_path_constraints([path[0], path[1], upper, path[-1]], constrained(path[-1], path_length=1))


def test_configured_anchor_constraints_cannot_be_replaced_by_client_copy(path):
    rejected(path, constrained(path[-1], path_length=0), message="path length exceeded")
    anchor = path[-1]
    path[-1] = constrained(path[-1], path_length=0)
    _check_path_constraints(path, anchor)


def test_duplicate_path_certificate_is_rejected(path):
    rejected([path[0], path[1], path[1], path[-1]], message="duplicate certificate")


@pytest.mark.parametrize("position", [1, 2])
def test_attestation_extension_cannot_be_selected_below_an_earlier_one(path, position):
    path[position] = replace(path[position], key_description=b"unit-only-earlier-extension")
    rejected(path, message="attested key is not the leaf")


@pytest.mark.parametrize("oid,raw", [
    ("basic_constraints", b"\x30\x00"),
    ("key_usage", b"\x03\x02\x07\x80"),
    (OID_KEY_DESCRIPTION.dotted_string, b"\x30\x00"),
    ("1.2.3.4", b"\x05\x00"),
])
def test_duplicate_extensions_rejected_even_when_identical(oid, raw):
    with pytest.raises(ValueError, match="duplicate certificate extension"):
        _certificate_extensions([extension(oid, raw), extension(oid, raw)])


@pytest.mark.parametrize("raw", [
    b"", b"\x05\x00", b"\x30\x00\x00",  # missing/wrong tag/trailing bytes
    b"\x30\x03\x01\x01\x01",  # non-DER Boolean
    b"\x30\x06\x01\x01\xff\x02\x01\xff",  # negative path length
    b"\x30\x03\x02\x01\x00",  # path length without CA
    b"\x30\x06\x01\x01\xff\x05\x01\x00",  # unexpected field
])
def test_malformed_basic_constraints_fail_closed(raw):
    with pytest.raises((ValueError, TypeError)):
        _certificate_extensions([extension("basic_constraints", raw)])


@pytest.mark.parametrize("raw", [
    b"", b"\x05\x00", b"\x03\x02\x07\x80\x00",  # syntax/trailing bytes
    b"\x03\x01\x00",  # no usage bits
    b"\x03\x02\x02\x05",  # nonzero unused bit
    b"\x03\x03\x06\x00\x40",  # undefined usage bit
    b"\x03\x02\x00\x01",  # encipherOnly without keyAgreement
])
def test_malformed_key_usage_fail_closed(raw):
    with pytest.raises((ValueError, TypeError, IndexError)):
        _certificate_extensions([extension("key_usage", raw)])


def test_key_usage_and_basic_constraints_must_agree():
    with pytest.raises(ValueError, match="keyCertSign requires"):
        _certificate_extensions([usage("key_cert_sign")])
    with pytest.raises(ValueError, match="pathLenConstraint conflicts"):
        _certificate_extensions([basic(path_length=0), usage("digital_signature")])
    result = _certificate_extensions([basic(path_length=0), usage("key_cert_sign")])
    assert result.ca and result.path_length == 0


def test_unknown_critical_extensions_rejected_noncritical_ignored():
    _certificate_extensions([extension("1.2.3.4", b"\x05\x00")])
    with pytest.raises(ValueError, match="unsupported critical"):
        _certificate_extensions([extension("1.2.3.4", b"\x05\x00", critical=True)])


@pytest.mark.parametrize("oid", sorted(module._UNSUPPORTED_CONSTRAINTS))
@pytest.mark.parametrize("critical", [False, True])
def test_unsupported_path_constraints_are_never_silently_ignored(oid, critical):
    raw = b"\x02\x01\x00" if oid == "2.5.29.54" else b"\x30\x00"
    with pytest.raises(ValueError, match="unsupported certificate constraint"):
        _certificate_extensions([extension(oid, raw, critical=critical)])


@pytest.mark.parametrize("chain,code", [
    ([b"x"], "attestation_chain_invalid"),
    ([b"x"] * 9, "attestation_chain_invalid"),
    ([b"x" * (64 * 1024 + 1), b"y"], "attestation_malformed"),
    ([b"x" * (64 * 1024)] * 5, "attestation_malformed"),
    ([b"", b"y"], "attestation_malformed"),
    (["text", b"y"], "attestation_malformed"),
])
def test_chain_resource_bounds_are_checked_before_parsing(monkeypatch, chain, code):
    def unexpected_parse(_raw):
        pytest.fail("unbounded or malformed input reached ASN.1 parsing")
    monkeypatch.setattr(_AttCert, "load", unexpected_parse)
    with pytest.raises(EnrollmentError) as error:
        verify_android_attestation(chain, b"unused", b"unused", AndroidPolicy([], []))
    assert error.value.code == code


def test_certificate_parser_rejects_trailing_data():
    fixture = AndroidFixture()
    with pytest.raises(ValueError, match="trailing data"):
        _AttCert.load(fixture.chain(b"c" * 32)[0] + b"\x00")


@pytest.mark.parametrize("sample", ["algorithm_EC_SecurityLevel_TEE", "algorithm_EC_SecurityLevel_StrongBox"])
def test_original_signed_bytes_are_preserved_for_real_device_samples(sample):
    raw = (Path(__file__).parent / "fixtures" / "android_google_samples" / sample / "cert0.der").read_bytes()
    cert = _AttCert.load(raw)
    assert cert.tbs == _der.parse_one(raw).children()[0].raw
    assert cert.constraints.key_usage == frozenset({"digital_signature"})


def test_expired_transported_root_does_not_override_valid_same_key_anchor(path):
    # Date checks use the configured x509 anchor, not the transported root copy.
    # The existing real TEE enrollment test exercises this with Google's 2016
    # root and the same-key 2022 renewal; this unit check also pins the constraint
    # helper's independence from the old copy's validity metadata.
    from datetime import timedelta
    anchor = path[-1]
    path[-1] = replace(path[-1], not_after=NOW - timedelta(days=1))
    _check_path_constraints(path, anchor)
