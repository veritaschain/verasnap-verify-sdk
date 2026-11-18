"""Build synthetic Android Key Attestation chains and Apple App Attest objects for tests.

Real roots are replaced by test roots passed to the policies, so every check
except the root pinning itself is exercised end to end.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------- DER encoding


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def integer(v: int) -> bytes:
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return tlv(0x02, b)


def enumerated(v: int) -> bytes:
    return tlv(0x0A, integer(v)[2:])


def octets(b: bytes) -> bytes:
    return tlv(0x04, b)


def boolean(v: bool) -> bytes:
    return tlv(0x01, b"\xff" if v else b"\x00")


def null() -> bytes:
    return b"\x05\x00"


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(sorted(items)))


def explicit(tag: int, inner: bytes) -> bytes:
    if tag < 31:
        head = bytes([0xA0 | tag])
    else:
        parts = []
        t = tag
        parts.append(t & 0x7F)
        t >>= 7
        while t:
            parts.append(0x80 | (t & 0x7F))
            t >>= 7
        head = bytes([0xBF]) + bytes(reversed(parts))
    return head + _len(len(inner)) + inner


# ---------------------------------------------------------------- certificates


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(subject_cn, subject_key, issuer_cn, issuer_key, *, ca: bool, extensions=(), days=365, not_before=None):
    nb = not_before or (NOW - timedelta(days=1))
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(_name(issuer_cn))
        .public_key(subject_key.public_key() if hasattr(subject_key, "public_key") else subject_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(nb + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical=critical)
    return builder.sign(issuer_key, hashes.SHA256())


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------- Android


def key_description(
    challenge: bytes,
    *,
    package: str = "org.veritaschain.verasnap",
    signing_digest: bytes = hashlib.sha256(b"release-cert").digest(),
    security_level: int = 2,
    verified_boot_state: int = 0,
    device_locked: bool = True,
    origin: int = 0,
    algorithm: int = 3,
    curve: int = 1,
    purposes=(2,),
    unknown_extra: bool = True,
) -> bytes:
    app_id = seq(set_of(seq(octets(package.encode()), integer(16))), set_of(octets(signing_digest)))
    software = seq(explicit(701, integer(int(NOW.timestamp() * 1000))), explicit(709, octets(app_id)))
    rot = seq(octets(b"\x11" * 32), boolean(device_locked), enumerated(verified_boot_state), octets(b"\x22" * 32))
    hw_items = [
        explicit(1, set_of(*[integer(p) for p in purposes])),
        explicit(2, integer(algorithm)),
        explicit(3, integer(256)),
        explicit(5, set_of(integer(4))),
        explicit(10, integer(curve)),
        explicit(503, null()),
        explicit(702, integer(origin)),
        explicit(704, rot),
        explicit(705, integer(160000)),
        explicit(706, integer(202610)),
    ]
    if unknown_extra:
        hw_items.append(explicit(724, octets(b"\x33" * 32)))  # moduleHash (KeyMint 400), unknown to old parsers
    hardware = seq(*hw_items)
    return seq(
        integer(300),
        enumerated(security_level),
        integer(300),
        enumerated(security_level),
        octets(challenge),
        octets(b""),
        software,
        hardware,
    )


class AndroidFixture:
    """A test attestation root, an intermediate, and a signing key with its leaf."""

    OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.root = make_cert("Test Attestation Root", self.root_key, "Test Attestation Root", self.root_key, ca=True, days=3650)
        self.inter_key = ec.generate_private_key(ec.SECP256R1())
        self.inter = make_cert("Test Attestation Intermediate", self.inter_key, "Test Attestation Root", self.root_key, ca=True)
        self.signing_key = ec.generate_private_key(ec.SECP256R1())

    def chain(self, challenge: bytes, *, key=None, **kd) -> list[bytes]:
        key = key or self.signing_key
        ext = x509.UnrecognizedExtension(self.OID, key_description(challenge, **kd))
        leaf = make_cert("Android Keystore Key", key, "Test Attestation Intermediate", self.inter_key, ca=False, extensions=[(ext, False)])
        return [der(leaf), der(self.inter), der(self.root)]


# ---------------------------------------------------------------- Apple


class AppleFixture:
    OID_NONCE = ObjectIdentifier("1.2.840.113635.100.8.2")

    def __init__(self, app_id: str = "ABCDE12345.org.veritaschain.verasnap"):
        self.app_id = app_id
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.root = make_cert("Test App Attestation Root CA", self.root_key, "Test App Attestation Root CA", self.root_key, ca=True, days=3650)
        self.inter_key = ec.generate_private_key(ec.SECP384R1())
        self.inter = make_cert("Test App Attestation CA 1", self.inter_key, "Test App Attestation Root CA", self.root_key, ca=True)
        self.attest_key = ec.generate_private_key(ec.SECP256R1())

    @property
    def key_id(self) -> bytes:
        pub = self.attest_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return hashlib.sha256(pub).digest()

    def auth_data(self, *, app_id=None, counter=0, aaguid=b"appattest" + b"\x00" * 7, attested=True, cred_id=None) -> bytes:
        rp = hashlib.sha256((app_id or self.app_id).encode()).digest()
        out = rp + b"\x40" + counter.to_bytes(4, "big")
        if attested:
            cid = cred_id if cred_id is not None else self.key_id
            out += aaguid + len(cid).to_bytes(2, "big") + cid + cbor2.dumps({1: 2})
        return out

    def attestation(self, client_data_hash: bytes, **auth) -> bytes:
        ad = self.auth_data(**auth)
        nonce = hashlib.sha256(ad + client_data_hash).digest()
        ext_value = seq(explicit(1, octets(nonce)))
        ext = x509.UnrecognizedExtension(self.OID_NONCE, ext_value)
        cred = make_cert("App Attest Credential", self.attest_key, "Test App Attestation CA 1", self.inter_key, ca=False, extensions=[(ext, False)])
        return cbor2.dumps({"fmt": "apple-appattest", "attStmt": {"x5c": [der(cred), der(self.inter)], "receipt": b"receipt"}, "authData": ad})

    def assertion(self, client_data_hash: bytes, counter: int) -> bytes:
        ad = self.auth_data(counter=counter, attested=False)
        nonce = hashlib.sha256(ad + client_data_hash).digest()
        sig = self.attest_key.sign(nonce, ec.ECDSA(hashes.SHA256()))
        return cbor2.dumps({"signature": sig, "authenticatorData": ad})
