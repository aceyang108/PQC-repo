import secrets
import hashlib
from dilithium_py.ml_dsa.default_parameters import ML_DSA_44

# SECP256R1 Curve Parameters (NIST P-256)
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = -3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_infinity(self):
        return self.x is None and self.y is None

    def __eq__(self, other):
        if other is None:
            return False
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.is_infinity():
            return "Point(Infinity)"
        return f"Point({hex(self.x)}, {hex(self.y)})"

INFINITY = Point(None, None)
G = Point(Gx, Gy)

def mod_inv(a, m):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % m, m
    while low > 1:
        r = high // low
        nm, nh = hm - lm * r, high - low * r
        lm, hm, low, high = nm, lm, nh, low
    return lm % m

def point_add(p1, p2):
    if p1.is_infinity():
        return p2
    if p2.is_infinity():
        return p1
    if p1.x == p2.x:
        if (p1.y + p2.y) % P == 0:
            return INFINITY
        return point_double(p1)
    
    num = (p2.y - p1.y) % P
    den = (p2.x - p1.x) % P
    m = (num * mod_inv(den, P)) % P
    x3 = (m * m - p1.x - p2.x) % P
    y3 = (m * (p1.x - x3) - p1.y) % P
    return Point(x3, y3)

def point_double(p):
    if p.is_infinity():
        return INFINITY
    num = (3 * p.x * p.x + A) % P
    den = (2 * p.y) % P
    m = (num * mod_inv(den, P)) % P
    x3 = (m * m - 2 * p.x) % P
    y3 = (m * (p.x - x3) - p.y) % P
    return Point(x3, y3)

def point_mul(k, p):
    k = k % N
    result = INFINITY
    addend = p
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1
    return result

def point_to_bytes(p, compressed=True):
    if p.is_infinity():
        return b'\x00' * 33 if compressed else b'\x00' * 65
    x_bytes = p.x.to_bytes(32, 'big')
    if compressed:
        prefix = b'\x02' if p.y % 2 == 0 else b'\x03'
        return prefix + x_bytes
    else:
        y_bytes = p.y.to_bytes(32, 'big')
        return b'\x04' + x_bytes + y_bytes

def bytes_to_point(b):
    if len(b) == 33:
        prefix = b[0]
        x = int.from_bytes(b[1:], 'big')
        y2 = (pow(x, 3, P) + A * x + B) % P
        y = pow(y2, (P + 1) // 4, P)
        if (prefix == 2 and y % 2 != 0) or (prefix == 3 and y % 2 == 0):
            y = P - y
        return Point(x, y)
    elif len(b) == 65:
        x = int.from_bytes(b[1:33], 'big')
        y = int.from_bytes(b[33:], 'big')
        return Point(x, y)
    raise ValueError("Invalid point bytes length")

# ECQV Implicit Certificate Helpers
def ecqv_hash(cert_data):
    h = hashlib.sha256(cert_data).digest()
    return int.from_bytes(h, 'big') % N

def ecqv_obu_keygen_request():
    """OBU generates raw registration values."""
    k_obu = secrets.randbelow(N - 1) + 1
    R_obu = point_mul(k_obu, G)
    return k_obu, R_obu

def ecqv_ca_issue(R_obu, obu_id, expiry, pk_obu_pqc, d_CA_ecc):
    """CA computes reconstruction point and private key contribution."""
    k_ca = secrets.randbelow(N - 1) + 1
    P_recon = point_add(R_obu, point_mul(k_ca, G))
    P_recon_bytes = point_to_bytes(P_recon, compressed=True)
    
    # Bind OBU ID, reconstruction point, expiry, and PQC public key
    cert_data = obu_id.encode('utf-8') + P_recon_bytes + expiry.to_bytes(8, 'big') + pk_obu_pqc
    e = ecqv_hash(cert_data)
    
    s_ca = (e * k_ca + d_CA_ecc) % N
    return P_recon, s_ca

def ecqv_obu_recover_key(s_ca, P_recon, k_obu, obu_id, expiry, pk_obu_pqc, Q_CA_ecc):
    """OBU recovers its private key."""
    P_recon_bytes = point_to_bytes(P_recon, compressed=True)
    cert_data = obu_id.encode('utf-8') + P_recon_bytes + expiry.to_bytes(8, 'big') + pk_obu_pqc
    e = ecqv_hash(cert_data)
    
    d_obu = (e * k_obu + s_ca) % N
    Q_obu = point_mul(d_obu, G)
    
    # Self-check correctness
    expected_Q_obu = point_add(point_mul(e, P_recon), Q_CA_ecc)
    if Q_obu != expected_Q_obu:
        raise ValueError("ECQV recovered key does not match CA public key reconstruction")
        
    return d_obu, Q_obu

def ecqv_rsu_reconstruct_public_key(P_recon, obu_id, expiry, pk_obu_pqc, Q_CA_ecc):
    """RSU reconstructs OBU's public key from implicit certificate data."""
    P_recon_bytes = point_to_bytes(P_recon, compressed=True)
    cert_data = obu_id.encode('utf-8') + P_recon_bytes + expiry.to_bytes(8, 'big') + pk_obu_pqc
    e = ecqv_hash(cert_data)
    
    Q_obu = point_add(point_mul(e, P_recon), Q_CA_ecc)
    return Q_obu

# H-FSwA (Silithium) Signing & Verification
def h_fswa_sign(sk_pqc, d_ecc, message, ctx=b""):
    """
    Generate H-FSwA (Silithium) Hybrid Signature:
    Returns 2452 bytes (32-byte Schnorr s + 2420-byte ML-DSA-44 signature)
    """
    # 1. ECC generates commitment point R = k * G
    k = secrets.randbelow(N - 1) + 1
    R_point = point_mul(k, G)
    R_bytes = point_to_bytes(R_point, compressed=True)  # 33 bytes
    
    # 2. Extract public key hash from sk_pqc to compute tr
    pk_pqc = ML_DSA_44.pk_from_sk(sk_pqc)
    tr = ML_DSA_44._h(pk_pqc, 64)
    
    # 3. Format message and compute external mu containing R_bytes
    m_prime = bytes([0]) + bytes([len(ctx)]) + ctx + message
    mu = ML_DSA_44._h(tr + m_prime + R_bytes, 64)
    
    # 4. Run PQC sign internal with this external mu
    rnd = secrets.token_bytes(32)
    sig_pqc = ML_DSA_44._sign_internal(sk_pqc, mu, rnd, external_mu=True)
    
    # Unpack PQC signature to get c_tilde
    c_tilde, z, h = ML_DSA_44._unpack_sig(sig_pqc)
    
    # 5. Treat c_tilde as the Schnorr challenge
    e = int.from_bytes(c_tilde, 'big') % N
    
    # 6. Compute Schnorr signature response s:
    s = (k - e * d_ecc) % N
    s_bytes = s.to_bytes(32, 'big')
    
    # Final Hybrid Signature is: s_bytes (32) + sig_pqc (2420) = 2452 bytes
    return s_bytes + sig_pqc

def h_fswa_verify(pk_pqc, Q_point, message, sig_hybrid, ctx=b""):
    """
    Verify H-FSwA (Silithium) Hybrid Signature:
    Returns True if both Schnorr and ML-DSA components verify successfully.
    """
    if len(sig_hybrid) != 2452:
        return False
        
    s_bytes = sig_hybrid[:32]
    sig_pqc = sig_hybrid[32:]
    
    s = int.from_bytes(s_bytes, 'big')
    if s >= N or s == 0:
        return False
        
    # 1. Unpack PQC signature to get c_tilde
    try:
        c_tilde, z, h = ML_DSA_44._unpack_sig(sig_pqc)
    except Exception:
        return False
        
    # 2. Treat c_tilde as Schnorr challenge integer e
    e = int.from_bytes(c_tilde, 'big') % N
    
    # 3. Reconstruct commitment point R' = s * G + e * Q
    sG = point_mul(s, G)
    eQ = point_mul(e, Q_point)
    R_prime = point_add(sG, eQ)
    if R_prime.is_infinity():
        return False
        
    R_bytes = point_to_bytes(R_prime, compressed=True)
    
    # 4. Compute mu' = H(tr + m_prime + R_bytes)
    tr = ML_DSA_44._h(pk_pqc, 64)
    m_prime = bytes([0]) + bytes([len(ctx)]) + ctx + message
    mu_prime = ML_DSA_44._h(tr + m_prime + R_bytes, 64)
    
    # 5. Run PQC verification using mu_prime and check if c_tilde matches
    try:
        rho, t1 = ML_DSA_44._unpack_pk(pk_pqc)
        if h.sum_hint() > ML_DSA_44.omega:
            return False
        if z.check_norm_bound(ML_DSA_44.gamma_1 - ML_DSA_44.beta):
            return False
            
        A_hat = ML_DSA_44._expand_matrix_from_seed(rho)
        c = ML_DSA_44.R.sample_in_ball(c_tilde, ML_DSA_44.tau)
        
        c = c.to_ntt()
        z = z.to_ntt()
        
        t1 = t1.scale(1 << ML_DSA_44.d)
        t1 = t1.to_ntt()
        
        Az_minus_ct1 = (A_hat @ z) - t1.scale(c)
        Az_minus_ct1 = Az_minus_ct1.from_ntt()
        
        w_prime = h.use_hint(Az_minus_ct1, 2 * ML_DSA_44.gamma_2)
        w_prime_bytes = w_prime.bit_pack_w(ML_DSA_44.gamma_2)
        
        return c_tilde == ML_DSA_44._h(mu_prime + w_prime_bytes, ML_DSA_44.c_tilde_bytes)
    except Exception:
        return False