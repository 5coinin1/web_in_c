"""CH3-A: Z3 bitvector encoding of server read-buffer append (server.c:76-83).

Source analysed (baseline commit 1be2ade):
    int space = (int)sizeof(client->read_buf) - client->read_len;   // L76
    if (n > space) { break; }                                       // L77-79
    memcpy(client->read_buf + client->read_len, recv_buf, n);       // L81
    client->read_len += n;                                          // L82
    client->read_buf[client->read_len] = '\\0';                     // L83

Bug: when read_len + n == 8192, the guard passes (n <= space) but the NUL
terminator write at index 8192 is one past the end of read_buf[8192].

This module exposes pure-function builders so the runner can call them,
inspect solver results and export SMT-LIB2.
"""

import z3

# ── ABI constants (measured from real GCC 16.2.0 / MSYS2 MinGW-w64) ─────────
CAPACITY  = 8192        # sizeof(client->read_buf) = MAX_MSG_LEN * 2
RECV_CAP  = 4096        # sizeof(recv_buf) in client_thread
BV_WIDTH  = 32          # C int is 4 bytes on this ABI


# ── helpers ──────────────────────────────────────────────────────────────────

def _bv(name: str) -> z3.BitVecRef:
    return z3.BitVec(name, BV_WIDTH)

def _const(val: int) -> z3.BitVecNumRef:
    return z3.BitVecVal(val, BV_WIDTH)

def _sle(a, b):
    """Signed less-than-or-equal."""
    return a <= b            # z3 BitVec.__le__ is signed by default... NO!
    # Actually z3 BitVec comparison operators are UNSIGNED by default.
    # We must be explicit.

def slt(a, b):
    return z3.BV2Int(a, is_signed=True) < z3.BV2Int(b, is_signed=True)

def sle(a, b):
    return z3.BV2Int(a, is_signed=True) <= z3.BV2Int(b, is_signed=True)

def sgt(a, b):
    return z3.BV2Int(a, is_signed=True) > z3.BV2Int(b, is_signed=True)

def sge(a, b):
    return z3.BV2Int(a, is_signed=True) >= z3.BV2Int(b, is_signed=True)


# ── domain constraints ──────────────────────────────────────────────────────

def domain(L, N, capacity=CAPACITY, recv_cap=RECV_CAP):
    """Preconditions for a single append step.

    L = read_len before append, N = bytes from recv() (already > 0).
    Both are signed int (BV32).
    """
    C = _const(capacity)
    return z3.And(
        sge(L, _const(0)),              # 0 <= L
        slt(L, C),                      # L < capacity
        sgt(N, _const(0)),              # 0 < N   (recv returned > 0)
        sle(N, _const(recv_cap)),       # N <= recv buffer size (4096)
    )


def guard_before(L, N, capacity=CAPACITY):
    """Original guard: n <= space  where space = capacity - read_len."""
    C = _const(capacity)
    S = C - L                           # space (BV32 subtract)
    return sle(N, S)                    # N <= S (signed)


def guard_fixed(L, N, capacity=CAPACITY):
    """Fixed guard: n <= capacity - 1 - read_len (reserves 1 byte for NUL)."""
    C = _const(capacity)
    return z3.And(
        sge(L, _const(0)),
        slt(L, C),
        sgt(N, _const(0)),
        sle(N, C - _const(1) - L),     # N <= C - 1 - L
    )


def safety(L, N, capacity=CAPACITY):
    """After the append, the terminator index must be strictly < capacity."""
    C = _const(capacity)
    L_next = L + N
    return z3.And(
        sge(L_next, _const(0)),         # no signed underflow
        slt(L_next, C),                 # terminator index < capacity
    )


def no_signed_overflow(L, N, capacity=CAPACITY):
    """Check that C-L and L+N do not overflow signed int32.

    We widen to 33 bits and compare: if the 33-bit result differs from
    the 32-bit result, there is overflow.
    """
    Le = z3.SignExt(1, L)
    Ne = z3.SignExt(1, N)
    Ce = z3.SignExt(1, _const(capacity))

    sub_32 = _const(capacity) - L
    sub_33 = Ce - Le
    add_32 = L + N
    add_33 = Le + Ne

    return z3.And(
        z3.SignExt(1, sub_32) == sub_33,
        z3.SignExt(1, add_32) == add_33,
    )


# ── top-level queries ────────────────────────────────────────────────────────

def query_before_violation(capacity=CAPACITY, recv_cap=RECV_CAP):
    """SAT = there exists (L,N) accepted by original guard that violates safety."""
    L, N = _bv('L'), _bv('N')
    return z3.And(
        domain(L, N, capacity, recv_cap),
        guard_before(L, N, capacity),
        no_signed_overflow(L, N, capacity),
        z3.Not(safety(L, N, capacity)),
    )

def query_fixed_violation(capacity=CAPACITY, recv_cap=RECV_CAP):
    """UNSAT expected = fixed guard never lets a bad terminator through."""
    L, N = _bv('L'), _bv('N')
    return z3.And(
        domain(L, N, capacity, recv_cap),
        guard_fixed(L, N, capacity),
        no_signed_overflow(L, N, capacity),
        z3.Not(safety(L, N, capacity)),
    )

def query_non_vacuity(capacity=CAPACITY, recv_cap=RECV_CAP):
    """SAT expected = fixed guard still accepts some input that fills to max safe index."""
    L, N = _bv('L'), _bv('N')
    C = _const(capacity)
    L_next = L + N
    return z3.And(
        domain(L, N, capacity, recv_cap),
        guard_fixed(L, N, capacity),
        L_next == C - _const(1),        # fills to index capacity-1 (8191)
    )

def query_signed_overflow(capacity=CAPACITY, recv_cap=RECV_CAP):
    """UNSAT expected = no signed overflow in the domain."""
    L, N = _bv('L'), _bv('N')
    return z3.And(
        domain(L, N, capacity, recv_cap),
        z3.Not(no_signed_overflow(L, N, capacity)),
    )


# ── inductive invariant ─────────────────────────────────────────────────────

def invariant_base(capacity=CAPACITY):
    """Base case: I(0) holds.  I(L) = 0 <= L < capacity."""
    L = _const(0)
    C = _const(capacity)
    I = z3.And(sge(L, _const(0)), slt(L, C))
    return z3.Not(I)   # UNSAT = base holds

def invariant_step(capacity=CAPACITY, recv_cap=RECV_CAP):
    """Step: if I(L) and fixed guard accepts N, then I(L+N).
    Also if rejected or connection closed, I is trivially preserved (no mutation).
    UNSAT = step holds.
    """
    L, N = _bv('L'), _bv('N')
    C = _const(capacity)
    I_pre = z3.And(sge(L, _const(0)), slt(L, C))
    L_next = L + N
    I_post = z3.And(sge(L_next, _const(0)), slt(L_next, C))
    return z3.And(
        I_pre,
        domain(L, N, capacity, recv_cap),
        guard_fixed(L, N, capacity),
        no_signed_overflow(L, N, capacity),
        z3.Not(I_post),
    )


# ── BMC: multiple recv rounds from empty buffer ─────────────────────────────

def bmc_query(k: int, use_fixed: bool, capacity=CAPACITY, recv_cap=RECV_CAP):
    """Unroll k recv steps from L_0 = 0.  Check if any step has bad terminator.

    Returns (formula, variable list).
    """
    C = _const(capacity)
    clauses = []
    bad_clauses = []
    L_prev = _const(0)
    variables = []

    for i in range(k):
        N_i = _bv(f'N_{i}')
        variables.append(N_i)
        L_next = L_prev + N_i

        clauses.append(domain(L_prev, N_i, capacity, recv_cap))
        clauses.append(no_signed_overflow(L_prev, N_i, capacity))

        if use_fixed:
            clauses.append(guard_fixed(L_prev, N_i, capacity))
        else:
            clauses.append(guard_before(L_prev, N_i, capacity))

        # bad: terminator >= capacity
        bad_clauses.append(z3.Not(safety(L_prev, N_i, capacity)))

        L_prev = L_next

    # At least one step must violate safety
    formula = z3.And(*clauses, z3.Or(*bad_clauses))
    return formula, variables


# ── solver helper ────────────────────────────────────────────────────────────

def solve(formula, label="query"):
    """Run Z3 on the formula. Returns (result_str, model_or_None)."""
    s = z3.Solver()
    s.add(formula)
    result = s.check()
    if result == z3.sat:
        m = s.model()
        return "SAT", m
    elif result == z3.unsat:
        return "UNSAT", None
    else:
        return "UNKNOWN", None
