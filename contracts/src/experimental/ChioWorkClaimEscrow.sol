// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "../interfaces/IERC20.sol";

/// @notice Experimental fixed-price work claims. Not a qualified deployment.
/// @dev The pinned verifier is trusted for predicate decisions and custody.
/// Agreement and decision digests commit off-chain artifacts; this contract
/// does not parse those artifacts, run a checker or prove chain finality.
contract ChioWorkClaimEscrow {
    uint256 public constant MAX_UNITS = 9007199254740991;
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant DECISION_TYPEHASH = keccak256(
        "ChioWorkDecision(bytes32 allocationId,bytes32 agreementDigest,bytes32 commitment,bytes32 decisionDigest,bool accepted,address beneficiary,address token,uint256 amount)"
    );
    uint256 private constant HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    enum State { Missing, Funded, Submitted, Payable, Paid, Rejected, TimedOut, Refunded }

    struct Terms {
        bytes32 agreementDigest;
        address payer;
        address beneficiary;
        address verifier;
        address token;
        uint256 amount;
        uint64 submitBy;
        uint64 challengeUntil;
        uint64 resolveBy;
        uint64 refundAfter;
    }

    struct Work {
        Terms terms;
        State state;
        bytes32 commitment;
        bytes32 decisionDigest;
        bool accepted;
        uint256 paid;
        uint256 refunded;
    }

    error InvalidTerms();
    error UnauthorizedCaller();
    error AgreementAlreadyFunded();
    error WorkNotFound();
    error WrongState();
    error InvalidCommitment();
    error ConflictingClaim();
    error SubmissionExpired();
    error InvalidDecision();
    error InvalidSignature();
    error ConflictingDecision();
    error OutsideResolutionWindow();
    error RefundNotDue();
    error TransferFailed();
    error NotAdmin();
    error TokenNotAllowed();
    error VerifierNotAllowed();
    error Paused();
    error ReentrantCall();

    event Funded(bytes32 indexed allocationId, bytes32 indexed agreementDigest, address indexed payer);
    event ClaimSubmitted(bytes32 indexed allocationId, bytes32 commitment);
    event DecisionRecorded(bytes32 indexed allocationId, bytes32 decisionDigest, bool accepted);
    event TimedOut(bytes32 indexed allocationId);
    event Paid(bytes32 indexed allocationId, address indexed beneficiary, uint256 amount);
    event Refunded(bytes32 indexed allocationId, address indexed payer, uint256 amount);
    event FundingPaused(bool paused);
    event TokenAllowed(address indexed token, bool allowed);
    event VerifierAllowed(address indexed verifier, bool allowed);

    address public immutable admin;
    bool public paused;
    mapping(address => bool) public tokenAllowed;
    mapping(address => bool) public verifierAllowed;
    // A different payer must not occupy a public digest and deny its actual buyer.
    mapping(address => mapping(bytes32 => bytes32)) public allocationForAgreement;
    mapping(bytes32 => Work) private works;
    bool private entered;

    constructor(address admin_) {
        if (admin_ == address(0)) revert InvalidTerms();
        admin = admin_;
    }

    modifier nonReentrant() {
        if (entered) revert ReentrantCall();
        entered = true;
        _;
        entered = false;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    // Configuration gates new funding only. Existing terms and claims are immutable.
    function setPaused(bool value) external onlyAdmin {
        paused = value;
        emit FundingPaused(value);
    }

    function setTokenAllowed(address token, bool allowed) external onlyAdmin {
        if (token == address(0) || (allowed && token.code.length == 0)) revert InvalidTerms();
        tokenAllowed[token] = allowed;
        emit TokenAllowed(token, allowed);
    }

    function setVerifierAllowed(address verifier, bool allowed) external onlyAdmin {
        if (verifier == address(0)) revert InvalidTerms();
        verifierAllowed[verifier] = allowed;
        emit VerifierAllowed(verifier, allowed);
    }

    function deriveAllocationId(Terms calldata terms) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), terms));
    }

    function fund(Terms calldata terms) external nonReentrant returns (bytes32 allocationId) {
        if (paused) revert Paused();
        if (
            terms.agreementDigest == bytes32(0) || terms.payer == address(0)
                || terms.beneficiary == address(0) || terms.verifier == address(0)
                || terms.token == address(0) || terms.payer == terms.beneficiary
                || terms.payer == address(this) || terms.beneficiary == address(this)
                || terms.verifier == terms.payer || terms.verifier == terms.beneficiary
                || terms.verifier == address(this) || terms.amount == 0 || terms.amount > MAX_UNITS
                || terms.submitBy <= block.timestamp || terms.challengeUntil <= terms.submitBy
                || terms.resolveBy <= terms.challengeUntil || terms.refundAfter <= terms.resolveBy
                || terms.refundAfter > MAX_UNITS
        ) revert InvalidTerms();
        if (msg.sender != terms.payer) revert UnauthorizedCaller();
        if (!tokenAllowed[terms.token]) revert TokenNotAllowed();
        if (!verifierAllowed[terms.verifier]) revert VerifierNotAllowed();
        if (allocationForAgreement[terms.payer][terms.agreementDigest] != bytes32(0)) revert AgreementAlreadyFunded();
        allocationId = deriveAllocationId(terms);
        Work storage work = works[allocationId];
        work.terms = terms;
        work.state = State.Funded;
        allocationForAgreement[terms.payer][terms.agreementDigest] = allocationId;
        _move(terms.token, terms.payer, address(this), terms.amount, true);
        emit Funded(allocationId, terms.agreementDigest, terms.payer);
    }

    function submitClaim(bytes32 allocationId, bytes32 commitment) external nonReentrant {
        Work storage work = _work(allocationId);
        if (msg.sender != work.terms.beneficiary) revert UnauthorizedCaller();
        if (commitment == bytes32(0)) revert InvalidCommitment();
        if (work.commitment != bytes32(0)) {
            if (work.commitment != commitment) revert ConflictingClaim();
            return; // Exact acknowledgment never creates another submission interval.
        }
        if (work.state != State.Funded) revert WrongState();
        if (block.timestamp > work.terms.submitBy) revert SubmissionExpired();
        work.commitment = commitment;
        work.state = State.Submitted;
        emit ClaimSubmitted(allocationId, commitment);
    }

    /// @dev Any courier may record the pinned verifier's exact decision.
    function recordDecision(bytes32 allocationId, bytes32 decisionDigest, bool accepted, bytes calldata signature)
        external nonReentrant
    {
        Work storage work = _work(allocationId);
        if (decisionDigest == bytes32(0)) revert InvalidDecision();
        if (work.decisionDigest == bytes32(0)) {
            if (work.state != State.Submitted) revert WrongState();
            if (block.timestamp <= work.terms.challengeUntil || block.timestamp > work.terms.resolveBy) {
                revert OutsideResolutionWindow();
            }
        }
        _verify(_decisionHash(work, allocationId, decisionDigest, accepted), work.terms.verifier, signature);
        if (work.decisionDigest != bytes32(0)) {
            if (work.decisionDigest != decisionDigest || work.accepted != accepted) revert ConflictingDecision();
            return;
        }
        work.decisionDigest = decisionDigest;
        work.accepted = accepted;
        work.state = accepted ? State.Payable : State.Rejected;
        emit DecisionRecorded(allocationId, decisionDigest, accepted);
    }

    function expire(bytes32 allocationId) external nonReentrant {
        _expire(_work(allocationId), allocationId);
    }

    function withdrawPayment(bytes32 allocationId) external nonReentrant {
        Work storage work = _work(allocationId);
        if (msg.sender != work.terms.beneficiary) revert UnauthorizedCaller();
        if (work.state != State.Payable) revert WrongState();
        // Earned withdrawals have no deadline, registry refresh or admin-pause gate.
        work.state = State.Paid;
        work.paid = work.terms.amount;
        _move(work.terms.token, address(this), work.terms.beneficiary, work.terms.amount, false);
        emit Paid(allocationId, work.terms.beneficiary, work.terms.amount);
    }

    function withdrawRefund(bytes32 allocationId) external nonReentrant {
        Work storage work = _work(allocationId);
        if (work.state != State.Rejected && work.state != State.TimedOut) _expire(work, allocationId);
        work.state = State.Refunded;
        work.refunded = work.terms.amount;
        _move(work.terms.token, address(this), work.terms.payer, work.terms.amount, false);
        emit Refunded(allocationId, work.terms.payer, work.terms.amount);
    }

    function getWork(bytes32 allocationId) external view returns (Work memory) {
        return _work(allocationId);
    }

    function _work(bytes32 allocationId) private view returns (Work storage work) {
        work = works[allocationId];
        if (work.state == State.Missing) revert WorkNotFound();
    }

    function _expire(Work storage work, bytes32 allocationId) private {
        if (work.state == State.TimedOut) return;
        if (work.state != State.Funded && work.state != State.Submitted) revert WrongState();
        if (block.timestamp <= work.terms.refundAfter) revert RefundNotDue();
        work.state = State.TimedOut;
        emit TimedOut(allocationId);
    }

    function _decisionHash(Work storage work, bytes32 allocationId, bytes32 decisionDigest, bool accepted)
        private view returns (bytes32)
    {
        bytes32 domain = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("ChioWorkClaimEscrow"),
            keccak256("1"), block.chainid, address(this)));
        bytes32 body = keccak256(abi.encode(DECISION_TYPEHASH, allocationId, work.terms.agreementDigest,
            work.commitment, decisionDigest, accepted, work.terms.beneficiary, work.terms.token, work.terms.amount));
        return keccak256(abi.encodePacked("\x19\x01", domain, body));
    }

    function _verify(bytes32 authorizationHash, address verifier, bytes calldata signature) private pure {
        if (signature.length != 65) revert InvalidSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if ((v != 27 && v != 28) || uint256(s) > HALF_ORDER || r == bytes32(0) || s == bytes32(0)) {
            revert InvalidSignature();
        }
        address signer = ecrecover(authorizationHash, v, r, s);
        if (signer == address(0) || signer != verifier) revert InvalidSignature();
    }

    // Trusted, allowlisted tokens must debit and credit exactly the agreed units.
    // Checking both sides also prevents an outgoing extra debit consuming another claim's backing.
    function _move(address token, address from, address to, uint256 amount, bool deposit) private {
        uint256 fromBefore = IERC20(token).balanceOf(from);
        uint256 toBefore = IERC20(token).balanceOf(to);
        bytes memory callData = deposit
            ? abi.encodeCall(IERC20.transferFrom, (from, to, amount))
            : abi.encodeCall(IERC20.transfer, (to, amount));
        (bool ok, bytes memory returned) = token.call(callData);
        if (!ok || (returned.length != 0 && (returned.length != 32 || abi.decode(returned, (uint256)) != 1))) {
            revert TransferFailed();
        }
        uint256 fromAfter = IERC20(token).balanceOf(from);
        uint256 toAfter = IERC20(token).balanceOf(to);
        if (fromAfter > fromBefore || fromBefore - fromAfter != amount
                || toAfter < toBefore || toAfter - toBefore != amount) revert TransferFailed();
    }
}
