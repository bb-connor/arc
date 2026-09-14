"""Recompute W0 from custody; sign only the supported artifact assurance."""
import artifacts as p
import review


def decide(agreement, pins, allocation, submission, store, key):
    body = p.verify_agreement(agreement, pins)
    p.require(key.public_key().public_bytes_raw().hex() == body['verifierKey'], "wrong verifier key")
    p.require(store.pin == body['custodianKey'], "wrong custody authority")
    sent = p.verify_submission(submission, body, allocation)
    p.check_implementation()
    source = store.get(sent['inputSha256'])
    output = store.get(sent['outputSha256'])
    p.require(store.get(p.digest(sent['custody'])) == p.canonical(sent['custody']), "custody receipt unavailable")
    p.load(source, p.MAX_OBJECT)
    expected = p.output(review.observations(source.decode('utf-8')))
    # Only a retrieved output failing the predicate is a signed rejection.
    # Authority, checker or custody failures above issue no financial decision.
    try:
        accepted = p.canonical(p.verify_output(output)) == p.canonical(expected)
    except p.ProtocolError:
        accepted = False
    store.bind_submission(allocation, submission)
    result = p.sign(p.decision_body(body, submission, accepted), key)
    p.verify_decision(result, body, submission)
    return store.record_decision(allocation, submission, result)


def authorize(agreement, pins, submission, observed, store, key):
    """Bind trusted private-chain reads; these are not a public finality proof."""
    body = p.verify_agreement(agreement, pins)
    p.fields(observed, ('allocationId', 'agreementDigest', 'commitment', 'state', 'chainTime', 'rail', 'deadlines'))
    p.verify_submission(submission, body, observed['allocationId'])
    p.require(observed['agreementDigest'] == '0x' + p.digest(body)
              and observed['commitment'] == '0x' + p.digest(submission)
              and observed['state'] == 'Submitted', 'observed claim differs from submitted work')
    p.require(p.canonical(observed['rail']) == p.canonical(body['rail'])
              and p.canonical(observed['deadlines']) == p.canonical(body['deadlines']), 'observed settlement terms differ')
    p.integer(observed['chainTime'], body['deadlines']['challengeUntil'] + 1, body['deadlines']['resolveBy'])
    decision = decide(agreement, pins, observed['allocationId'], submission, store, key)
    checked = p.verify_decision(decision, body, submission)
    decision_digest = '0x' + p.digest(checked)
    authorization = {'allocationId': observed['allocationId'], 'agreementDigest': observed['agreementDigest'],
                     'commitment': checked['commitment'], 'decisionDigest': decision_digest,
                     'accepted': checked['accepted'], 'beneficiary': body['rail']['beneficiary'],
                     'token': body['rail']['token'], 'amount': body['rail']['amount']}
    return {'decision': decision, 'decisionDigest': decision_digest, 'authorization': authorization,
            'domain': {'name': 'ChioWorkClaimEscrow', 'version': '1', 'chainId': body['rail']['chainId'],
                       'verifyingContract': body['rail']['escrow']}}
