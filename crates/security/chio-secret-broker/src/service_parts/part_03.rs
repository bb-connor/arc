fn pre_dispatch_authority_projection(
    state: AttemptState,
    outcome: BrokerFailureOutcome,
) -> Result<FailureProjection> {
    let (stage, dispatch_knowledge) = match state {
        AttemptState::Registered if outcome == BrokerFailureOutcome::Denied => (
            BrokerFailureStage::Admission,
            BrokerDispatchKnowledge::NotStarted,
        ),
        AttemptState::Prepared => (
            BrokerFailureStage::Hold,
            BrokerDispatchKnowledge::NotCommitted,
        ),
        AttemptState::Held | AttemptState::Reversed => (
            BrokerFailureStage::Capture,
            BrokerDispatchKnowledge::NotCommitted,
        ),
        AttemptState::Failed if outcome == BrokerFailureOutcome::Denied => (
            BrokerFailureStage::Admission,
            BrokerDispatchKnowledge::NotStarted,
        ),
        AttemptState::Failed if outcome == BrokerFailureOutcome::Reversed => (
            BrokerFailureStage::Capture,
            BrokerDispatchKnowledge::NotCommitted,
        ),
        AttemptState::Registered
        | AttemptState::Captured
        | AttemptState::DispatchCommitted
        | AttemptState::UnknownOutcome
        | AttemptState::Completed
        | AttemptState::Failed => {
            return Err(BrokerError::Conflict(
                "authoritative pre-dispatch terminal conflicts with the local attempt state"
                    .to_string(),
            ));
        }
    };
    Ok(FailureProjection {
        stage,
        outcome,
        dispatch_knowledge,
    })
}

fn failure_state_projection(state: AttemptState, error: &BrokerError) -> Result<FailureProjection> {
    Ok(match state {
        AttemptState::Registered => FailureProjection {
            stage: BrokerFailureStage::Admission,
            outcome: failure_outcome_before_dispatch(error),
            dispatch_knowledge: BrokerDispatchKnowledge::NotStarted,
        },
        AttemptState::Prepared => FailureProjection {
            stage: BrokerFailureStage::Hold,
            outcome: failure_outcome_before_dispatch(error),
            dispatch_knowledge: BrokerDispatchKnowledge::NotCommitted,
        },
        AttemptState::Held => FailureProjection {
            stage: BrokerFailureStage::Capture,
            outcome: failure_outcome_before_dispatch(error),
            dispatch_knowledge: BrokerDispatchKnowledge::NotCommitted,
        },
        AttemptState::Reversed => FailureProjection {
            stage: BrokerFailureStage::Capture,
            outcome: BrokerFailureOutcome::Reversed,
            dispatch_knowledge: BrokerDispatchKnowledge::NotCommitted,
        },
        AttemptState::Failed => FailureProjection {
            stage: BrokerFailureStage::Admission,
            outcome: failure_outcome_before_dispatch(error),
            dispatch_knowledge: BrokerDispatchKnowledge::NotStarted,
        },
        AttemptState::Captured
        | AttemptState::DispatchCommitted
        | AttemptState::UnknownOutcome
        | AttemptState::Completed => {
            return Err(BrokerError::Conflict(
                "post-capture broker attempt cannot emit a failure receipt".to_string(),
            ));
        }
    })
}

fn failure_receipt_id(request: &BrokerExecuteRequest) -> Result<String> {
    failure_receipt_id_for_canonical_request_digest(&failure_receipt_key_digest(request)?)
}

fn failure_receipt_key_digest(request: &BrokerExecuteRequest) -> Result<String> {
    match broker_execute_request_registration_digest(request) {
        Ok(digest) => Ok(digest),
        Err(_) => {
            let canonical = canonical_json_bytes(request).map_err(|error| {
                BrokerError::Invariant(format!("failure terminal request encoding failed: {error}"))
            })?;
            let mut hasher = Sha256::new();
            hasher.update(FAILURE_RECEIPT_REQUEST_DOMAIN);
            hasher.update(canonical);
            Ok(hex::encode(hasher.finalize()))
        }
    }
}

pub(crate) fn failure_receipt_id_for_canonical_request_digest(digest: &str) -> Result<String> {
    validate_digest(digest, "failure terminal canonical request digest")?;
    Ok(format!("broker-failure-terminal-{digest}"))
}

fn attempt_operation_gate_index(digest: &str) -> Result<usize> {
    validate_digest(digest, "attempt operation gate digest")?;
    let prefix = digest.get(..2).ok_or_else(|| {
        BrokerError::Invariant("attempt operation gate digest lost its prefix".to_string())
    })?;
    let prefix = usize::from(u8::from_str_radix(prefix, 16).map_err(|error| {
        BrokerError::Invariant(format!("attempt operation gate prefix is invalid: {error}"))
    })?);
    Ok(prefix % ATTEMPT_OPERATION_GATE_COUNT)
}

fn failure_bound_request_digest(request: &BrokerExecuteRequest) -> Result<String> {
    broker_request_digest(request).or_else(|_| {
        let canonical = canonical_json_bytes(request).map_err(|error| {
            BrokerError::Invariant(format!("failure request fallback encoding failed: {error}"))
        })?;
        Ok(hex::encode(Sha256::digest(canonical)))
    })
}

fn failure_outcome_before_dispatch(error: &BrokerError) -> BrokerFailureOutcome {
    if matches!(error, BrokerError::AuthorizationDenied(_)) {
        BrokerFailureOutcome::Denied
    } else {
        BrokerFailureOutcome::Failed
    }
}

pub fn broker_request_digest(request: &BrokerExecuteRequest) -> Result<String> {
    let canonical = canonical_json_bytes(&request.request)
        .map_err(|error| BrokerError::Invariant(format!("request digest failed: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcOperation {
    RegisterAttempt,
    PrepareDispatch,
    ReleaseAttempt,
    Issue,
    Revoke,
    Status,
    Execute,
    Provision,
    Rotate,
    Disable,
    Delete,
}

impl IpcOperation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RegisterAttempt => "register_attempt",
            Self::PrepareDispatch => "prepare_dispatch",
            Self::ReleaseAttempt => "release_attempt",
            Self::Issue => "issue",
            Self::Revoke => "revoke",
            Self::Status => "status",
            Self::Execute => "execute",
            Self::Provision => "provision",
            Self::Rotate => "rotate",
            Self::Disable => "disable",
            Self::Delete => "delete",
        }
    }
}

pub struct SensitiveIpcBytes(Zeroizing<Vec<u8>>);

#[cfg(test)]
std::thread_local! {
    static BOUNDED_SENSITIVE_DROP_COUNT: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
    static IPC_SENSITIVE_DROP_COUNT: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
pub(crate) fn reset_sensitive_drop_observer() {
    BOUNDED_SENSITIVE_DROP_COUNT.with(|count| count.set(0));
    IPC_SENSITIVE_DROP_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn sensitive_drop_observation() -> (usize, usize) {
    (
        BOUNDED_SENSITIVE_DROP_COUNT.with(|count| count.get()),
        IPC_SENSITIVE_DROP_COUNT.with(|count| count.get()),
    )
}

impl SensitiveIpcBytes {
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<Vec<u8>> for SensitiveIpcBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl From<Zeroizing<Vec<u8>>> for SensitiveIpcBytes {
    fn from(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for SensitiveIpcBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl std::ops::Deref for SensitiveIpcBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl zeroize::ZeroizeOnDrop for SensitiveIpcBytes {}

impl Drop for SensitiveIpcBytes {
    fn drop(&mut self) {
        #[cfg(test)]
        let contained_sensitive_bytes = !self.0.is_empty();
        self.0.zeroize();
        #[cfg(test)]
        if contained_sensitive_bytes {
            IPC_SENSITIVE_DROP_COUNT.with(|count| match count.get().checked_add(1) {
                Some(next) => count.set(next),
                None => panic!("IPC sensitive drop observer overflow"),
            });
        }
    }
}

pub(crate) struct BoundedZeroizingByteArray<const MAXIMUM: usize>(Zeroizing<Vec<u8>>);

impl<const MAXIMUM: usize> BoundedZeroizingByteArray<MAXIMUM> {
    pub(crate) fn copy_from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAXIMUM {
            return Err(BrokerError::InvalidRequest(
                "sensitive byte array is oversized".to_string(),
            ));
        }
        let mut storage = Vec::new();
        storage.try_reserve_exact(MAXIMUM).map_err(|_| {
            BrokerError::Storage("sensitive byte array allocation failed".to_string())
        })?;
        let mut storage = Zeroizing::new(storage);
        storage.extend_from_slice(bytes);
        Ok(Self(storage))
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn into_sensitive(mut self) -> SensitiveIpcBytes {
        SensitiveIpcBytes(std::mem::replace(
            &mut self.0,
            Zeroizing::new(Vec::new()),
        ))
    }
}

impl<const MAXIMUM: usize> std::ops::Deref for BoundedZeroizingByteArray<MAXIMUM> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<const MAXIMUM: usize> zeroize::ZeroizeOnDrop
    for BoundedZeroizingByteArray<MAXIMUM>
{
}

impl<const MAXIMUM: usize> Drop for BoundedZeroizingByteArray<MAXIMUM> {
    fn drop(&mut self) {
        #[cfg(test)]
        let contained_sensitive_bytes = !self.0.is_empty();
        self.0.zeroize();
        #[cfg(test)]
        if contained_sensitive_bytes {
            BOUNDED_SENSITIVE_DROP_COUNT.with(|count| match count.get().checked_add(1) {
                Some(next) => count.set(next),
                None => panic!("bounded sensitive drop observer overflow"),
            });
        }
    }
}

pub(crate) struct BoundedZeroizingString<const MAXIMUM: usize>(Zeroizing<String>);

impl<const MAXIMUM: usize> BoundedZeroizingString<MAXIMUM> {
    fn with_capacity() -> Result<Self> {
        let mut storage = String::new();
        storage.try_reserve_exact(MAXIMUM).map_err(|_| {
            BrokerError::Storage("sensitive JSON string allocation failed".to_string())
        })?;
        Ok(Self(Zeroizing::new(storage)))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn into_string(mut self) -> String {
        std::mem::take(&mut *self.0)
    }

    fn push(&mut self, character: char) -> Result<()> {
        let length = self
            .0
            .len()
            .checked_add(character.len_utf8())
            .ok_or_else(sensitive_json_invalid)?;
        if length > MAXIMUM {
            return Err(sensitive_json_invalid());
        }
        self.0.push(character);
        Ok(())
    }
}

impl<const MAXIMUM: usize> zeroize::ZeroizeOnDrop for BoundedZeroizingString<MAXIMUM> {}

impl<const MAXIMUM: usize> Drop for BoundedZeroizingString<MAXIMUM> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn sensitive_json_invalid() -> BrokerError {
    BrokerError::InvalidRequest("sensitive JSON payload is invalid".to_string())
}

pub(crate) struct SensitiveJsonParser<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> SensitiveJsonParser<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    pub(crate) fn expect_literal(&mut self, expected: &[u8]) -> Result<()> {
        let end = self
            .position
            .checked_add(expected.len())
            .ok_or_else(sensitive_json_invalid)?;
        if self.input.get(self.position..end) != Some(expected) {
            return Err(sensitive_json_invalid());
        }
        self.position = end;
        Ok(())
    }

    pub(crate) fn parse_string<const MAXIMUM: usize>(
        &mut self,
    ) -> Result<BoundedZeroizingString<MAXIMUM>> {
        self.expect_literal(b"\"")?;
        let mut value = BoundedZeroizingString::with_capacity()?;
        loop {
            let byte = *self
                .input
                .get(self.position)
                .ok_or_else(sensitive_json_invalid)?;
            match byte {
                b'"' => {
                    self.position += 1;
                    return Ok(value);
                }
                b'\\' => {
                    let escape = *self
                        .input
                        .get(self.position + 1)
                        .ok_or_else(sensitive_json_invalid)?;
                    match escape {
                        b'"' => value.push('"')?,
                        b'\\' => value.push('\\')?,
                        b'b' => value.push('\u{08}')?,
                        b'f' => value.push('\u{0c}')?,
                        b'n' => value.push('\n')?,
                        b'r' => value.push('\r')?,
                        b't' => value.push('\t')?,
                        b'u' => {
                            let escape_end = self
                                .position
                                .checked_add(6)
                                .ok_or_else(sensitive_json_invalid)?;
                            let digits = self
                                .input
                                .get(self.position + 2..escape_end)
                                .ok_or_else(sensitive_json_invalid)?;
                            let mut code = 0_u8;
                            for digit in digits.iter().copied() {
                                let nibble = match digit {
                                    b'0'..=b'9' => digit - b'0',
                                    b'a'..=b'f' => digit - b'a' + 10,
                                    _ => return Err(sensitive_json_invalid()),
                                };
                                code = code
                                    .checked_mul(16)
                                    .and_then(|value| value.checked_add(nibble))
                                    .ok_or_else(sensitive_json_invalid)?;
                            }
                            if code > 0x1f
                                || matches!(code, 0x08 | 0x09 | 0x0a | 0x0c | 0x0d)
                            {
                                return Err(sensitive_json_invalid());
                            }
                            value.push(char::from(code))?;
                            self.position = escape_end;
                            continue;
                        }
                        _ => return Err(sensitive_json_invalid()),
                    }
                    self.position += 2;
                }
                0x00..=0x1f => return Err(sensitive_json_invalid()),
                0x20..=0x7f => {
                    value.push(char::from(byte))?;
                    self.position += 1;
                }
                _ => {
                    let width = match byte {
                        0xc2..=0xdf => 2,
                        0xe0..=0xef => 3,
                        0xf0..=0xf4 => 4,
                        _ => return Err(sensitive_json_invalid()),
                    };
                    let end = self
                        .position
                        .checked_add(width)
                        .ok_or_else(sensitive_json_invalid)?;
                    let encoded = self
                        .input
                        .get(self.position..end)
                        .ok_or_else(sensitive_json_invalid)?;
                    let encoded =
                        std::str::from_utf8(encoded).map_err(|_| sensitive_json_invalid())?;
                    let mut characters = encoded.chars();
                    let character = characters.next().ok_or_else(sensitive_json_invalid)?;
                    if characters.next().is_some() {
                        return Err(sensitive_json_invalid());
                    }
                    value.push(character)?;
                    self.position = end;
                }
            }
        }
    }

    pub(crate) fn parse_byte_array<const MAXIMUM: usize>(
        &mut self,
    ) -> Result<BoundedZeroizingByteArray<MAXIMUM>> {
        self.expect_literal(b"[")?;
        let mut value = BoundedZeroizingByteArray::copy_from_slice(&[])?;
        if self.input.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(value);
        }
        loop {
            if value.0.len() == MAXIMUM {
                return Err(sensitive_json_invalid());
            }
            let first = *self
                .input
                .get(self.position)
                .ok_or_else(sensitive_json_invalid)?;
            if !first.is_ascii_digit() {
                return Err(sensitive_json_invalid());
            }
            let mut byte = first - b'0';
            self.position += 1;
            if first != b'0' {
                while let Some(digit @ b'0'..=b'9') = self.input.get(self.position).copied() {
                    byte = byte
                        .checked_mul(10)
                        .and_then(|value| value.checked_add(digit - b'0'))
                        .ok_or_else(sensitive_json_invalid)?;
                    self.position += 1;
                }
            } else if self
                .input
                .get(self.position)
                .is_some_and(|byte| byte.is_ascii_digit())
            {
                return Err(sensitive_json_invalid());
            }
            value.0.push(byte);
            match self.input.get(self.position) {
                Some(&b',') => self.position += 1,
                Some(&b']') => {
                    self.position += 1;
                    return Ok(value);
                }
                _ => return Err(sensitive_json_invalid()),
            }
        }
    }

    pub(crate) fn parse_i_json_u64(&mut self) -> Result<u64> {
        const MAXIMUM: u64 = (1 << 53) - 1;
        let first = *self
            .input
            .get(self.position)
            .ok_or_else(sensitive_json_invalid)?;
        if !first.is_ascii_digit() {
            return Err(sensitive_json_invalid());
        }
        let mut value = u64::from(first - b'0');
        self.position += 1;
        if first == b'0' {
            if self
                .input
                .get(self.position)
                .is_some_and(|byte| byte.is_ascii_digit())
            {
                return Err(sensitive_json_invalid());
            }
            return Ok(value);
        }
        while let Some(digit @ b'0'..=b'9') = self.input.get(self.position).copied() {
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(u64::from(digit - b'0')))
                .filter(|value| *value <= MAXIMUM)
                .ok_or_else(sensitive_json_invalid)?;
            self.position += 1;
        }
        Ok(value)
    }

    pub(crate) fn finish(self) -> Result<()> {
        if self.position != self.input.len() {
            return Err(sensitive_json_invalid());
        }
        Ok(())
    }
}

pub struct AuthenticatedIpcRequest {
    pub operation: IpcOperation,
    pub tenant_scope: String,
    pub authorization: SensitiveIpcBytes,
    pub payload: SensitiveIpcBytes,
}

impl zeroize::ZeroizeOnDrop for AuthenticatedIpcRequest {}

pub(crate) fn checked_canonical_length(total: usize, additional: usize) -> Result<usize> {
    total
        .checked_add(additional)
        .ok_or_else(|| BrokerError::InvalidRequest("canonical JSON length overflow".to_string()))
}

pub(crate) fn canonical_json_string_length(value: &str) -> Result<usize> {
    let mut length = 2_usize;
    for character in value.chars() {
        let additional = match character {
            '"' | '\\' | '\u{08}' | '\u{0c}' | '\n' | '\r' | '\t' => 2,
            character if character <= '\u{1f}' => 6,
            character => character.len_utf8(),
        };
        length = checked_canonical_length(length, additional)?;
    }
    Ok(length)
}

pub(crate) fn canonical_json_byte_array_length(bytes: &[u8]) -> Result<usize> {
    let mut length = 2_usize;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if index != 0 {
            length = checked_canonical_length(length, 1)?;
        }
        let digits = if byte >= 100 {
            3
        } else if byte >= 10 {
            2
        } else {
            1
        };
        length = checked_canonical_length(length, digits)?;
    }
    Ok(length)
}

pub(crate) fn canonical_json_u64_length(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 10 {
        value /= 10;
        length += 1;
    }
    length
}

pub(crate) struct ZeroizingCanonicalJsonWriter {
    bytes: Zeroizing<Vec<u8>>,
    exact_length: usize,
    allocation_capacity: usize,
}

impl ZeroizingCanonicalJsonWriter {
    pub(crate) fn with_exact_length(exact_length: usize) -> Result<Self> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(exact_length).map_err(|_| {
            BrokerError::Storage("sensitive canonical JSON allocation failed".to_string())
        })?;
        let allocation_capacity = bytes.capacity();
        Ok(Self {
            bytes: Zeroizing::new(bytes),
            exact_length,
            allocation_capacity,
        })
    }

    fn ensure_remaining(&self, additional: usize) -> Result<()> {
        let Some(length) = self.bytes.len().checked_add(additional) else {
            return Err(BrokerError::Invariant(
                "sensitive canonical JSON length was underestimated".to_string(),
            ));
        };
        if length > self.exact_length {
            return Err(BrokerError::Invariant(
                "sensitive canonical JSON length was underestimated".to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn push(&mut self, byte: u8) -> Result<()> {
        self.ensure_remaining(1)?;
        self.bytes.push(byte);
        Ok(())
    }

    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        self.ensure_remaining(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn write_string(&mut self, value: &str) -> Result<()> {
        self.push(b'"')?;
        for character in value.chars() {
            match character {
                '"' => self.extend_from_slice(b"\\\"")?,
                '\\' => self.extend_from_slice(b"\\\\")?,
                '\u{08}' => self.extend_from_slice(b"\\b")?,
                '\u{0c}' => self.extend_from_slice(b"\\f")?,
                '\n' => self.extend_from_slice(b"\\n")?,
                '\r' => self.extend_from_slice(b"\\r")?,
                '\t' => self.extend_from_slice(b"\\t")?,
                character if character <= '\u{1f}' => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    let byte = character as u8;
                    self.extend_from_slice(b"\\u00")?;
                    self.push(HEX[usize::from(byte >> 4)])?;
                    self.push(HEX[usize::from(byte & 0x0f)])?;
                }
                character if character.is_ascii() => self.push(character as u8)?,
                character => {
                    let mut utf8 = Zeroizing::new([0_u8; 4]);
                    let encoded = character.encode_utf8(&mut *utf8);
                    self.extend_from_slice(encoded.as_bytes())?;
                }
            }
        }
        self.push(b'"')
    }

    pub(crate) fn write_byte_array(&mut self, bytes: &[u8]) -> Result<()> {
        self.push(b'[')?;
        for (index, byte) in bytes.iter().copied().enumerate() {
            if index != 0 {
                self.push(b',')?;
            }
            if byte >= 100 {
                self.push(b'0' + (byte / 100))?;
                self.push(b'0' + ((byte / 10) % 10))?;
            } else if byte >= 10 {
                self.push(b'0' + (byte / 10))?;
            }
            self.push(b'0' + (byte % 10))?;
        }
        self.push(b']')
    }

    pub(crate) fn write_u64(&mut self, value: u64) -> Result<()> {
        let mut divisor = 1_u64;
        while value / divisor >= 10 {
            divisor = divisor.checked_mul(10).ok_or_else(|| {
                BrokerError::Invariant("canonical JSON integer overflow".to_string())
            })?;
        }
        loop {
            let digit = u8::try_from((value / divisor) % 10).map_err(|_| {
                BrokerError::Invariant("canonical JSON digit conversion failed".to_string())
            })?;
            self.push(b'0' + digit)?;
            if divisor == 1 {
                break;
            }
            divisor /= 10;
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<Zeroizing<Vec<u8>>> {
        if self.bytes.len() != self.exact_length
            || self.bytes.capacity() != self.allocation_capacity
        {
            return Err(BrokerError::Invariant(
                "sensitive canonical JSON length or allocation changed".to_string(),
            ));
        }
        Ok(self.bytes)
    }
}

impl zeroize::ZeroizeOnDrop for ZeroizingCanonicalJsonWriter {}

pub fn canonical_ipc_request_bytes(
    request: &AuthenticatedIpcRequest,
) -> Result<Zeroizing<Vec<u8>>> {
    let operation = request.operation.as_str();
    let mut exact_length = b"{\"authorization\":".len();
    exact_length = checked_canonical_length(
        exact_length,
        canonical_json_byte_array_length(request.authorization.as_slice())?,
    )?;
    exact_length = checked_canonical_length(exact_length, b",\"operation\":".len())?;
    exact_length = checked_canonical_length(
        exact_length,
        canonical_json_string_length(operation)?,
    )?;
    exact_length = checked_canonical_length(exact_length, b",\"payload\":".len())?;
    exact_length = checked_canonical_length(
        exact_length,
        canonical_json_byte_array_length(request.payload.as_slice())?,
    )?;
    exact_length = checked_canonical_length(exact_length, b",\"tenantScope\":".len())?;
    exact_length = checked_canonical_length(
        exact_length,
        canonical_json_string_length(&request.tenant_scope)?,
    )?;
    exact_length = checked_canonical_length(exact_length, 1)?;

    let mut encoded = ZeroizingCanonicalJsonWriter::with_exact_length(exact_length)?;
    encoded.extend_from_slice(b"{\"authorization\":")?;
    encoded.write_byte_array(request.authorization.as_slice())?;
    encoded.extend_from_slice(b",\"operation\":")?;
    encoded.write_string(operation)?;
    encoded.extend_from_slice(b",\"payload\":")?;
    encoded.write_byte_array(request.payload.as_slice())?;
    encoded.extend_from_slice(b",\"tenantScope\":")?;
    encoded.write_string(&request.tenant_scope)?;
    encoded.push(b'}')?;
    encoded.finish()
}

fn decode_canonical_ipc_request(frame: &[u8]) -> Result<AuthenticatedIpcRequest> {
    let mut parser = SensitiveJsonParser::new(frame);
    parser.expect_literal(b"{\"authorization\":")?;
    let authorization = parser.parse_byte_array::<65_536>()?;
    parser.expect_literal(b",\"operation\":")?;
    let operation = parser.parse_string::<32>()?;
    let operation = match operation.as_str() {
        "register_attempt" => IpcOperation::RegisterAttempt,
        "prepare_dispatch" => IpcOperation::PrepareDispatch,
        "release_attempt" => IpcOperation::ReleaseAttempt,
        "issue" => IpcOperation::Issue,
        "revoke" => IpcOperation::Revoke,
        "status" => IpcOperation::Status,
        "execute" => IpcOperation::Execute,
        "provision" => IpcOperation::Provision,
        "rotate" => IpcOperation::Rotate,
        "disable" => IpcOperation::Disable,
        "delete" => IpcOperation::Delete,
        _ => return Err(sensitive_json_invalid()),
    };
    parser.expect_literal(b",\"payload\":")?;
    let payload = parser.parse_byte_array::<MAX_WIRE_BYTES>()?;
    parser.expect_literal(b",\"tenantScope\":")?;
    let tenant_scope = parser.parse_string::<512>()?;
    parser.expect_literal(b"}")?;
    parser.finish()?;
    let request = AuthenticatedIpcRequest {
        operation,
        tenant_scope: tenant_scope.into_string(),
        authorization: authorization.into_sensitive(),
        payload: payload.into_sensitive(),
    };
    let canonical = canonical_ipc_request_bytes(&request)?;
    if canonical.as_slice() != frame {
        return Err(BrokerError::InvalidRequest(
            "IPC request is not canonical JSON".to_string(),
        ));
    }
    Ok(request)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IpcResponse {
    pub operation: IpcOperation,
    pub accepted: bool,
    pub response: Vec<u8>,
    pub error_code: Option<String>,
}

pub trait BrokerIpcHandler: Send + Sync {
    fn register_attempt(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn prepare_dispatch(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn release_attempt(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn issue(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn revoke(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn status(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn execute(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn provision(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn rotate(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn disable(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
    fn delete(&self, request: AuthenticatedIpcRequest) -> Result<IpcResponse>;
}

include!("ipc_deadline.inc");

#[cfg(unix)]
#[derive(Debug)]
enum BrokerIpcServeFailure {
    Client(BrokerError),
    Internal(BrokerError),
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BrokerSocketIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
pub struct UnixBrokerEndpoint {
    listener: UnixListener,
    handler: Arc<dyn BrokerIpcHandler>,
    authorized_client_uid: u32,
    deadlines: BrokerIpcDeadlines,
    socket_path: PathBuf,
    socket_identity: BrokerSocketIdentity,
    trusted_service_uid: u32,
    _lifecycle_lock: File,
}

#[cfg(unix)]
impl UnixBrokerEndpoint {
    pub fn bind(
        path: impl AsRef<Path>,
        handler: Arc<dyn BrokerIpcHandler>,
        trusted_service_uid: u32,
        authorized_client_uid: u32,
    ) -> Result<Self> {
        Self::bind_with_deadlines(
            path,
            handler,
            trusted_service_uid,
            authorized_client_uid,
            BrokerIpcDeadlines::default(),
        )
    }

    pub fn bind_with_deadlines(
        path: impl AsRef<Path>,
        handler: Arc<dyn BrokerIpcHandler>,
        trusted_service_uid: u32,
        authorized_client_uid: u32,
        deadlines: BrokerIpcDeadlines,
    ) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(BrokerError::AuthorityUnavailable(
                "authenticated broker IPC peer credentials require Linux".to_string(),
            ));
        }
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(BrokerError::InvalidRequest(
                "broker IPC path must be absolute".to_string(),
            ));
        }
        let lifecycle_lock = acquire_broker_socket_lifecycle_lock(path, trusted_service_uid)?;
        if path.exists() {
            return Err(BrokerError::Storage(
                "broker IPC path already exists".to_string(),
            ));
        }
        let listener = UnixListener::bind(path)
            .map_err(|error| BrokerError::Storage(format!("IPC bind failed: {error}")))?;
        let mut provisional_cleanup = ProvisionalBrokerSocketCleanup::new(path)?;
        fs_permissions(path, 0o600)?;
        let socket_identity = validate_broker_socket_identity(path, trusted_service_uid)?;
        if socket_identity != provisional_cleanup.identity() {
            return Err(BrokerError::Custody(
                "broker IPC socket identity changed during bind".to_string(),
            ));
        }
        let endpoint = Self {
            listener,
            handler,
            authorized_client_uid,
            deadlines,
            socket_path: path.to_path_buf(),
            socket_identity,
            trusted_service_uid,
            _lifecycle_lock: lifecycle_lock,
        };
        provisional_cleanup.disarm();
        Ok(endpoint)
    }

    /// Serve one accepted connection under the v2 deadline contract.
    ///
    /// Peer-controlled faults return a typed nonfatal outcome. Service faults
    /// return `Err` so daemon supervision observes the failure.
    pub fn serve_one(&self) -> Result<BrokerIpcServeOutcome> {
        let (stream, _) = self
            .listener
            .accept()
            .map_err(|error| BrokerError::Storage(format!("IPC accept failed: {error}")))?;
        match self.serve_stream(stream) {
            Ok(()) => Ok(BrokerIpcServeOutcome::ResponseWritten),
            Err(BrokerIpcServeFailure::Client(error)) => {
                Ok(BrokerIpcServeOutcome::ClientFault {
                    diagnostic_code: error.diagnostic_code(),
                })
            }
            Err(BrokerIpcServeFailure::Internal(error)) => Err(error),
        }
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.listener.set_nonblocking(nonblocking).map_err(|error| {
            BrokerError::Storage(format!("IPC listener mode failed: {error}"))
        })
    }

    /// Serve at most one connection from a nonblocking listener.
    pub fn try_serve_one(&self) -> Result<Option<BrokerIpcServeOutcome>> {
        let stream = match self.listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => {
                return Err(BrokerError::Storage(format!(
                    "IPC nonblocking accept failed: {error}"
                )))
            }
        };
        let outcome = match self.serve_stream(stream) {
            Ok(()) => BrokerIpcServeOutcome::ResponseWritten,
            Err(BrokerIpcServeFailure::Client(error)) => BrokerIpcServeOutcome::ClientFault {
                diagnostic_code: error.diagnostic_code(),
            },
            Err(BrokerIpcServeFailure::Internal(error)) => return Err(error),
        };
        Ok(Some(outcome))
    }

    fn serve_stream(
        &self,
        stream: std::os::unix::net::UnixStream,
    ) -> std::result::Result<(), BrokerIpcServeFailure> {
        let mut stream = BrokerIpcDeadlineIo::new(stream, self.deadlines).map_err(|error| {
            BrokerIpcServeFailure::Internal(BrokerError::Storage(format!(
                "IPC stream deadline setup failed: {error}"
            )))
        })?;
        if let Err(error) = validate_broker_peer_uid(stream.stream(), self.authorized_client_uid) {
            return Err(if matches!(&error, BrokerError::AuthorizationDenied(_)) {
                BrokerIpcServeFailure::Client(error)
            } else {
                BrokerIpcServeFailure::Internal(error)
            });
        }
        let frame = match read_bounded_sensitive_frame(&mut stream) {
            Ok(frame) => frame,
            Err(_error) if stream.read_deadline_setup_failed() => {
                return Err(BrokerIpcServeFailure::Internal(BrokerError::Storage(
                    "IPC read deadline maintenance failed".to_string(),
                )))
            }
            Err(error) => return Err(BrokerIpcServeFailure::Client(error)),
        };
        let request = decode_canonical_ipc_request(frame.as_slice())
            .map_err(BrokerIpcServeFailure::Client)?;
        if request.authorization.is_empty() || request.authorization.len() > 65_536 {
            return Err(BrokerIpcServeFailure::Client(BrokerError::AuthorizationDenied(
                "IPC operation authorization is missing or oversized".to_string(),
            )));
        }
        validate_identifier(&request.tenant_scope, "IPC tenant scope", 512)
            .map_err(BrokerIpcServeFailure::Client)?;
        if request.payload.len() > MAX_WIRE_BYTES {
            return Err(BrokerIpcServeFailure::Client(BrokerError::InvalidRequest(
                "IPC operation payload is oversized".to_string(),
            )));
        }
        let operation = request.operation;
        let handled = match operation {
            IpcOperation::RegisterAttempt => self.handler.register_attempt(request),
            IpcOperation::PrepareDispatch => self.handler.prepare_dispatch(request),
            IpcOperation::ReleaseAttempt => self.handler.release_attempt(request),
            IpcOperation::Issue => self.handler.issue(request),
            IpcOperation::Revoke => self.handler.revoke(request),
            IpcOperation::Status => self.handler.status(request),
            IpcOperation::Execute => self.handler.execute(request),
            IpcOperation::Provision => self.handler.provision(request),
            IpcOperation::Rotate => self.handler.rotate(request),
            IpcOperation::Disable => self.handler.disable(request),
            IpcOperation::Delete => self.handler.delete(request),
        };
        let response = classify_broker_ipc_handler_result(operation, handled)?;
        validate_broker_ipc_response_envelope(operation, &response)
            .map_err(BrokerIpcServeFailure::Internal)?;
        let encoded = canonical_json_bytes(&response)
            .map_err(|error| BrokerError::Invariant(format!("IPC response failed: {error}")))
            .map_err(BrokerIpcServeFailure::Internal)?;
        write_broker_ipc_response(&mut stream, &encoded)
    }
}

include!("ipc_response.inc");

#[cfg(target_os = "linux")]
fn validate_broker_peer_uid(
    stream: &std::os::unix::net::UnixStream,
    authorized_client_uid: u32,
) -> Result<()> {
    let credentials = rustix::net::sockopt::socket_peercred(stream).map_err(|error| {
        BrokerError::Storage(format!("broker IPC client credential lookup failed: {error}"))
    })?;
    if credentials.uid.as_raw() != authorized_client_uid {
        return Err(BrokerError::AuthorizationDenied(
            "broker IPC client UID is not authorized".to_string(),
        ));
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn validate_broker_peer_uid(
    _stream: &std::os::unix::net::UnixStream,
    _authorized_client_uid: u32,
) -> Result<()> {
    Err(BrokerError::AuthorityUnavailable(
        "kernel-observed broker IPC client credentials require Linux".to_string(),
    ))
}

include!("ipc_lifecycle.inc");

fn read_bounded_sensitive_frame(reader: &mut impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).map_err(|error| {
        BrokerError::InvalidRequest(format!("IPC frame prefix failed: {error}"))
    })?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| BrokerError::InvalidRequest("IPC frame length overflow".to_string()))?;
    if length == 0 || length > MAX_WIRE_BYTES {
        return Err(BrokerError::InvalidRequest(
            "IPC frame is empty or oversized".to_string(),
        ));
    }
    let mut frame = Zeroizing::new(vec![0_u8; length]);
    read_sensitive_frame_body(reader, &mut frame)?;
    Ok(frame)
}

fn read_sensitive_frame_body(
    reader: &mut impl Read,
    frame: &mut Zeroizing<Vec<u8>>,
) -> Result<()> {
    if let Err(error) = reader.read_exact(frame.as_mut_slice()) {
        frame.zeroize();
        return Err(BrokerError::InvalidRequest(format!(
            "IPC frame body failed: {error}"
        )));
    }
    Ok(())
}

pub fn read_bounded_frame(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).map_err(|error| {
        BrokerError::InvalidRequest(format!("IPC frame prefix failed: {error}"))
    })?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| BrokerError::InvalidRequest("IPC frame length overflow".to_string()))?;
    if length == 0 || length > MAX_WIRE_BYTES {
        return Err(BrokerError::InvalidRequest(
            "IPC frame is empty or oversized".to_string(),
        ));
    }
    let mut frame = vec![0_u8; length];
    reader
        .read_exact(&mut frame)
        .map_err(|error| BrokerError::InvalidRequest(format!("IPC frame body failed: {error}")))?;
    Ok(frame)
}

pub fn write_bounded_frame(writer: &mut impl Write, frame: &[u8]) -> Result<()> {
    if frame.is_empty() || frame.len() > MAX_WIRE_BYTES {
        return Err(BrokerError::InvalidRequest(
            "IPC response frame is empty or oversized".to_string(),
        ));
    }
    let length = u32::try_from(frame.len())
        .map_err(|_| BrokerError::InvalidRequest("IPC response length overflow".to_string()))?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(frame))
        .and_then(|()| writer.flush())
        .map_err(|error| BrokerError::Storage(format!("IPC response write failed: {error}")))
}

#[cfg(unix)]
fn fs_permissions(path: &Path, mode: u32) -> Result<()> {
    let permissions = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, permissions)
        .map_err(|error| BrokerError::Storage(format!("IPC permissions failed: {error}")))
}

#[cfg(test)]
mod tests {
    include!("tests_01.rs");
    include!("tests_02.rs");
    include!("tests_03.rs");
}
