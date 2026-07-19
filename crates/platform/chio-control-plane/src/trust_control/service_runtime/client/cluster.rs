use super::super::*;

impl TrustControlClient {
    pub(crate) fn admission_request_vote(
        &self,
        request: &AdmissionRequestVoteRequest,
    ) -> Result<AdmissionRequestVoteResponse, CliError> {
        self.post_internal_json(
            INTERNAL_ADMISSION_REQUEST_VOTE_PATH,
            request,
            Some(request.term),
        )
    }

    pub(crate) fn admission_append_entries(
        &self,
        request: &AdmissionAppendEntriesRequest,
    ) -> Result<AdmissionAppendEntriesResponse, CliError> {
        self.post_internal_json(
            INTERNAL_ADMISSION_APPEND_ENTRIES_PATH,
            request,
            Some(request.term),
        )
    }

    pub(crate) fn admission_proposal(
        &self,
        request: &AdmissionProposalRequest,
    ) -> Result<AdmissionConsensusResult, CliError> {
        self.post_internal_json(INTERNAL_ADMISSION_PROPOSAL_PATH, request, None)
    }

    pub(crate) fn admission_snapshot(&self) -> Result<AdmissionConsensusSnapshot, CliError> {
        self.get_internal_json(INTERNAL_ADMISSION_SNAPSHOT_PATH, None)
    }

    pub(crate) fn admission_capture_replica_query(
        &self,
        request: &AdmissionCapturePointQueryRequest,
    ) -> Result<AdmissionCaptureReplicaQueryResponse, CliError> {
        self.post_internal_json(INTERNAL_ADMISSION_CAPTURE_QUERY_PATH, request, None)
    }

    pub(crate) fn invocation_capture_replica_query(
        &self,
        request: &CaptureInvocationPointQueryRequest,
    ) -> Result<CaptureInvocationReplicaQueryResponse, CliError> {
        self.post_internal_json(INTERNAL_INVOCATION_CAPTURE_QUERY_PATH, request, None)
    }

    pub(crate) fn cluster_status(&self) -> Result<ClusterStatusResponse, CliError> {
        self.get_internal_json(INTERNAL_CLUSTER_STATUS_PATH, None)
    }

    pub(crate) fn cluster_snapshot(&self) -> Result<ClusterStateSnapshotResponse, CliError> {
        self.get_internal_json(INTERNAL_CLUSTER_SNAPSHOT_PATH, None)
    }

    pub(crate) fn revocation_deltas(
        &self,
        query: &RevocationDeltaQuery,
    ) -> Result<RevocationDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_REVOCATIONS_DELTA_PATH, query, None)
    }

    pub(crate) fn tool_receipt_deltas(
        &self,
        query: &ReceiptDeltaQuery,
    ) -> Result<ReceiptDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_TOOL_RECEIPTS_DELTA_PATH, query, None)
    }

    pub(crate) fn child_receipt_deltas(
        &self,
        query: &ReceiptDeltaQuery,
    ) -> Result<ReceiptDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_CHILD_RECEIPTS_DELTA_PATH, query, None)
    }

    pub(crate) fn lineage_deltas(
        &self,
        query: &ReceiptDeltaQuery,
    ) -> Result<LineageDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_LINEAGE_DELTA_PATH, query, None)
    }

    pub(crate) fn budget_deltas(
        &self,
        query: &BudgetDeltaQuery,
    ) -> Result<BudgetDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_BUDGETS_DELTA_PATH, query, None)
    }
}
