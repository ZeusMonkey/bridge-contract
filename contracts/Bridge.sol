// SPDX-License-Identifier: MIT

pragma solidity 0.8.9;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/security/Pausable.sol";
import "./utils/AccessControl.sol";
import "./interfaces/IBridgeHandler.sol";

/**
    @title Facilitates deposits, creation and voting of deposit proposals, and deposit executions.
    @author Ryuhei Matsuda
 */
contract Bridge is Pausable, AccessControl {
    // Limit relayers number because proposal can fit only so much votes
    uint256 public constant MAX_RELAYERS = 128;

    address public handlerAddress;

    uint8 public relayerThreshold;
    uint128 public fee;
    uint40 public expiry;

    enum ProposalStatus {
        Inactive,
        Active,
        Passed,
        Executed,
        Cancelled
    }

    struct Proposal {
        ProposalStatus status;
        uint128 yesVotes; // bitmap, 128 maximum votes
        uint8 yesVotesTotal;
        uint40 proposedBlock; // 1099511627775 maximum block
    }

    // destinationChainID => number of deposits
    mapping(uint8 => uint64) public depositCounts;
    // destinationChainID + depositNonce => dataHash => Proposal
    mapping(uint72 => mapping(bytes32 => Proposal)) private _proposals;

    event RelayerThresholdChanged(uint8 newThreshold);
    event RelayerAdded(address relayer);
    event RelayerRemoved(address relayer);
    event Deposit(uint8 destinationChainID, uint64 depositNonce);
    event ProposalEvent(
        uint8 originChainID,
        uint64 depositNonce,
        ProposalStatus status,
        bytes32 dataHash
    );
    event ProposalVote(
        uint8 originChainID,
        uint64 depositNonce,
        ProposalStatus status,
        bytes32 dataHash
    );

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    modifier onlyAdmin() {
        _onlyAdmin();
        _;
    }

    modifier onlyAdminOrRelayer() {
        _onlyAdminOrRelayer();
        _;
    }

    modifier onlyRelayers() {
        _onlyRelayers();
        _;
    }

    function _onlyAdminOrRelayer() private view {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, msg.sender) ||
                hasRole(RELAYER_ROLE, msg.sender),
            "sender is not relayer or admin"
        );
    }

    function _onlyAdmin() private view {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "sender doesn't have admin role"
        );
    }

    function _onlyRelayers() private view {
        require(
            hasRole(RELAYER_ROLE, msg.sender),
            "sender doesn't have relayer role"
        );
    }

    function _relayerBit(address _relayer) private view returns (uint128) {
        return
            uint128(
                1 <<
                    (AccessControl.getRoleMemberIndex(RELAYER_ROLE, _relayer) -
                        1)
            );
    }

    function _hasVoted(Proposal memory _proposal, address _relayer)
        private
        view
        returns (bool)
    {
        return (_relayerBit(_relayer) & uint256(_proposal.yesVotes)) > 0;
    }

    /**
        @notice Initializes Bridge, creates and grants {msg.sender} the admin role,
        creates and grants {initialRelayers} the relayer role.
        @param _initialRelayers Addresses that should be initially granted the relayer role.
        @param _initialRelayerThreshold Number of votes needed for a deposit proposal to be considered passed.
        @param _fee Fee to bridge token.
        @param _expiry bridge expire block amount 
     */
    constructor(
        address[] memory _initialRelayers,
        uint8 _initialRelayerThreshold,
        uint128 _fee,
        uint40 _expiry
    ) {
        relayerThreshold = _initialRelayerThreshold;
        fee = _fee;
        expiry = _expiry;
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);

        for (uint256 i; i < _initialRelayers.length; i++) {
            grantRole(RELAYER_ROLE, _initialRelayers[i]);
        }
    }

    /**
        @notice Returns true if {relayer} has voted on {destNonce} {dataHash} proposal.
        @notice Naming left unchanged for backward compatibility.
        @param _destNonce destinationChainID + depositNonce of the proposal.
        @param _dataHash Hash of data to be provided when deposit proposal is executed.
        @param _relayer Address to check.
     */
    function hasVotedOnProposal(
        uint72 _destNonce,
        bytes32 _dataHash,
        address _relayer
    ) public view returns (bool) {
        return _hasVoted(_proposals[_destNonce][_dataHash], _relayer);
    }

    /**
        @notice Returns true if {relayer} has the relayer role.
        @param _relayer Address to check.
     */
    function isRelayer(address _relayer) external view returns (bool) {
        return hasRole(RELAYER_ROLE, _relayer);
    }

    /**
        @notice Removes admin role from {msg.sender} and grants it to {newAdmin}.
        @notice Only callable by an address that currently has the admin role.
        @param _newAdmin Address that admin role will be granted to.
     */
    function renounceAdmin(address _newAdmin) external onlyAdmin {
        require(msg.sender != _newAdmin, "Cannot renounce oneself");
        grantRole(DEFAULT_ADMIN_ROLE, _newAdmin);
        renounceRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
        @notice Pauses deposits, proposal creation and voting, and deposit executions.
        @notice Only callable by an address that currently has the admin role.
     */
    function adminPauseTransfers() external onlyAdmin {
        _pause();
    }

    /**
        @notice Unpauses deposits, proposal creation and voting, and deposit executions.
        @notice Only callable by an address that currently has the admin role.
     */
    function adminUnpauseTransfers() external onlyAdmin {
        _unpause();
    }

    /**
        @notice Modifies the number of votes required for a proposal to be considered passed.
        @notice Only callable by an address that currently has the admin role.
        @param _newThreshold Value {_relayerThreshold} will be changed to.
        @notice Emits {RelayerThresholdChanged} event.
     */
    function adminChangeRelayerThreshold(uint8 _newThreshold)
        external
        onlyAdmin
    {
        relayerThreshold = _newThreshold;
        emit RelayerThresholdChanged(_newThreshold);
    }

    /**
        @notice Grants {relayerAddress} the relayer role.
        @notice Only callable by an address that currently has the admin role, which is
                checked in grantRole().
        @param _relayerAddress Address of relayer to be added.
        @notice Emits {RelayerAdded} event.
     */
    function adminAddRelayer(address _relayerAddress) external {
        require(
            !hasRole(RELAYER_ROLE, _relayerAddress),
            "addr already has relayer role!"
        );
        require(totalRelayers() < MAX_RELAYERS, "relayers limit reached");
        grantRole(RELAYER_ROLE, _relayerAddress);
        emit RelayerAdded(_relayerAddress);
    }

    /**
        @notice Removes relayer role for {relayerAddress}.
        @notice Only callable by an address that currently has the admin role, which is
                checked in revokeRole().
        @param _relayerAddress Address of relayer to be removed.
        @notice Emits {RelayerRemoved} event.
     */
    function adminRemoveRelayer(address _relayerAddress) external {
        require(
            hasRole(RELAYER_ROLE, _relayerAddress),
            "addr doesn't have relayer role!"
        );
        revokeRole(RELAYER_ROLE, _relayerAddress);
        emit RelayerRemoved(_relayerAddress);
    }

    /**
        @notice Set handler address.
        @param _handlerAddress Address of handler resource will be set for.
     */
    function setHandler(address _handlerAddress) external onlyAdmin {
        handlerAddress = _handlerAddress;
    }

    /**
        @notice Returns a proposal.
        @param _originChainID Chain ID deposit originated from.
        @param _depositNonce ID of proposal generated by proposal's origin Bridge contract.
        @param _dataHash Hash of data to be provided when deposit proposal is executed.
     */
    function getProposal(
        uint8 _originChainID,
        uint64 _depositNonce,
        bytes32 _dataHash
    ) external view returns (Proposal memory) {
        uint72 nonceAndID = (uint72(_depositNonce) << 8) |
            uint72(_originChainID);
        return _proposals[nonceAndID][_dataHash];
    }

    /**
        @notice Returns total relayers number.
        @notice Added for backwards compatibility.
     */
    function totalRelayers() public view returns (uint256) {
        return AccessControl.getRoleMemberCount(RELAYER_ROLE);
    }

    /**
        @notice Changes deposit fee.
        @notice Only callable by admin.
        @param _newFee Value {_fee} will be updated to.
     */
    function adminChangeFee(uint128 _newFee) external onlyAdmin {
        require(fee != _newFee, "Current fee is equal to new fee");
        fee = _newFee;
    }

    /**
        @notice Initiates a transfer using a specified handler contract.
        @notice Only callable when Bridge is not paused.
        @param _destinationChainID ID of chain deposit will be bridged to.
        @param _amount Token amount to deposit.
        @param _recipient Address to receive.
        @notice Emits {Deposit} event.
     */
    function deposit(
        uint8 _destinationChainID,
        uint256 _amount,
        address _recipient
    ) external payable whenNotPaused {
        require(msg.value == fee, "Incorrect fee supplied");

        uint64 depositNonce = ++depositCounts[_destinationChainID];

        IBridgeHandler(handlerAddress).deposit(
            _destinationChainID,
            depositNonce,
            msg.sender,
            _amount,
            _recipient
        );

        emit Deposit(_destinationChainID, depositNonce);
    }

    /**
        @notice When called, {msg.sender} will be marked as voting in favor of proposal.
        @notice Only callable by relayers when Bridge is not paused.
        @param _chainID ID of chain deposit originated from.
        @param _depositNonce ID of deposited generated by origin Bridge contract.
        @param _dataHash Hash of data provided when deposit was made.
        @notice Proposal must not have already been passed or executed.
        @notice {msg.sender} must not have already voted on proposal.
        @notice Emits {ProposalEvent} event with status indicating the proposal status.
        @notice Emits {ProposalVote} event.
     */
    function voteProposal(
        uint8 _chainID,
        uint64 _depositNonce,
        bytes32 _dataHash
    ) external onlyRelayers whenNotPaused {
        uint72 nonceAndID = (uint72(_depositNonce) << 8) | uint72(_chainID);
        Proposal memory proposal = _proposals[nonceAndID][_dataHash];
        require(
            uint256(proposal.status) <= 1,
            "proposal already passed/executed/cancelled"
        );
        require(!_hasVoted(proposal, msg.sender), "relayer already voted");

        if (proposal.status == ProposalStatus.Inactive) {
            proposal = Proposal({
                status: ProposalStatus.Active,
                yesVotes: 0,
                yesVotesTotal: 0,
                proposedBlock: uint40(block.number) // Overflow is desired.
            });

            emit ProposalEvent(
                _chainID,
                _depositNonce,
                ProposalStatus.Active,
                _dataHash
            );
        } else if (uint40(block.number - proposal.proposedBlock) > expiry) {
            // if the number of blocks that has passed since this proposal was
            // submitted exceeds the expiry threshold set, cancel the proposal
            proposal.status = ProposalStatus.Cancelled;

            emit ProposalEvent(
                _chainID,
                _depositNonce,
                ProposalStatus.Cancelled,
                _dataHash
            );
        }

        if (proposal.status != ProposalStatus.Cancelled) {
            proposal.yesVotes = proposal.yesVotes | _relayerBit(msg.sender);
            proposal.yesVotesTotal++; // TODO: check if bit counting is cheaper.

            emit ProposalVote(
                _chainID,
                _depositNonce,
                proposal.status,
                _dataHash
            );

            // Finalize if _relayerThreshold has been reached
            if (proposal.yesVotesTotal >= relayerThreshold) {
                proposal.status = ProposalStatus.Passed;

                emit ProposalEvent(
                    _chainID,
                    _depositNonce,
                    ProposalStatus.Passed,
                    _dataHash
                );
            }
        }
        _proposals[nonceAndID][_dataHash] = proposal;
    }

    /**
        @notice Cancels a deposit proposal that has not been executed yet.
        @notice Only callable by relayers when Bridge is not paused.
        @param _chainID ID of chain deposit originated from.
        @param _depositNonce ID of deposited generated by origin Bridge contract.
        @param _dataHash Hash of data originally provided when deposit was made.
        @notice Proposal must be past expiry threshold.
        @notice Emits {ProposalEvent} event with status {Cancelled}.
     */
    function cancelProposal(
        uint8 _chainID,
        uint64 _depositNonce,
        bytes32 _dataHash
    ) public onlyAdminOrRelayer {
        uint72 nonceAndID = (uint72(_depositNonce) << 8) | uint72(_chainID);
        Proposal memory proposal = _proposals[nonceAndID][_dataHash];
        ProposalStatus currentStatus = proposal.status;

        require(
            currentStatus == ProposalStatus.Active ||
                currentStatus == ProposalStatus.Passed,
            "Proposal cannot be cancelled"
        );
        require(
            uint40(block.number - proposal.proposedBlock) > expiry,
            "Proposal not at expiry threshold"
        );

        proposal.status = ProposalStatus.Cancelled;
        _proposals[nonceAndID][_dataHash] = proposal;

        emit ProposalEvent(
            _chainID,
            _depositNonce,
            ProposalStatus.Cancelled,
            _dataHash
        );
    }

    /**
        @notice Executes a deposit proposal that is considered passed using a specified handler contract.
        @notice Only callable by relayers when Bridge is not paused.
        @param _chainID ID of chain deposit originated from.
        @param _depositNonce ID of deposited generated by origin Bridge contract.
        @param _amount Token amount to deposit.
        @param _recipient Address to receive.
        @notice Proposal must have Passed status.
        @notice Hash of {data} must equal proposal's {dataHash}.
        @notice Emits {ProposalEvent} event with status {Executed}.
     */
    function executeProposal(
        uint8 _chainID,
        uint64 _depositNonce,
        uint256 _amount,
        address _recipient
    ) external onlyRelayers whenNotPaused {
        uint72 nonceAndID = (uint72(_depositNonce) << 8) | uint72(_chainID);
        bytes32 dataHash = keccak256(abi.encodePacked(_amount, _recipient));
        Proposal storage proposal = _proposals[nonceAndID][dataHash];

        require(
            proposal.status == ProposalStatus.Passed,
            "Proposal must have Passed status"
        );

        proposal.status = ProposalStatus.Executed;

        IBridgeHandler(handlerAddress).executeProposal(_amount, _recipient);

        emit ProposalEvent(
            _chainID,
            _depositNonce,
            ProposalStatus.Executed,
            dataHash
        );
    }

    /**
        @param _addrs Array of addresses to transfer {amounts} to.
        @param _amounts Array of amonuts to transfer to {addrs}.
     */
    function transferFunds(
        address payable[] calldata _addrs,
        uint256[] calldata _amounts
    ) external onlyAdmin {
        for (uint256 i = 0; i < _addrs.length; i++) {
            _addrs[i].transfer(_amounts[i]);
        }
    }
}
