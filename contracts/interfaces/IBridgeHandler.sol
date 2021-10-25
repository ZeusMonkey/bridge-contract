// SPDX-License-Identifier: MIT

pragma solidity 0.8.9;

/**
    @title Interface for BridgeHandler contracts .
    @author Ryuhei Matsuda
 */
interface IBridgeHandler {
    /**
        @param _destinationChainID Chain ID deposit is expected to be bridged to.
        @param _depositNonce This value is generated as an ID by the Bridge contract.
        @param _depositer Address of account making the deposit in the Bridge contract.
        @param _amount Token amount to deposit.
        @param _recipient Address to receive.
     */
    function deposit(
        uint8 _destinationChainID,
        uint64 _depositNonce,
        address _depositer,
        uint256 _amount,
        address _recipient
    ) external;

    /**
        @param _amount Token amount to deposit.
        @param _recipient Address to receive.
     */
    function executeProposal(uint256 _amount, address _recipient) external;
}
