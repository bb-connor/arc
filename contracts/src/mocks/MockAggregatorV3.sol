// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract MockAggregatorV3 {
    uint8 public immutable decimals;
    string public description;

    uint80 private roundId;
    int256 private answer;
    uint256 private startedAt;
    uint256 private updatedAt;
    uint80 private answeredInRound;

    constructor(uint8 decimals_, string memory description_, int256 answer_) {
        decimals = decimals_;
        description = description_;
        _setAnswer(answer_, block.timestamp, block.timestamp);
    }

    function setRoundData(
        uint80 roundId_,
        int256 answer_,
        uint256 startedAt_,
        uint256 updatedAt_,
        uint80 answeredInRound_
    ) external {
        roundId = roundId_;
        answer = answer_;
        startedAt = startedAt_;
        updatedAt = updatedAt_;
        answeredInRound = answeredInRound_;
    }

    function setAnswer(int256 answer_) external {
        _setAnswer(answer_, block.timestamp, block.timestamp);
    }

    function latestRoundData()
        external
        view
        returns (
            uint80,
            int256,
            uint256,
            uint256,
            uint80
        )
    {
        return (roundId, answer, startedAt, updatedAt, answeredInRound);
    }

    function _setAnswer(int256 answer_, uint256 startedAt_, uint256 updatedAt_) internal {
        roundId += 1;
        answer = answer_;
        startedAt = startedAt_;
        updatedAt = updatedAt_;
        answeredInRound = roundId;
    }
}
