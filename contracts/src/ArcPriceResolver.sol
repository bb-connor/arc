// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IAggregatorV3} from "./interfaces/IAggregatorV3.sol";
import {IArcPriceResolver} from "./interfaces/IArcPriceResolver.sol";

contract ArcPriceResolver is IArcPriceResolver {
    error NotAdmin();
    error ZeroAddress();
    error FeedNotConfigured();
    error StalePrice();
    error SequencerDown();

    address public admin;
    address public immutable sequencerFeed;

    mapping(bytes32 => PriceFeed) private feeds;

    constructor(address admin_, address sequencerFeed_) {
        if (admin_ == address(0)) revert ZeroAddress();
        admin = admin_;
        sequencerFeed = sequencerFeed_;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    function registerFeed(
        bytes32 base,
        bytes32 quote,
        address aggregator,
        uint256 maxStalenessSeconds
    ) external onlyAdmin {
        if (aggregator == address(0)) revert ZeroAddress();
        feeds[_feedKey(base, quote)] = PriceFeed({
            aggregator: aggregator,
            maxStalenessSeconds: maxStalenessSeconds,
            decimals: IAggregatorV3(aggregator).decimals(),
            description: IAggregatorV3(aggregator).description()
        });
        emit FeedRegistered(base, quote, aggregator, maxStalenessSeconds);
    }

    function getPrice(bytes32 base, bytes32 quote)
        external
        view
        returns (int256 price, uint8 decimals, uint256 updatedAt)
    {
        (bool up,) = sequencerStatus();
        if (!up) revert SequencerDown();

        PriceFeed memory feed = feeds[_feedKey(base, quote)];
        if (feed.aggregator == address(0)) revert FeedNotConfigured();

        (, price,, updatedAt,) = IAggregatorV3(feed.aggregator).latestRoundData();
        if (block.timestamp > updatedAt + feed.maxStalenessSeconds) revert StalePrice();
        return (price, feed.decimals, updatedAt);
    }

    function sequencerStatus() public view returns (bool up, uint256 startedAt) {
        if (sequencerFeed == address(0)) {
            return (true, block.timestamp);
        }
        (, int256 answer, uint256 reportedStartedAt,,) =
            IAggregatorV3(sequencerFeed).latestRoundData();
        return (answer == 0, reportedStartedAt);
    }

    function _feedKey(bytes32 base, bytes32 quote) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(base, quote));
    }
}
