// SPDX-License-Identifier: LGPL-3.0-only
import "../munged/Safe.sol";
import {SafeMath} from "../munged/external/SafeMath.sol";
import {ISafe, IStaticFallbackMethod, IFallbackMethod, ExtensibleBase} from "../munged/handler/extensible/ExtensibleBase.sol";

contract SafeHarness is Safe {
    constructor(
        address[] memory _owners,
        uint256 _threshold,
        address to,
        bytes memory data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) {
        setup(_owners, _threshold, to, data, fallbackHandler, paymentToken, payment, paymentReceiver);
    }

    // harnessed functions
    function signatureSplitPublic(bytes memory signatures, uint256 pos) public pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(signatures.length >= 65 * (pos + 1));
        return signatureSplit(signatures, pos);
    }

    function getCurrentOwner(bytes32 dataHash, uint8 v, bytes32 r, bytes32 s) public pure returns (address currentOwner) {
        if (v == 0 || v == 1) {
            currentOwner = address(uint160(uint256(r)));
        } else if (v > 30) {
            currentOwner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), v - 4, r, s);
        } else {
            currentOwner = ecrecover(dataHash, v, r, s);
        }
    }

    function numSigsSufficient(bytes memory signatures,uint256 requiredSignatures) public pure returns (bool) {
        return (signatures.length >= SafeMath.mul(requiredSignatures,65));
    }

    // harnessed getters
    function getModule(address module) public view returns (address) {
        return modules[module];
    }

    function getSafeGuard() public view returns (address) {
        return getGuard();
    }

    function getModuleGuardExternal() public view returns (address) {
        return getModuleGuard();
    }

    function getNativeTokenBalance() public view returns (uint256) {
        return address(this).balance;
    }

    function getNativeTokenBalanceFor(address addr) public view returns (uint256) {
        return addr.balance;
    }

    function getOwnersCount() public view returns (uint256) {
        return ownerCount;
    }

    function getOwnersCountFromArray() public view returns (uint256) {
        return getOwners().length;
    }

    function getFallbackHandler() public view returns (address) {
        address handler;
        assembly{
            handler := sload(FALLBACK_HANDLER_STORAGE_SLOT)
        }
        return handler ;
    }

    // TODO deprecate this with CVL2
    function addressToBytes32(address addr) public pure returns (bytes32) {
        return bytes32(uint256(uint160(addr)));
    }

    function getTransactionHashPublic(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) public view returns (bytes32) {
        // MUNGED: The function was made internal to enable CVL summaries.
        return getTransactionHash(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce);
    }
}
