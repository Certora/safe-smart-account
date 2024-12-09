// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import {Safe} from "../../contracts/Safe.sol";
import {FallbackManager} from "../../contracts/base/FallbackManager.sol";
import {ITransactionGuard, GuardManager} from "../../contracts/base/GuardManager.sol";
import {ModuleManager} from "../../contracts/base/ModuleManager.sol";
import {OwnerManager} from "../../contracts/base/OwnerManager.sol";
import {NativeCurrencyPaymentFallback} from "../../contracts/common/NativeCurrencyPaymentFallback.sol";
import {SecuredTokenTransfer} from "../../contracts/common/SecuredTokenTransfer.sol";
import {SignatureDecoder} from "../../contracts/common/SignatureDecoder.sol";
import {Singleton} from "../../contracts/common/Singleton.sol";
import {StorageAccessible} from "../../contracts/common/StorageAccessible.sol";
import {SafeMath} from "../../contracts/external/SafeMath.sol";
import {ISafe} from "../../contracts/interfaces/ISafe.sol";
import {ISignatureValidator, ISignatureValidatorConstants} from "../../contracts/interfaces/ISignatureValidator.sol";
import {Enum} from "../../contracts/libraries/Enum.sol";

contract SafeHarness is Safe {

    function getOwnerCount() external view returns (uint256) {
        return ownerCount;
    }

    function getGuardExternal() external view returns (address) {
        return getGuard();
    }

}