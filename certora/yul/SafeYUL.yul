// TODO(nlordell):
// - Comment code
// - Don't use string literals where possible, they make the code bigger

// Preprocessor wishlist:
// - #define nonpayable() if callvalue() { revert(0x00, 0x00) }
// - #define EVENT_NAME 0x...
// - #define SENTINEL_MODULES 0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b688792f
// - #define THRESHOLD 4
// - #define IS_L2_SAFE ...

object "Safe" {
  code {
    sstore(4, 1)
    let size := datasize("runtime")
    datacopy(0x00, dataoffset("runtime"), size)
    return(0x00, size)
  }

  object "runtime" {
    code {
      switch shr(224, calldataload(0x00))
      case 0xffa1ad74 { VERSION() }
      case 0xaffed0e0 { nonce() }
      case 0x7d832974 { approvedHashes() }
      case 0xb63e800d { setup() }
      case 0x6a761202 { execTransaction() }
      case 0x934f3a11 { checkSignatures() }
      case 0x12fb68e0 { checkNSignatures() }
      case 0xd4d9bdcd { approveHash() }
      case 0xf698da25 { domainSeparator() }
      case 0xe86637db { encodeTransactionData() }
      case 0xd8d11f78 { getTransactionHash() }
      case 0x610b5925 { enableModule() }
      case 0xe009cfde { disableModule() }
      case 0x468721a7 { execTransactionFromModule() }
      case 0x5229073f { execTransactionFromModuleReturnData() }
      case 0x2d9ad53d { isModuleEnabled() }
      case 0x0d582f13 { addOwnerWithThreshold() }
      case 0xf8dc5dd9 { removeOwner() }
      case 0xe318b52b { swapOwner() }
      case 0x694e80c3 { changeThreshold() }
      case 0xe75235b8 { getThreshold() }
      case 0x2f54bf6e { isOwner() }
      case 0xf08a0323 { setFallbackHandler() }
      case 0xe19a9dd9 { setGuard() }
      case 0xb4faba09 { simulateAndRevert() }
      default {
        if iszero(calldatasize()) {
          receive()
        }
        fallback()
      }

      function VERSION() {
        if callvalue() { revert(0x00, 0x00) }

        mstore(0x00, 0x20)
        mstore(0x3f, "\x0b1.4.1+Yul.0")
        return(0x00, 0x60)
      }

      function nonce() {
        if callvalue() { revert(0x00, 0x00) }

        mstore(0x00, sload(5))
        return(0x00, 0x20)
      }

      function approvedHashes() {
        if callvalue() { revert(0x00, 0x00) }

        mstore(0x20, 8)
        mstore(0x00, shr(96, calldataload(0x10)))
        mstore(0x20, keccak256(0x00, 0x40))
        mstore(0x00, calldataload(0x24))
        mstore(0x00, sload(keccak256(0x00, 0x40)))
        return(0x00, 0x20)
      }

      function setup() {
        if sload(4) { _error("GS200") }

        let owners := add(calldataload(0x04), 0x04)
        let ownersCount := calldataload(owners)
        let ownersSize := shl(5, ownersCount)
        let threshold := calldataload(0x24)
        {
          if gt(threshold, ownersCount) { _error("GS201") }
          if iszero(threshold) { _error("GS202") }
          let previousOwner := 1
          for {
            let ownerPtr := add(owners, ownersSize)
          } gt(ownerPtr, owners) {
            ownerPtr := sub(ownerPtr, 0x20)
          } {
            let owner := calldataload(ownerPtr)
            if or(lt(owner, 2), eq(owner, address())) { _error("GS203") }
            mstore(0x00, owner)
            mstore(0x20, 2)
            let slot := keccak256(0x00, 0x40)
            if sload(slot) { _error("GS204") }
            sstore(slot, previousOwner)
            previousOwner := owner
          }
          // owners[SENTINEL_OWNERS]
          sstore(
            0xe90b7bceb6e7df5418fb78d8ee546e97c83a08bbccc01a0644d599ccd2a7c2e0,
            previousOwner
          )
          sstore(3, ownersCount)
          sstore(4, threshold)
        }

        let fallbackHandler := shr(96, calldataload(0x90))
        if fallbackHandler {
          _internalSetFallbackHandler(fallbackHandler)
        }

        let initializer := shr(96, calldataload(0x50))
        {
          let sentinel := 0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b688792f
          if sload(sentinel) { _error("GS100") }
          sstore(sentinel, 1)
          if initializer {
            let data := add(calldataload(0x64), 0x04)
            let dataLength := calldataload(data)
            calldatacopy(0x00, add(data, 0x20), dataLength)
            if iszero(
              delegatecall(
                gas(),
                initializer,
                0x00, dataLength,
                0x00, 0x00
              )
            ) {
              _error("GS000")
            }
            if iszero(returndatasize()) {
              if iszero(extcodesize(initializer)) { _error("GS002") }
            }
          }
        }

        let payment := calldataload(0xc4)
        if payment {
          _handlePayment(
            shr(96, calldataload(0xb0)),
            payment,
            shr(96, calldataload(0xf0))
          )
        }

        // event SafeSetup(address indexed initiator, address[] owners, uint256 threshold, address initializer, address fallbackHandler)
        mstore(0x00, 0x80)
        mstore(0x20, threshold)
        mstore(0x40, initializer)
        mstore(0x60, fallbackHandler)
        calldatacopy(0x80, owners, add(ownersSize, 0x20))
        log2(
          0x00, add(ownersSize, 0xa0),
          0x141df868a6331af528e38c83b7aa03edc19be66e37ae67f9285bf4f8e3c6a1a8,
          caller()
        )
        stop()
      }

      function execTransaction() {
        let _nonce := sload(5)
        let txDataLength := 0x42
        _encodeTransactionData(0x104, _nonce)
        mstore(0xe4, txDataLength)
        mstore(0x146, 0)
        sstore(5, add(_nonce, 1))
        let txHash := keccak256(0x104, txDataLength)
        let signatures := add(calldataload(0x124), 0x04)
        let threshold := sload(4)
        if iszero(threshold) { _error("GS001") }
        _innerCheckNSignatures(
          txHash,
          0x00,
          txDataLength,
          signatures,
          threshold
        )
        // GUARD_STORAGE_SLOT
        let guard := sload(
          0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8
        )
        if guard {
          // Guard.checkTransaction
          mstore(0, hex"75f0bb52")
          calldatacopy(0x04, 0x04, 0x120)
          mstore(0x44, 0x160)
          let data := add(calldataload(0x44), 0x04)
          let dataEncodedLength := add(calldataload(data), 0x20)
          calldatacopy(0x164, data, dataEncodedLength)
          let dataEnd := add(0x164, dataEncodedLength)
          mstore(dataEnd, 0)
          let signaturesOffset := and(add(dataEnd, 0x1f), not(0x1f))
          mstore(0x124, signaturesOffset)
          let signaturesStart := add(signaturesOffset, 0x04)
          let signaturesEncodedLength := add(calldataload(signatures), 0x20)
          calldatacopy(signaturesStart, signatures, signaturesEncodedLength)
          let signaturesEnd := add(signaturesStart, signaturesEncodedLength)
          mstore(signaturesEnd, 0)
          mstore(0x144, caller())
          if iszero(
            call(
              gas(),
              guard,
              0,
              0x00, add(and(add(signaturesEnd, 0x1f), not(0x1f)), 0x04),
              0x00, 0x00
            )
          ) {
            returndatacopy(0x00, 0x00, returndatasize())
            revert(0x00, returndatasize())
          }
        }
        let safeTxGas := calldataload(0x84)
        {
          let safeTxGasEip150 := div(shl(safeTxGas, 6), 63)
          let safeTxGasBuf := add(safeTxGas, 2500)
          let safeTxGasMask := sub(lt(safeTxGasEip150, safeTxGasBuf), 1)
          if lt(
            gas(),
            add(
              or(
                and(safeTxGasMask, safeTxGasEip150),
                and(not(safeTxGasMask), safeTxGasBuf)
              ),
              500
            )
          ) {
            _error("GS010")
          }
        }
        let gasPrice := calldataload(0xc4)
        let gasLimit := safeTxGas
        if iszero(gasPrice) {
          gasLimit := sub(gas(), 2500)
        }
        let gasUsed := gas()
        let success := _execute(
          calldataload(0x04),
          calldataload(0x24),
          add(calldataload(0x44), 0x04),
          calldataload(0x64),
          gasLimit
        )
        gasUsed := sub(gasUsed, gas())
        if iszero(
          or(
            success,
            or(safeTxGas, gasPrice)
          )
        ) {
          _error("GS013")
        }
        let payment := 0
        if gasPrice {
          let token := calldataload(0xe4)
          if and(iszero(token), gt(gasPrice, gasprice())) {
            gasPrice := gasprice()
          }
          let totalGas := add(gasUsed, calldataload(0xa4))
          if lt(totalGas, gasUsed) { revert(0x00, 0x00) }
          payment := mul(totalGas, gasPrice)
          if xor(div(payment, totalGas), gasPrice) { revert(0x00, 0x00) }
          _handlePayment(token, payment, calldataload(0x104))
        }
        // event ExecutionSuccess(bytes32 indexed txHash, uint256 payment)
        // event ExecutionFailure(bytes32 indexed txHash, uint256 payment)
        mstore(0x00, payment)
        log2(
          0x00, 0x20,
          or(
            mul(
              success,
              0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e
            ),
            mul(
              iszero(success),
              0x23428b18acfb3ea64b08dc0c1d296ea9c09702c09083ca5272e64d115b687d23
            )
          ),
          txHash
        )
        if guard {
          // Guard.checkAfterExecution
          mstore(0, hex"93271368")
          mstore(0x04, txHash)
          mstore(0x24, success)
          if iszero(
            call(
              gas(),
              guard,
              0,
              0x00, 0x44,
              0x00, 0x00
            )
          ) {
            returndatacopy(0x00, 0x00, returndatasize())
            revert(0x00, returndatasize())
          }
        }
        mstore(0x00, success)
        return(0x00, 0x20)
      }

      function checkSignatures() {
        let threshold := sload(4)
        if iszero(threshold) { _error("GS001") }
        _checkNSignatures(threshold)
      }

      function checkNSignatures() {
        _checkNSignatures(calldataload(0x64))
      }

      function approveHash() {
        if callvalue() { revert(0x00, 0x00) }

        mstore(0x00, caller())
        mstore(0x20, 2)
        if iszero(sload(keccak256(0x00, 0x40))) { _error("GS030") }

        mstore(0x20, 8)
        mstore(0x00, caller())
        mstore(0x20, keccak256(0x00, 0x40))
        let hash := calldataload(0x04)
        mstore(0x00, hash)
        sstore(keccak256(0x00, 0x40), 1)
        // event ApproveHash(bytes32 indexed hash, address indexed owner)
        log3(
          0x00, 0x00,
          0xf2a0eb156472d1440255b0d7c1e19cc07115d1051fe605b0dce69acfec884d9c,
          hash,
          caller()
        )
        stop()
      }

      function domainSeparator() {
        if callvalue() { revert(0x00, 0x00) }

        mstore(0x00, _domainSeparator())
        return(0x00, 0x20)
      }

      function encodeTransactionData() {
        if callvalue() { revert(0x00, 0x00) }

        _encodeTransactionData(0x40, calldataload(0x124))
        mstore(0x00, 0x20)
        mstore(0x20, 0x42)
        mstore(0x82, 0)
        return(0x00, 0xa0)
      }

      function getTransactionHash() {
        if callvalue() { revert(0x00, 0x00) }

        _encodeTransactionData(0x00, calldataload(0x124))
        mstore(0x00, keccak256(0x00, 0x42))
        return(0x00, 0x20)
      }

      function enableModule() {
        _authorized()

        let module := shr(96, calldataload(0x10))
        if lt(module, 2) { _error("GS101") }

        mstore(0x00, module)
        mstore(0x20, 1)
        let slot := keccak256(0x00, 0x40)
        if sload(slot) { _error("GS102") }

        let sentinel := 0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b688792f
        sstore(slot, sload(sentinel))
        sstore(sentinel, module)
        // event EnabledModule(address indexed module)
        log2(
          0x00, 0x00,
          0xecdf3a3effea5783a3c4c2140e677577666428d44ed9d474a0b3a4c9943f8440,
          module
        )
        stop()
      }

      function disableModule() {
        _authorized()

        let module := shr(96, calldataload(0x30))
        if lt(module, 2) { _error("GS101") }

        mstore(0x20, 1)
        mstore(0x00, shr(96, calldataload(0x10)))
        let prevSlot := keccak256(0x00, 0x40)
        if xor(sload(prevSlot), module) { _error("GS103") }

        mstore(0x00, module)
        let slot := keccak256(0x00, 0x40)
        sstore(prevSlot, sload(slot))
        sstore(slot, 0)
        // event DisabledModule(address indexed module)
        log2(
          0x00, 0x00,
          0xaab4fa2b463f581b2b32cb3b7e3b704b9ce37cc209b5fb4d77e593ace4054276,
          module
        )
        stop()
      }

      function execTransactionFromModule() {
        mstore(0x00, _execTransactionFromModule())
        return(0x00, 0x20)
      }

      function execTransactionFromModuleReturnData() {
        mstore(0x00, _execTransactionFromModule())
        mstore(0x20, 0x40)
        mstore(0x40, returndatasize())
        returndatacopy(0x60, 0x00, returndatasize())
        return(0x00, and(add(returndatasize(), 0x7f), not(0x1f)))
      }

      function isModuleEnabled() {
        if callvalue() { revert(0x00, 0x00) }

        let module := shr(96, calldataload(0x10))
        if gt(module, 1) {
          mstore(0x00, module)
          mstore(0x20, 1)
          mstore(0x00, iszero(iszero(sload(keccak256(0x00, 0x40)))))
        }
        return(0x00, 0x20)
      }

      function addOwnerWithThreshold() {
        _authorized()

        let owner := shr(96, calldataload(0x10))
        if or(lt(owner, 2), eq(owner, address())) { _error("GS203") }

        mstore(0x00, owner)
        mstore(0x20, 2)
        let slot := keccak256(0x00, 0x40)
        if sload(slot) { _error("GS204") }

        let sentinel := 0xe90b7bceb6e7df5418fb78d8ee546e97c83a08bbccc01a0644d599ccd2a7c2e0
        sstore(slot, sload(sentinel))
        sstore(sentinel, owner)
        sstore(3, add(sload(3), 1))
        // event AddedOwner(address indexed owner)
        log2(
          0x00, 0x00,
          0x9465fa0c962cc76958e6373a993326400c1c94f8be2fe3a952adfa7f60b2ea26,
          owner
        )
        let threshold := calldataload(0x24)
        if xor(threshold, sload(4)) {
          _changeThreshold(threshold)
        }
        stop()
      }

      function removeOwner() {
        _authorized()

        let ownerCount := sub(sload(3), 1)
        let threshold := calldataload(0x44)
        if lt(ownerCount, threshold) { _error("GS201") }

        let owner := shr(96, calldataload(0x30))
        if lt(owner, 2) { _error("GS203") }

        mstore(0x00, shr(96, calldataload(0x10)))
        mstore(0x20, 2)
        let prevSlot := keccak256(0x00, 0x40)
        if xor(sload(prevSlot), owner) { _error("GS205") }

        mstore(0x00, owner)
        let slot := keccak256(0x00, 0x40)
        sstore(prevSlot, sload(slot))
        sstore(slot, 0)
        sstore(3, ownerCount)
        // event RemovedOwner(address indexed owner)
        log2(
          0x00, 0x00,
          0xf8d49fc529812e9a7c5c50e69c20f0dccc0db8fa95c98bc58cc9a4f1c1299eaf,
          owner
        )
        if xor(threshold, sload(4)) {
          _changeThreshold(threshold)
        }
        stop()
      }

      function swapOwner() {
        _authorized()

        let newOwner := shr(96, calldataload(0x50))
        if or(lt(newOwner, 2), eq(newOwner, address())) { _error("GS203") }

        mstore(0x00, newOwner)
        mstore(0x20, 2)
        let newSlot := keccak256(0x00, 0x40)
        if sload(newSlot) { _error("GS204") }

        let oldOwner := shr(96, calldataload(0x30))
        if lt(oldOwner, 2) { _error("GS203") }

        mstore(0x00, shr(96, calldataload(0x10)))
        let prevSlot := keccak256(0x00, 0x40)
        if xor(sload(prevSlot), oldOwner) { _error("GS205") }

        mstore(0x00, oldOwner)
        let oldSlot := keccak256(0x00, 0x40)
        sstore(newSlot, sload(oldSlot))
        sstore(prevSlot, newOwner)
        sstore(oldSlot, 0)
        // event RemovedOwner(address indexed owner)
        log2(
          0x00, 0x00,
          0xf8d49fc529812e9a7c5c50e69c20f0dccc0db8fa95c98bc58cc9a4f1c1299eaf,
          oldOwner
        )
        // event AddedOwner(address indexed owner)
        log2(
          0x00, 0x00,
          0x9465fa0c962cc76958e6373a993326400c1c94f8be2fe3a952adfa7f60b2ea26,
          newOwner
        )
      }

      function changeThreshold() {
        _authorized()

        _changeThreshold(calldataload(0x04))
        stop()
      }

      function getThreshold() {
        if callvalue() { revert(0x00, 0x00) }

        mstore(0x00, sload(4))
        return(0x00, 0x20)
      }

      function isOwner() {
        if callvalue() { revert(0x00, 0x00) }

        let owner := shr(96, calldataload(0x10))
        if gt(owner, 1) {
          mstore(0x00, owner)
          mstore(0x20, 2)
          mstore(0x00, iszero(iszero(sload(keccak256(0x00, 0x40)))))
        }
        return(0x00, 0x20)
      }

      function setFallbackHandler() {
        _authorized()

        let fallbackHandler := shr(96, calldataload(0x10))
        _internalSetFallbackHandler(fallbackHandler)
        // event ChangedFallbackHandler(address indexed fallbackHandler)
        log2(
          0x00, 0x00,
          0x5ac6c46c93c8d0e53714ba3b53db3e7c046da994313d7ed0d192028bc7c228b0,
          fallbackHandler
        )
        stop()
      }

      function setGuard() {
        _authorized()

        let guard := shr(96, calldataload(0x10))
        if guard {
          // guard.supportsInterface(type(Guard).interfaceId)
          mstore(0x00, hex"01ffc9a7e6d7a83a")
          if or(
            or(
              xor(returndatasize(), 0x20),
              xor(mload(0x00), 1)
            ),
            iszero(staticcall(gas(), guard, 0x00, 0x24, 0x00, 0x20))
          ) {
            _error("GS300")
          }
        }
        // GUARD_STORAGE_SLOT
        sstore(
          0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8,
          guard
        )
        // event ChangedGuard(address indexed guard)
        log2(
          0x00, 0x00,
          0x1151116914515bc0891ff9047a6cb32cf902546f83066499bcf8ba33d2353fa2,
          guard
        )
        stop()
      }

      function simulateAndRevert() {
        let data := add(calldataload(0x24), 0x04)
        let dataLength := calldataload(data)
        calldatacopy(0x00, add(data, 0x20), dataLength)
        mstore(
          0x00,
          delegatecall(
            gas(),
            calldataload(0x04),
            0x00, dataLength,
            0x00, 0x00
          )
        )
        mstore(0x20, returndatasize())
        returndatacopy(0x40, 0x00, returndatasize())
        revert(0x00, add(returndatasize(), 0x40))
      }

      function receive() {
        // event SafeReceived(address indexed sender, uint256 value)
        mstore(0x00, callvalue())
        log2(
          0x00, 0x20,
          0x3d0ce9bfc3ed7d6862dbb28b2dea94561fe714a1b4d019aa8af39730d1ad7c3d,
          caller()
        )
        stop()
      }

      function fallback() {
        if callvalue() { revert(0x00, 0x00) }

        calldatacopy(0x00, 0x00, calldatasize())
        mstore(calldatasize(), shl(96, caller()))
        let success := call(
          gas(),
          // FALLBACK_HANDLER_STORAGE_SLOT
          sload(0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5),
          0,
          0x00, add(calldatasize(), 0x14),
          0x00, 0x00
        )
        returndatacopy(0x00, 0x00, returndatasize())

        if success {
          return(0x00, returndatasize())
        }
        revert(0x00, returndatasize())
      }

      function _error(code) {
        mstore(0x00, hex"08c379a0")
        mstore(0x04, 0x20)
        mstore(0x24, 0x05)
        mstore(0x44, code)
        revert(0x00, 0x64)
      }

      function _authorized() {
        if callvalue() { revert(0x00, 0x00) }
        if iszero(eq(caller(), address())) { _error("GS031") }
      }

      function _checkNSignatures(n) {
        if callvalue() { revert(0x00, 0x00) }

        _innerCheckNSignatures(
          calldataload(0x04),
          add(calldataload(0x24), 0x04),
          0x00,
          add(calldataload(0x44), 0x04),
          n
        )
        stop()
      }

      function _innerCheckNSignatures(dataHash, data, dataLength, signatures, n) {
        let signaturesLength := calldataload(signatures)
        let signaturesPtr := add(signatures, 0x20)
        if lt(div(signaturesLength, 0x41), n) { _error("GS020") }
        let fixedLength := mul(n, 0x41)

        let dataPrefixLength := 0
        for {
          let ptr := signaturesPtr
          let end := add(ptr, fixedLength)
          let lastOwner := 1
          let currentOwner
        } lt(ptr, end) {
          ptr := add(ptr, 0x41)
          mstore(0x00, currentOwner)
          mstore(0x20, 2)
          if or(
            iszero(gt(currentOwner, lastOwner)),
            iszero(sload(keccak256(0x00, 0x40)))
          ) {
            _error("GS026")
          }
          lastOwner := currentOwner
        } {
          let v := byte(0, calldataload(add(ptr, 0x40)))
          if iszero(v) {
            let magic := hex"20c13b0b"
            if iszero(dataPrefixLength) {
              mstore(0xa0, magic)
              mstore(0xa4, 0x40)
              if data {
                dataLength := calldataload(data)
                calldatacopy(0xe4, data, add(dataLength, 0x20))
                mstore(add(0x104, dataLength), 0)
                if xor(dataHash, keccak256(0x104, dataLength)) { _error("GS027") }
              }
              let signatureOffset := and(add(dataLength, 0x7f), not(0x1f))
              mstore(0xc4, signatureOffset)
              dataPrefixLength := add(signatureOffset, 0x04)
            }
            currentOwner := and(
              calldataload(ptr),
              0xffffffffffffffffffffffffffffffffffffffff
            )
            let s := calldataload(add(ptr, 0x20))
            if lt(s, fixedLength) { _error("GS021") }
            // `signaturesLength - 0x20` can't overflow as in order to reach
            // this point: `signaturesLength >= fixedLength >= 0x41`
            if gt(s, sub(signaturesLength, 0x20)) { _error("GS022") }
            let offset := add(signaturesPtr, s)
            let length := calldataload(offset)
            // `signaturesLength - s - 0x20` can't overflow as we already
            // checked: `s <= signaturesLength - 0x20`.
            if gt(length, sub(signaturesLength, add(s, 0x20))) { _error("GS023") }
            calldatacopy(add(0xa0, dataPrefixLength), offset, add(length, 0x20))
            mstore(add(add(dataPrefixLength, length), 0xc0), 0)
            if iszero(
              staticcall(
                gas(),
                currentOwner,
                0xa0, add(dataPrefixLength, and(add(length, 0x3f), not(0x1f))),
                0x00, 0x20
              )
            ) {
              returndatacopy(0x00, 0x00, returndatasize())
              revert(0x00, returndatasize())
            }
            if or(
              xor(returndatasize(), 0x20),
              xor(mload(0x00), magic)
            ) {
              _error("GS024")
            }
            continue
          }
          if eq(v, 1) {
            currentOwner := and(
              calldataload(ptr),
              0xffffffffffffffffffffffffffffffffffffffff
            )
            if xor(currentOwner, caller()) {
              mstore(0x20, 8)
              mstore(0x00, currentOwner)
              mstore(0x20, keccak256(0x00, 0x40))
              mstore(0x00, dataHash)
              if iszero(sload(keccak256(0x00, 0x40))) { _error("GS025") }
            }
            continue
          }
          {
            mstore(0x20, dataHash)
            if gt(v, 30) {
              mstore(0x00, "\x00\x00\x00\x00\x19Ethereum Signed Message:\n32")
              mstore(0x20, keccak256(0x04, 0x3c))
              v := sub(v, 4)
            }
            mstore(0x40, v)
            mstore(0x60, calldataload(ptr))
            mstore(0x80, calldataload(add(ptr, 0x20)))
            mstore(0x00, 0)
            pop(staticcall(gas(), 1, 0x20, 0x80, 0x00, 0x20))
            currentOwner := mload(0x00)
          }
        }
      }

      function _domainSeparator() -> result {
        mstore(0x00, 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218)
        mstore(0x20, chainid())
        mstore(0x40, address())
        result := keccak256(0x00, 0x60)
      }

      function _encodeTransactionData(ptr, _nonce) {
        let data := add(calldataload(0x44), 0x04)
        let dataLength := calldataload(data)
        calldatacopy(0x00, add(data, 0x20), dataLength)
        let dataHash := keccak256(0x00, dataLength)
        mstore(0x00, 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8)
        mstore(0x20, shr(96, calldataload(0x10)))
        mstore(0x40, calldataload(0x24))
        mstore(0x60, dataHash)
        mstore(0x80, and(calldataload(0x64), 1))
        mstore(0xa0, calldataload(0x84))
        mstore(0xc0, calldataload(0xa4))
        mstore(0xe0, calldataload(0xc4))
        mstore(0x100, calldataload(0xe4))
        mstore(0x120, calldataload(0x104))
        mstore(0x140, _nonce)
        let safeTxHash := keccak256(0x00, 0x160)
        let domain := _domainSeparator()
        mstore(ptr, hex"1901")
        mstore(add(ptr, 0x02), domain)
        mstore(add(ptr, 0x22), safeTxHash)
      }

      function _execTransactionFromModule() -> success {
        if callvalue() { revert(0x00, 0x00) }

        mstore(0x00, caller())
        mstore(0x20, 1)
        let slot := keccak256(0x00, 0x40)
        if or(lt(caller(), 2), iszero(sload(slot))) { _error("GS104") }

        success := _execute(
          calldataload(0x04),
          calldataload(0x24),
          add(calldataload(0x44), 0x04),
          calldataload(0x64),
          // Can't use gas() here because of ERC-4337.
          0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        )
        // event ExecutionFromModuleSuccess(address indexed module)
        // event ExecutionFromModuleFailure(address indexed module)
        log2(
          0x00, 0x00,
          or(
            mul(
              success,
              0x6895c13664aa4f67288b25d7a21d7aaa34916e355fb9b6fae0a139a9085becb8
            ),
            mul(
              iszero(success),
              0xacd2c8702804128fdb0db2bb49f6d127dd0181c13fd45dbfe16de0930e2bd375
            )
          ),
          caller()
        )
      }

      function _execute(to, value, data, operation, gasLimit) -> success {
        let dataLength := calldataload(data)
        calldatacopy(0x00, add(data, 0x20), dataLength)

        switch operation
        case 0 { success := call(gasLimit, to, value, 0x00, dataLength, 0x00, 0x00) }
        case 1 { success := delegatecall(gasLimit, to, 0x00, dataLength, 0x00, 0x00) }
        default { revert(0x00, 0x00) }
      }

      function _handlePayment(token, payment, receiver) {
        receiver := or(receiver, mul(iszero(receiver), origin()))
        switch token
        case 0 {
          if iszero(call(gas(), receiver, payment, 0x00, 0x00, 0x00, 0x00)) {
            _error("GS011")
          }
        }
        default {
          // token.transfer(receiver, payment)
          mstore(0x00, hex"a9059cbb")
          mstore(0x04, receiver)
          mstore(0x24, payment)
          let success := call(
            sub(gas(), 10000),
            token,
            0,
            0x00, 0x44,
            0x00, 0x20
          )
          switch returndatasize()
          case 0x00 {
            success := mul(success, extcodesize(token))
          }
          case 0x20 {
            success := and(success, eq(mload(0x00), 1))
          }
          default {
            success := 0
          }
          if iszero(success) { _error("GS012") }
        }
      }

      function _changeThreshold(threshold) {
        if gt(threshold, sload(3)) { _error("GS201") }
        if iszero(threshold) { _error("GS202") }
        sstore(4, threshold)
        // event ChangedThreshold(uint256 threshold)
        mstore(0x00, threshold)
        log1(
          0x00, 0x20,
          0x610f7ff2b304ae8903c3de74c60c6ab1f7d6226b3f52c5161905bb5ad4039c93
        )
      }

      function _internalSetFallbackHandler(fallbackHandler) {
        if eq(fallbackHandler, address()) { _error("GS400") }
        // FALLBACK_HANDLER_STORAGE_SLOT
        sstore(
          0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5,
          fallbackHandler
        )
      }
    }
  }
}