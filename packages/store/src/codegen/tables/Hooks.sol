// SPDX-License-Identifier: MIT
pragma solidity >=0.8.21;

/* Autogenerated file. Do not edit manually. */

// Import schema type
import { SchemaType } from "@latticexyz/schema-type/src/solidity/SchemaType.sol";

// Import store internals
import { IStore } from "../../IStore.sol";
import { StoreSwitch } from "../../StoreSwitch.sol";
import { StoreCore } from "../../StoreCore.sol";
import { Bytes } from "../../Bytes.sol";
import { Memory } from "../../Memory.sol";
import { SliceLib } from "../../Slice.sol";
import { EncodeArray } from "../../tightcoder/EncodeArray.sol";
import { FieldLayout, FieldLayoutLib } from "../../FieldLayout.sol";
import { Schema, SchemaLib } from "../../Schema.sol";
import { PackedCounter, PackedCounterLib } from "../../PackedCounter.sol";
import { ResourceId } from "../../ResourceId.sol";
import { RESOURCE_TABLE, RESOURCE_OFFCHAIN_TABLE } from "../../storeResourceTypes.sol";

// Import user types
import { ResourceId } from "./../../ResourceId.sol";

FieldLayout constant _fieldLayout = FieldLayout.wrap(
  0x0000000100000000000000000000000000000000000000000000000000000000
);

library Hooks {
  /**
   * @notice Get the table values' field layout.
   * @return _fieldLayout The field layout for the table.
   */
  function getFieldLayout() internal pure returns (FieldLayout) {
    return _fieldLayout;
  }

  /**
   * @notice Get the table's key schema.
   * @return _keySchema The key schema for the table.
   */
  function getKeySchema() internal pure returns (Schema) {
    SchemaType[] memory _keySchema = new SchemaType[](1);
    _keySchema[0] = SchemaType.BYTES32;

    return SchemaLib.encode(_keySchema);
  }

  /**
   * @notice Get the table's value schema.
   * @return _valueSchema The value schema for the table.
   */
  function getValueSchema() internal pure returns (Schema) {
    SchemaType[] memory _valueSchema = new SchemaType[](1);
    _valueSchema[0] = SchemaType.BYTES21_ARRAY;

    return SchemaLib.encode(_valueSchema);
  }

  /**
   * @notice Get the table's key field names.
   * @return keyNames An array of strings with the names of key fields.
   */
  function getKeyNames() internal pure returns (string[] memory keyNames) {
    keyNames = new string[](1);
    keyNames[0] = "resourceId";
  }

  /**
   * @notice Get the table's value field names.
   * @return fieldNames An array of strings with the names of value fields.
   */
  function getFieldNames() internal pure returns (string[] memory fieldNames) {
    fieldNames = new string[](1);
    fieldNames[0] = "hooks";
  }

  /**
   * @notice Register the table with its config.
   */
  function register(ResourceId _tableId) internal {
    StoreSwitch.registerTable(_tableId, _fieldLayout, getKeySchema(), getValueSchema(), getKeyNames(), getFieldNames());
  }

  /**
   * @notice Register the table with its config.
   */
  function _register(ResourceId _tableId) internal {
    StoreCore.registerTable(_tableId, _fieldLayout, getKeySchema(), getValueSchema(), getKeyNames(), getFieldNames());
  }

  /**
   * @notice Register the table with its config (using the specified store).
   */
  function register(IStore _store, ResourceId _tableId) internal {
    _store.registerTable(_tableId, _fieldLayout, getKeySchema(), getValueSchema(), getKeyNames(), getFieldNames());
  }

  /**
   * @notice Get hooks.
   */
  function getHooks(ResourceId _tableId, ResourceId resourceId) internal view returns (bytes21[] memory hooks) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    bytes memory _blob = StoreSwitch.getDynamicField(_tableId, _keyTuple, 0);
    return (SliceLib.getSubslice(_blob, 0, _blob.length).decodeArray_bytes21());
  }

  /**
   * @notice Get hooks.
   */
  function _getHooks(ResourceId _tableId, ResourceId resourceId) internal view returns (bytes21[] memory hooks) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    bytes memory _blob = StoreCore.getDynamicField(_tableId, _keyTuple, 0);
    return (SliceLib.getSubslice(_blob, 0, _blob.length).decodeArray_bytes21());
  }

  /**
   * @notice Get hooks (using the specified store).
   */
  function getHooks(
    IStore _store,
    ResourceId _tableId,
    ResourceId resourceId
  ) internal view returns (bytes21[] memory hooks) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    bytes memory _blob = _store.getDynamicField(_tableId, _keyTuple, 0);
    return (SliceLib.getSubslice(_blob, 0, _blob.length).decodeArray_bytes21());
  }

  /**
   * @notice Get hooks.
   */
  function get(ResourceId _tableId, ResourceId resourceId) internal view returns (bytes21[] memory hooks) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    bytes memory _blob = StoreSwitch.getDynamicField(_tableId, _keyTuple, 0);
    return (SliceLib.getSubslice(_blob, 0, _blob.length).decodeArray_bytes21());
  }

  /**
   * @notice Get hooks.
   */
  function _get(ResourceId _tableId, ResourceId resourceId) internal view returns (bytes21[] memory hooks) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    bytes memory _blob = StoreCore.getDynamicField(_tableId, _keyTuple, 0);
    return (SliceLib.getSubslice(_blob, 0, _blob.length).decodeArray_bytes21());
  }

  /**
   * @notice Get hooks (using the specified store).
   */
  function get(
    IStore _store,
    ResourceId _tableId,
    ResourceId resourceId
  ) internal view returns (bytes21[] memory hooks) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    bytes memory _blob = _store.getDynamicField(_tableId, _keyTuple, 0);
    return (SliceLib.getSubslice(_blob, 0, _blob.length).decodeArray_bytes21());
  }

  /**
   * @notice Set hooks.
   */
  function setHooks(ResourceId _tableId, ResourceId resourceId, bytes21[] memory hooks) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    StoreSwitch.setDynamicField(_tableId, _keyTuple, 0, EncodeArray.encode((hooks)));
  }

  /**
   * @notice Set hooks.
   */
  function _setHooks(ResourceId _tableId, ResourceId resourceId, bytes21[] memory hooks) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    StoreCore.setDynamicField(_tableId, _keyTuple, 0, EncodeArray.encode((hooks)));
  }

  /**
   * @notice Set hooks (using the specified store).
   */
  function setHooks(IStore _store, ResourceId _tableId, ResourceId resourceId, bytes21[] memory hooks) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    _store.setDynamicField(_tableId, _keyTuple, 0, EncodeArray.encode((hooks)));
  }

  /**
   * @notice Set hooks.
   */
  function set(ResourceId _tableId, ResourceId resourceId, bytes21[] memory hooks) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    StoreSwitch.setDynamicField(_tableId, _keyTuple, 0, EncodeArray.encode((hooks)));
  }

  /**
   * @notice Set hooks.
   */
  function _set(ResourceId _tableId, ResourceId resourceId, bytes21[] memory hooks) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    StoreCore.setDynamicField(_tableId, _keyTuple, 0, EncodeArray.encode((hooks)));
  }

  /**
   * @notice Set hooks (using the specified store).
   */
  function set(IStore _store, ResourceId _tableId, ResourceId resourceId, bytes21[] memory hooks) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    _store.setDynamicField(_tableId, _keyTuple, 0, EncodeArray.encode((hooks)));
  }

  /**
   * @notice Get the length of hooks.
   */
  function lengthHooks(ResourceId _tableId, ResourceId resourceId) internal view returns (uint256) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    uint256 _byteLength = StoreSwitch.getDynamicFieldLength(_tableId, _keyTuple, 0);
    unchecked {
      return _byteLength / 21;
    }
  }

  /**
   * @notice Get the length of hooks.
   */
  function _lengthHooks(ResourceId _tableId, ResourceId resourceId) internal view returns (uint256) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    uint256 _byteLength = StoreCore.getDynamicFieldLength(_tableId, _keyTuple, 0);
    unchecked {
      return _byteLength / 21;
    }
  }

  /**
   * @notice Get the length of hooks (using the specified store).
   */
  function lengthHooks(IStore _store, ResourceId _tableId, ResourceId resourceId) internal view returns (uint256) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    uint256 _byteLength = _store.getDynamicFieldLength(_tableId, _keyTuple, 0);
    unchecked {
      return _byteLength / 21;
    }
  }

  /**
   * @notice Get the length of hooks.
   */
  function length(ResourceId _tableId, ResourceId resourceId) internal view returns (uint256) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    uint256 _byteLength = StoreSwitch.getDynamicFieldLength(_tableId, _keyTuple, 0);
    unchecked {
      return _byteLength / 21;
    }
  }

  /**
   * @notice Get the length of hooks.
   */
  function _length(ResourceId _tableId, ResourceId resourceId) internal view returns (uint256) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    uint256 _byteLength = StoreCore.getDynamicFieldLength(_tableId, _keyTuple, 0);
    unchecked {
      return _byteLength / 21;
    }
  }

  /**
   * @notice Get the length of hooks (using the specified store).
   */
  function length(IStore _store, ResourceId _tableId, ResourceId resourceId) internal view returns (uint256) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    uint256 _byteLength = _store.getDynamicFieldLength(_tableId, _keyTuple, 0);
    unchecked {
      return _byteLength / 21;
    }
  }

  /**
   * @notice Get an item of hooks.
   * @dev Reverts with Store_IndexOutOfBounds if `_index` is out of bounds for the array.
   */
  function getItemHooks(ResourceId _tableId, ResourceId resourceId, uint256 _index) internal view returns (bytes21) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    unchecked {
      bytes memory _blob = StoreSwitch.getDynamicFieldSlice(_tableId, _keyTuple, 0, _index * 21, (_index + 1) * 21);
      return (bytes21(_blob));
    }
  }

  /**
   * @notice Get an item of hooks.
   * @dev Reverts with Store_IndexOutOfBounds if `_index` is out of bounds for the array.
   */
  function _getItemHooks(ResourceId _tableId, ResourceId resourceId, uint256 _index) internal view returns (bytes21) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    unchecked {
      bytes memory _blob = StoreCore.getDynamicFieldSlice(_tableId, _keyTuple, 0, _index * 21, (_index + 1) * 21);
      return (bytes21(_blob));
    }
  }

  /**
   * @notice Get an item of hooks (using the specified store).
   * @dev Reverts with Store_IndexOutOfBounds if `_index` is out of bounds for the array.
   */
  function getItemHooks(
    IStore _store,
    ResourceId _tableId,
    ResourceId resourceId,
    uint256 _index
  ) internal view returns (bytes21) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    unchecked {
      bytes memory _blob = _store.getDynamicFieldSlice(_tableId, _keyTuple, 0, _index * 21, (_index + 1) * 21);
      return (bytes21(_blob));
    }
  }

  /**
   * @notice Get an item of hooks.
   * @dev Reverts with Store_IndexOutOfBounds if `_index` is out of bounds for the array.
   */
  function getItem(ResourceId _tableId, ResourceId resourceId, uint256 _index) internal view returns (bytes21) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    unchecked {
      bytes memory _blob = StoreSwitch.getDynamicFieldSlice(_tableId, _keyTuple, 0, _index * 21, (_index + 1) * 21);
      return (bytes21(_blob));
    }
  }

  /**
   * @notice Get an item of hooks.
   * @dev Reverts with Store_IndexOutOfBounds if `_index` is out of bounds for the array.
   */
  function _getItem(ResourceId _tableId, ResourceId resourceId, uint256 _index) internal view returns (bytes21) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    unchecked {
      bytes memory _blob = StoreCore.getDynamicFieldSlice(_tableId, _keyTuple, 0, _index * 21, (_index + 1) * 21);
      return (bytes21(_blob));
    }
  }

  /**
   * @notice Get an item of hooks (using the specified store).
   * @dev Reverts with Store_IndexOutOfBounds if `_index` is out of bounds for the array.
   */
  function getItem(
    IStore _store,
    ResourceId _tableId,
    ResourceId resourceId,
    uint256 _index
  ) internal view returns (bytes21) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    unchecked {
      bytes memory _blob = _store.getDynamicFieldSlice(_tableId, _keyTuple, 0, _index * 21, (_index + 1) * 21);
      return (bytes21(_blob));
    }
  }

  /**
   * @notice Push an element to hooks.
   */
  function pushHooks(ResourceId _tableId, ResourceId resourceId, bytes21 _element) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    StoreSwitch.pushToDynamicField(_tableId, _keyTuple, 0, abi.encodePacked((_element)));
  }

  /**
   * @notice Push an element to hooks.
   */
  function _pushHooks(ResourceId _tableId, ResourceId resourceId, bytes21 _element) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    StoreCore.pushToDynamicField(_tableId, _keyTuple, 0, abi.encodePacked((_element)));
  }

  /**
   * @notice Push an element to hooks (using the specified store).
   */
  function pushHooks(IStore _store, ResourceId _tableId, ResourceId resourceId, bytes21 _element) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    _store.pushToDynamicField(_tableId, _keyTuple, 0, abi.encodePacked((_element)));
  }

  /**
   * @notice Push an element to hooks.
   */
  function push(ResourceId _tableId, ResourceId resourceId, bytes21 _element) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    StoreSwitch.pushToDynamicField(_tableId, _keyTuple, 0, abi.encodePacked((_element)));
  }

  /**
   * @notice Push an element to hooks.
   */
  function _push(ResourceId _tableId, ResourceId resourceId, bytes21 _element) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    StoreCore.pushToDynamicField(_tableId, _keyTuple, 0, abi.encodePacked((_element)));
  }

  /**
   * @notice Push an element to hooks (using the specified store).
   */
  function push(IStore _store, ResourceId _tableId, ResourceId resourceId, bytes21 _element) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    _store.pushToDynamicField(_tableId, _keyTuple, 0, abi.encodePacked((_element)));
  }

  /**
   * @notice Pop an element from hooks.
   */
  function popHooks(ResourceId _tableId, ResourceId resourceId) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    StoreSwitch.popFromDynamicField(_tableId, _keyTuple, 0, 21);
  }

  /**
   * @notice Pop an element from hooks.
   */
  function _popHooks(ResourceId _tableId, ResourceId resourceId) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    StoreCore.popFromDynamicField(_tableId, _keyTuple, 0, 21);
  }

  /**
   * @notice Pop an element from hooks (using the specified store).
   */
  function popHooks(IStore _store, ResourceId _tableId, ResourceId resourceId) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    _store.popFromDynamicField(_tableId, _keyTuple, 0, 21);
  }

  /**
   * @notice Pop an element from hooks.
   */
  function pop(ResourceId _tableId, ResourceId resourceId) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    StoreSwitch.popFromDynamicField(_tableId, _keyTuple, 0, 21);
  }

  /**
   * @notice Pop an element from hooks.
   */
  function _pop(ResourceId _tableId, ResourceId resourceId) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    StoreCore.popFromDynamicField(_tableId, _keyTuple, 0, 21);
  }

  /**
   * @notice Pop an element from hooks (using the specified store).
   */
  function pop(IStore _store, ResourceId _tableId, ResourceId resourceId) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    _store.popFromDynamicField(_tableId, _keyTuple, 0, 21);
  }

  /**
   * @notice Update an element of hooks at `_index`.
   */
  function updateHooks(ResourceId _tableId, ResourceId resourceId, uint256 _index, bytes21 _element) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    unchecked {
      bytes memory _encoded = abi.encodePacked((_element));
      StoreSwitch.spliceDynamicData(_tableId, _keyTuple, 0, uint40(_index * 21), uint40(_encoded.length), _encoded);
    }
  }

  /**
   * @notice Update an element of hooks at `_index`.
   */
  function _updateHooks(ResourceId _tableId, ResourceId resourceId, uint256 _index, bytes21 _element) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    unchecked {
      bytes memory _encoded = abi.encodePacked((_element));
      StoreCore.spliceDynamicData(_tableId, _keyTuple, 0, uint40(_index * 21), uint40(_encoded.length), _encoded);
    }
  }

  /**
   * @notice Update an element of hooks (using the specified store) at `_index`.
   */
  function updateHooks(
    IStore _store,
    ResourceId _tableId,
    ResourceId resourceId,
    uint256 _index,
    bytes21 _element
  ) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    unchecked {
      bytes memory _encoded = abi.encodePacked((_element));
      _store.spliceDynamicData(_tableId, _keyTuple, 0, uint40(_index * 21), uint40(_encoded.length), _encoded);
    }
  }

  /**
   * @notice Update an element of hooks at `_index`.
   */
  function update(ResourceId _tableId, ResourceId resourceId, uint256 _index, bytes21 _element) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    unchecked {
      bytes memory _encoded = abi.encodePacked((_element));
      StoreSwitch.spliceDynamicData(_tableId, _keyTuple, 0, uint40(_index * 21), uint40(_encoded.length), _encoded);
    }
  }

  /**
   * @notice Update an element of hooks at `_index`.
   */
  function _update(ResourceId _tableId, ResourceId resourceId, uint256 _index, bytes21 _element) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    unchecked {
      bytes memory _encoded = abi.encodePacked((_element));
      StoreCore.spliceDynamicData(_tableId, _keyTuple, 0, uint40(_index * 21), uint40(_encoded.length), _encoded);
    }
  }

  /**
   * @notice Update an element of hooks (using the specified store) at `_index`.
   */
  function update(
    IStore _store,
    ResourceId _tableId,
    ResourceId resourceId,
    uint256 _index,
    bytes21 _element
  ) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    unchecked {
      bytes memory _encoded = abi.encodePacked((_element));
      _store.spliceDynamicData(_tableId, _keyTuple, 0, uint40(_index * 21), uint40(_encoded.length), _encoded);
    }
  }

  /**
   * @notice Delete all data for given keys.
   */
  function deleteRecord(ResourceId _tableId, ResourceId resourceId) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    StoreSwitch.deleteRecord(_tableId, _keyTuple);
  }

  /**
   * @notice Delete all data for given keys.
   */
  function _deleteRecord(ResourceId _tableId, ResourceId resourceId) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    StoreCore.deleteRecord(_tableId, _keyTuple, _fieldLayout);
  }

  /**
   * @notice Delete all data for given keys (using the specified store).
   */
  function deleteRecord(IStore _store, ResourceId _tableId, ResourceId resourceId) internal {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    _store.deleteRecord(_tableId, _keyTuple);
  }

  /**
   * @notice Tightly pack dynamic data lengths using this table's schema.
   * @return _encodedLengths The lengths of the dynamic fields (packed into a single bytes32 value).
   */
  function encodeLengths(bytes21[] memory hooks) internal pure returns (PackedCounter _encodedLengths) {
    // Lengths are effectively checked during copy by 2**40 bytes exceeding gas limits
    unchecked {
      _encodedLengths = PackedCounterLib.pack(hooks.length * 21);
    }
  }

  /**
   * @notice Tightly pack dynamic (variable length) data using this table's schema.
   * @return The dynamic data, encoded into a sequence of bytes.
   */
  function encodeDynamic(bytes21[] memory hooks) internal pure returns (bytes memory) {
    return abi.encodePacked(EncodeArray.encode((hooks)));
  }

  /**
   * @notice Encode all of a record's fields.
   * @return The static (fixed length) data, encoded into a sequence of bytes.
   * @return The lengths of the dynamic fields (packed into a single bytes32 value).
   * @return The dyanmic (variable length) data, encoded into a sequence of bytes.
   */
  function encode(bytes21[] memory hooks) internal pure returns (bytes memory, PackedCounter, bytes memory) {
    bytes memory _staticData;
    PackedCounter _encodedLengths = encodeLengths(hooks);
    bytes memory _dynamicData = encodeDynamic(hooks);

    return (_staticData, _encodedLengths, _dynamicData);
  }

  /**
   * @notice Encode keys as a bytes32 array using this table's field layout.
   */
  function encodeKeyTuple(ResourceId resourceId) internal pure returns (bytes32[] memory) {
    bytes32[] memory _keyTuple = new bytes32[](1);
    _keyTuple[0] = ResourceId.unwrap(resourceId);

    return _keyTuple;
  }
}
