// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import { Create2 } from "./Create2.sol";
import { World } from "../World.sol";
import { IWorldFactory } from "./IWorldFactory.sol";
import { IBaseWorld } from "../interfaces/IBaseWorld.sol";
import { IModule } from "../interfaces/IModule.sol";

contract WorldFactory is IWorldFactory {
  IModule public coreModule;
  uint256 public worldCount;

  constructor(IModule _coreModule) {
    coreModule = _coreModule;
  }

  /**
    @dev Deploy a new World and install coreModule.
  */
  function deployWorld() public {
    bytes memory bytecode = type(World).creationCode;
    address worldAddress = Create2.deploy(bytecode, worldCount);
    IBaseWorld world = IBaseWorld(worldAddress);
    world.installRootModule(coreModule, new bytes(0));
    emit WorldDeployed(worldAddress);
    worldCount++;
  }
}
