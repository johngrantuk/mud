import { existsSync, readFileSync } from "fs";
import path from "path";
import chalk from "chalk";
import { BigNumber, ContractInterface, ethers } from "ethers";
import { defaultAbiCoder as abi, Fragment, ParamType } from "ethers/lib/utils.js";
import { createPublicClient, createWalletClient, http, Hex, Abi, Address } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { getOutDirectory, getScriptDirectory, cast, forge } from "@latticexyz/common/foundry";
import { resolveWithContext } from "@latticexyz/config";
import { MUDError } from "@latticexyz/common/errors";
import { encodeSchema } from "@latticexyz/schema-type/deprecated";
import { StoreConfig } from "@latticexyz/store";
import { resolveAbiOrUserType } from "@latticexyz/store/codegen";
import { WorldConfig, resolveWorldConfig } from "@latticexyz/world";
import { IBaseWorld } from "@latticexyz/world/types/ethers-contracts/IBaseWorld";
import WorldData from "@latticexyz/world/abi/World.sol/World.json" assert { type: "json" };
import IBaseWorldData from "@latticexyz/world/abi/IBaseWorld.sol/IBaseWorld.json" assert { type: "json" };
import CoreModuleData from "@latticexyz/world/abi/CoreModule.sol/CoreModule.json" assert { type: "json" };
import KeysWithValueModuleData from "@latticexyz/world/abi/KeysWithValueModule.sol/KeysWithValueModule.json" assert { type: "json" };
import KeysInTableModuleData from "@latticexyz/world/abi/KeysInTableModule.sol/KeysInTableModule.json" assert { type: "json" };
import UniqueEntityModuleData from "@latticexyz/world/abi/UniqueEntityModule.sol/UniqueEntityModule.json" assert { type: "json" };
import SnapSyncModuleData from "@latticexyz/world/abi/SnapSyncModule.sol/SnapSyncModule.json" assert { type: "json" };
import { getChain } from "./getChainId";
import { stringToBytes16 } from "@latticexyz/utils";

export function uint8ArrayToHex(array: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < array.length; i++) {
    const byte = array[i];
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

function convertToBytes16(uint8Array: Uint8Array): string {
  const hexString = Array.from(uint8Array, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return hexString.padEnd(32, "0");
}

export interface DeployConfig {
  profile?: string;
  rpc: string;
  privateKey: string;
  priorityFeeMultiplier: number;
  debug?: boolean;
  worldAddress?: string;
  disableTxWait: boolean;
  pollInterval: number;
}

export interface DeploymentInfo {
  blockNumber: number;
  worldAddress: string;
}

export async function deploy(
  mudConfig: StoreConfig & WorldConfig,
  existingContractNames: string[],
  deployConfig: DeployConfig
): Promise<DeploymentInfo> {
  const resolvedConfig = resolveWorldConfig(mudConfig, existingContractNames);

  const startTime = Date.now();
  const { worldContractName, namespace, postDeployScript } = mudConfig;
  const { profile, rpc, privateKey, priorityFeeMultiplier, debug, worldAddress, disableTxWait, pollInterval } =
    deployConfig;
  const forgeOutDirectory = await getOutDirectory(profile);

  // Set up signer for deployment
  // const provider = new ethers.providers.StaticJsonRpcProvider(rpc);
  // provider.pollingInterval = pollInterval;
  // const signer = new ethers.Wallet(privateKey, provider);

  // Set up Local Account for deployment
  const publicClient = createPublicClient({
    transport: http(rpc),
    pollingInterval: pollInterval,
  });
  const chainId = await publicClient.getChainId();
  const chain = getChain(chainId);
  const account = privateKeyToAccount(privateKey as Hex);
  const client = createWalletClient({
    chain,
    account,
    pollingInterval: pollInterval,
    transport: http(rpc),
  });

  // Manual nonce handling to allow for faster sending of transactions without waiting for previous transactions
  let nonce = await publicClient.getTransactionCount({
    address: account.address,
  });
  console.log("Initial nonce", nonce);

  // Compute maxFeePerGas and maxPriorityFeePerGas like ethers, but allow for a multiplier to allow replacing pending transactions
  let maxPriorityFeePerGas: number;
  let maxFeePerGas: bigint;
  await setInternalFeePerGas(priorityFeeMultiplier);

  // Catch all to await any promises before exiting the script
  let promises: Promise<unknown>[] = [];

  // Get block number before deploying
  const blockNumber = Number(await cast(["block-number", "--rpc-url", rpc], { profile }));
  console.log("Start deployment at block", blockNumber);

  // Deploy World
  const worldPromise = {
    World: worldAddress
      ? Promise.resolve(worldAddress)
      : worldContractName
      ? deployContractByName(worldContractName, disableTxWait)
      : deployContract(IBaseWorldData.abi, WorldData.bytecode, disableTxWait, "World"),
  };

  // Deploy Systems
  const systemPromises = Object.keys(resolvedConfig.systems).reduce<Record<string, Promise<string>>>(
    (acc, systemName) => {
      acc[systemName] = deployContractByName(systemName, disableTxWait);
      return acc;
    },
    {}
  );

  // Deploy default World modules
  const defaultModules: Record<string, Promise<string>> = {
    // TODO: these only need to be deployed once per chain, add a check if they exist already
    CoreModule: deployContract(CoreModuleData.abi, CoreModuleData.bytecode, disableTxWait, "CoreModule"),
    KeysWithValueModule: deployContract(
      KeysWithValueModuleData.abi,
      KeysWithValueModuleData.bytecode,
      disableTxWait,
      "KeysWithValueModule"
    ),
    KeysInTableModule: deployContract(
      KeysInTableModuleData.abi,
      KeysInTableModuleData.bytecode,
      disableTxWait,
      "KeysInTableModule"
    ),
    UniqueEntityModule: deployContract(
      UniqueEntityModuleData.abi,
      UniqueEntityModuleData.bytecode,
      disableTxWait,
      "UniqueEntityModule"
    ),
    SnapSyncModule: deployContract(
      SnapSyncModuleData.abi,
      SnapSyncModuleData.bytecode,
      disableTxWait,
      "SnapSyncModule"
    ),
  };

  // Deploy user Modules
  const modulePromises = mudConfig.modules
    .filter((module) => !defaultModules[module.name]) // Only deploy user modules here, not default modules
    .reduce<Record<string, Promise<string>>>((acc, module) => {
      acc[module.name] = deployContractByName(module.name, disableTxWait);
      return acc;
    }, defaultModules);

  // Combine all contracts into one object
  const contractPromises: Record<string, Promise<string>> = { ...worldPromise, ...systemPromises, ...modulePromises };

  const worldContractAddr = await contractPromises.World;
  // Create World contract instance from deployed address
  // const WorldContract = new ethers.Contract(worldContractAddr, IBaseWorldData.abi, signer) as IBaseWorld;

  const confirmations = disableTxWait ? 0 : 1;

  // Install core Modules
  if (!worldAddress) {
    console.log(chalk.blue("Installing core World modules"));
    // await fastTxExecute(WorldContract, "installRootModule", [await modulePromises.CoreModule, "0x"], confirmations);
    await fastTx(
      worldContractAddr as Hex,
      IBaseWorldData.abi as Abi,
      "installRootModule",
      [await modulePromises.CoreModule, "0x"],
      confirmations
    );
    console.log(chalk.green("Installed core World modules"));
  }

  // Register namespace
  // if (namespace) await fastTxExecute(WorldContract, "registerNamespace", [toBytes16(namespace)], confirmations);
  if (namespace)
    await fastTx(
      worldContractAddr as Hex,
      IBaseWorldData.abi as Abi,
      "registerNamespace",
      [toBytes16(namespace)],
      confirmations
    );

  // Register tables
  const tableIds: { [tableName: string]: Uint8Array } = {};
  promises = [
    ...promises,
    ...Object.entries(mudConfig.tables).map(async ([tableName, { name, schema, keySchema }]) => {
      console.log(chalk.blue(`Registering table ${tableName} at ${namespace}/${name}`));

      // Store the tableId for later use
      tableIds[tableName] = toResourceSelector(namespace, name);

      // Register table
      const schemaTypes = Object.values(schema).map((abiOrUserType) => {
        const { schemaType } = resolveAbiOrUserType(abiOrUserType, mudConfig);
        return schemaType;
      });

      const keyTypes = Object.values(keySchema).map((abiOrUserType) => {
        const { schemaType } = resolveAbiOrUserType(abiOrUserType, mudConfig);
        return schemaType;
      });

      // await fastTxExecute(
      //   WorldContract,
      //   "registerTable",
      //   [toBytes16(namespace), toBytes16(name), encodeSchema(schemaTypes), encodeSchema(keyTypes)],
      //   confirmations
      // );
      const x = uint8ArrayToHex(encodeSchema(schemaTypes));
      const y = uint8ArrayToHex(encodeSchema(keyTypes));
      const a = convertToBytes16(stringToBytes16(namespace));
      const b = convertToBytes16(stringToBytes16(name));
      await fastTx(
        worldContractAddr as Hex,
        IBaseWorldData.abi as Abi,
        "registerTable",
        [`0x${a}`, `0x${b}`, `0x${x}`, `0x${y}`],
        confirmations
      );

      // Register table metadata
      // await fastTxExecute(
      //   WorldContract,
      //   "setMetadata(bytes16,bytes16,string,string[])",
      //   [toBytes16(namespace), toBytes16(name), tableName, Object.keys(schema)],
      //   confirmations
      // );
      await fastTx(
        worldContractAddr as Hex,
        IBaseWorldData.abi as Abi,
        "setMetadata(bytes16,bytes16,string,string[])",
        [toBytes16(namespace), toBytes16(name), tableName, Object.keys(schema)],
        confirmations
      );

      console.log(chalk.green(`Registered table ${tableName} at ${name}`));
    }),
  ];

  // Register systems (using forEach instead of for..of to avoid blocking on async calls)
  promises = [
    ...promises,
    ...Object.entries(resolvedConfig.systems).map(
      async ([systemName, { name, openAccess, registerFunctionSelectors }]) => {
        // Register system at route
        console.log(chalk.blue(`Registering system ${systemName} at ${namespace}/${name}`));
        // await fastTxExecute(
        //   WorldContract,
        //   "registerSystem",
        //   [toBytes16(namespace), toBytes16(name), await contractPromises[systemName], openAccess],
        //   confirmations
        // );
        const a = convertToBytes16(stringToBytes16(namespace));
        const b = convertToBytes16(stringToBytes16(name));
        await fastTx(
          worldContractAddr as Hex,
          IBaseWorldData.abi as Abi,
          "registerSystem",
          [`0x${a}`, `0x${b}`, await contractPromises[systemName], openAccess],
          confirmations
        );
        console.log(chalk.green(`Registered system ${systemName} at ${namespace}/${name}`));

        // Register function selectors for the system
        if (registerFunctionSelectors) {
          const functionSignatures: FunctionSignature[] = await loadFunctionSignatures(systemName);
          const isRoot = namespace === "";
          // Using Promise.all to avoid blocking on async calls
          await Promise.all(
            functionSignatures.map(async ({ functionName, functionArgs }) => {
              const functionSignature = isRoot
                ? functionName + functionArgs
                : `${namespace}_${name}_${functionName}${functionArgs}`;

              console.log(chalk.blue(`Registering function "${functionSignature}"`));
              if (isRoot) {
                const worldFunctionSelector = toFunctionSelector(
                  functionSignature === ""
                    ? { functionName: systemName, functionArgs } // Register the system's fallback function as `<systemName>(<args>)`
                    : { functionName, functionArgs }
                );
                const systemFunctionSelector = toFunctionSelector({ functionName, functionArgs });
                // await fastTxExecute(
                //   WorldContract,
                //   "registerRootFunctionSelector",
                //   [toBytes16(namespace), toBytes16(name), worldFunctionSelector, systemFunctionSelector],
                //   confirmations
                // );
                await fastTx(
                  worldContractAddr as Hex,
                  IBaseWorldData.abi as Abi,
                  "registerRootFunctionSelector",
                  [toBytes16(namespace), toBytes16(name), worldFunctionSelector, systemFunctionSelector],
                  confirmations
                );
              } else {
                // await fastTxExecute(
                //   WorldContract,
                //   "registerFunctionSelector",
                //   [toBytes16(namespace), toBytes16(name), functionName, functionArgs],
                //   confirmations
                // );
                await fastTx(
                  worldContractAddr as Hex,
                  IBaseWorldData.abi as Abi,
                  "registerFunctionSelector",
                  [toBytes16(namespace), toBytes16(name), functionName, functionArgs],
                  confirmations
                );
              }
              console.log(chalk.green(`Registered function "${functionSignature}"`));
            })
          );
        }
      }
    ),
  ];

  // Wait for resources to be registered before granting access to them
  await Promise.all(promises); // ----------------------------------------------------------------------------------------------
  promises = [];

  // Grant access to systems
  for (const [systemName, { name, accessListAddresses, accessListSystems }] of Object.entries(resolvedConfig.systems)) {
    const resourceSelector = `${namespace}/${name}`;

    // Grant access to addresses
    promises = [
      ...promises,
      ...accessListAddresses.map(async (address) => {
        console.log(chalk.blue(`Grant ${address} access to ${systemName} (${resourceSelector})`));
        // await fastTxExecute(
        //   WorldContract,
        //   "grantAccess",
        //   [toBytes16(namespace), toBytes16(name), address],
        //   confirmations
        // );
        await fastTx(
          worldContractAddr as Hex,
          IBaseWorldData.abi as Abi,
          "grantAccess",
          [toBytes16(namespace), toBytes16(name), address],
          confirmations
        );
        console.log(chalk.green(`Granted ${address} access to ${systemName} (${namespace}/${name})`));
      }),
    ];

    // Grant access to other systems
    promises = [
      ...promises,
      ...accessListSystems.map(async (granteeSystem) => {
        console.log(chalk.blue(`Grant ${granteeSystem} access to ${systemName} (${resourceSelector})`));
        // await fastTxExecute(
        //   WorldContract,
        //   "grantAccess",
        //   [toBytes16(namespace), toBytes16(name), await contractPromises[granteeSystem]],
        //   confirmations
        // );
        await fastTx(
          worldContractAddr as Hex,
          IBaseWorldData.abi as Abi,
          "grantAccess",
          [toBytes16(namespace), toBytes16(name), await contractPromises[granteeSystem]],
          confirmations
        );
        console.log(chalk.green(`Granted ${granteeSystem} access to ${systemName} (${resourceSelector})`));
      }),
    ];
  }

  // Wait for access to be granted before installing modules
  await Promise.all(promises); // ----------------------------------------------------------------------------------------------
  promises = [];

  // Install modules
  promises = [
    ...promises,
    ...mudConfig.modules.map(async (module) => {
      console.log(chalk.blue(`Installing${module.root ? " root " : " "}module ${module.name}`));
      // Resolve arguments
      const resolvedArgs = await Promise.all(
        module.args.map((arg) => resolveWithContext(arg, { tableIds, systemAddresses: contractPromises }))
      );
      const values = resolvedArgs.map((arg) => arg.value);
      const types = resolvedArgs.map((arg) => arg.type);
      const moduleAddress = await contractPromises[module.name];
      if (!moduleAddress) throw new Error(`Module ${module.name} not found`);

      // Send transaction to install module
      // await fastTxExecute(
      //   WorldContract,
      //   module.root ? "installRootModule" : "installModule",
      //   [moduleAddress, abi.encode(types, values)],
      //   confirmations
      // );
      await fastTx(
        worldContractAddr as Hex,
        IBaseWorldData.abi as Abi,
        module.root ? "installRootModule" : "installModule",
        [moduleAddress, abi.encode(types, values)],
        confirmations
      );

      console.log(chalk.green(`Installed${module.root ? " root " : " "}module ${module.name}`));
    }),
  ];

  // Await all promises before executing PostDeploy script
  await Promise.all(promises); // ----------------------------------------------------------------------------------------------

  // Confirm the current nonce is the expected nonce to make sure all transactions have been included
  let remoteNonce = await publicClient.getTransactionCount({
    address: account.address,
  });
  let retryCount = 0;
  const maxRetries = 100;
  while (remoteNonce !== nonce && retryCount < maxRetries) {
    console.log(
      chalk.gray(
        `Waiting for transactions to be included before executing ${postDeployScript} (local nonce: ${nonce}, remote nonce: ${remoteNonce}, retry number ${retryCount}/${maxRetries})`
      )
    );
    await new Promise((resolve) => setTimeout(resolve, pollInterval));
    retryCount++;
    remoteNonce = await publicClient.getTransactionCount({
      address: account.address,
    });
  }
  if (remoteNonce !== nonce) {
    throw new MUDError(
      "Remote nonce doesn't match local nonce, indicating that not all deploy transactions were included."
    );
  }

  promises = [];

  // Execute postDeploy forge script
  const postDeployPath = path.join(await getScriptDirectory(), postDeployScript + ".s.sol");
  if (existsSync(postDeployPath)) {
    console.log(chalk.blue(`Executing post deploy script at ${postDeployPath}`));
    await forge(
      [
        "script",
        postDeployScript,
        "--sig",
        "run(address)",
        await contractPromises.World,
        "--broadcast",
        "--rpc-url",
        rpc,
        "-vvv",
      ],
      {
        profile,
      }
    );
  } else {
    console.log(`No script at ${postDeployPath}, skipping post deploy hook`);
  }

  console.log(chalk.green("Deployment completed in", (Date.now() - startTime) / 1000, "seconds"));

  return { worldAddress: await contractPromises.World, blockNumber };

  // ------------------- INTERNAL FUNCTIONS -------------------
  // (Inlined to avoid having to pass around nonce, signer and forgeOutDir)

  /**
   * Deploy a contract and return the address
   * @param contractName Name of the contract to deploy (must exist in the file system)
   * @param disableTxWait Disable waiting for contract deployment
   * @returns Address of the deployed contract
   */
  async function deployContractByName(contractName: string, disableTxWait: boolean): Promise<string> {
    console.log(chalk.blue("Deploying", contractName));

    const { abi, bytecode } = await getContractData(contractName);
    return deployContract(abi, bytecode, disableTxWait, contractName);
  }

  /**
   * Deploy a contract and return the address
   * @param abi The contract interface
   * @param bytecode The contract bytecode
   * @param disableTxWait Disable waiting for contract deployment
   * @param contractName The contract name (optional, used for logs)
   * @param retryCount
   * @returns Address of the deployed contract
   */
  // async function deployContractOG(
  //   abi: ContractInterface,
  //   bytecode: string | { object: string },
  //   disableTxWait: boolean,
  //   contractName?: string,
  //   retryCount = 0
  // ): Promise<string> {
  //   try {
  //     const factory = new ethers.ContractFactory(abi, bytecode, signer);
  //     console.log(chalk.gray(`executing deployment of ${contractName} with nonce ${nonce}`));
  //     const deployPromise = factory
  //       .deploy({
  //         nonce: nonce++,
  //         maxPriorityFeePerGas,
  //         maxFeePerGas,
  //       })
  //       .then((c) => (disableTxWait ? c : c.deployed()));

  //     promises.push(deployPromise);
  //     const { address } = await deployPromise;

  //     console.log(chalk.green("Deployed", contractName, "to", address));
  //     return address;
  //   } catch (error: any) {
  //     if (debug) console.error(error);
  //     if (retryCount === 0 && error?.message.includes("transaction already imported")) {
  //       // If the deployment failed because the transaction was already imported,
  //       // retry with a higher priority fee
  //       setInternalFeePerGas(priorityFeeMultiplier * 1.1);
  //       return deployContract(abi, bytecode, disableTxWait, contractName, retryCount++);
  //     } else if (error?.message.includes("invalid bytecode")) {
  //       throw new MUDError(
  //         `Error deploying ${contractName}: invalid bytecode. Note that linking of public libraries is not supported yet, make sure none of your libraries use "external" functions.`
  //       );
  //     } else if (error?.message.includes("CreateContractLimit")) {
  //       throw new MUDError(`Error deploying ${contractName}: CreateContractLimit exceeded.`);
  //     } else throw error;
  //   }
  // }

  async function deployContract(
    abi: ContractInterface,
    bytecode: string | { object: string },
    disableTxWait: boolean,
    contractName?: string,
    retryCount = 0
  ): Promise<string> {
    try {
      console.log(chalk.gray(`executing deployment of ${contractName} with nonce ${nonce}`));

      const hash = await client.deployContract({
        abi: abi as Abi,
        bytecode: typeof bytecode === "string" ? (bytecode as Hex) : (bytecode.object as Hex),
        nonce: nonce++,
        gas: 30000000n, // TODO - viem throws without this with EstimateGasExecutionError: The amount of gas provided for the transaction exceeds the limit allowed for the block.
      });
      if (!hash) throw Error("No Deploy"); // TODO - How was this handled?

      // TODO Was this doing anything??
      console.log(`!!!!!! disableTxWait`, disableTxWait);
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      const contractAddress = receipt.contractAddress;
      // promises.push(deployPromise);
      console.log(chalk.green("Deployed", contractName, "to", contractAddress));
      return contractAddress as string;
    } catch (error: any) {
      if (debug) console.error(error);
      if (retryCount === 0 && error?.message.includes("transaction already imported")) {
        // If the deployment failed because the transaction was already imported,
        // retry with a higher priority fee
        setInternalFeePerGas(priorityFeeMultiplier * 1.1);
        return deployContract(abi, bytecode, disableTxWait, contractName, retryCount++);
      } else if (error?.message.includes("invalid bytecode")) {
        throw new MUDError(
          `Error deploying ${contractName}: invalid bytecode. Note that linking of public libraries is not supported yet, make sure none of your libraries use "external" functions.`
        );
      } else if (error?.message.includes("CreateContractLimit")) {
        throw new MUDError(`Error deploying ${contractName}: CreateContractLimit exceeded.`);
      } else throw error;
    }
  }

  /**
   * Deploy a contract and return the address
   * @param contractName Name of the contract to deploy (must exist in the file system)
   * @returns Address of the deployed contract
   *
   * NOTE: Forge deploy seems to be slightly slower than ethers
   * (probably due to the extra overhead spawning a child process to run forge),
   * so we mostly use ethersDeployContract here.
   * However, for contracts not in the user directory (eg. the vanilla World contract),
   * using forge is more convenient because it automatically finds the contract in the @latticexyz/world package.
   */
  // async function forgeDeployContract(contractName: string): Promise<string> {
  //   console.log(chalk.blue("Deploying", contractName));

  //   const { deployedTo } = JSON.parse(
  //     await forge(
  //       ["create", contractName, "--rpc-url", rpc, "--private-key", privateKey, "--json", "--nonce", String(nonce++)],
  //       { profile, silent: true }
  //     )
  //   );
  //   return deployedTo;
  // }

  async function loadFunctionSignatures(contractName: string): Promise<FunctionSignature[]> {
    const { abi } = await getContractData(contractName);

    return abi
      .filter((item) => ["fallback", "function"].includes(item.type))
      .map((item) => {
        if (item.type === "fallback") return { functionName: "", functionArgs: "" };

        return {
          functionName: item.name,
          functionArgs: parseComponents(item.inputs),
        };
      });
  }

  /**
   * Recursively turn (nested) structs in signatures into tuples
   */
  function parseComponents(params: ParamType[]): string {
    const components = params.map((param) => {
      const tupleMatch = param.type.match(/tuple(.*)/);
      if (tupleMatch) {
        // there can be arrays of tuples,
        // `tupleMatch[1]` preserves the array brackets (or is empty string for non-arrays)
        return parseComponents(param.components) + tupleMatch[1];
      } else {
        return param.type;
      }
    });
    return `(${components})`;
  }

  /**
   * Only await gas estimation (for speed), only execute if gas estimation succeeds (for safety)
   */
  async function fastTxExecute<C extends { estimateGas: any; [key: string]: any }, F extends keyof C>(
    contract: C,
    func: F,
    args: Parameters<C[F]>,
    confirmations = 1,
    retryCount = 0
  ): Promise<Awaited<ReturnType<Awaited<ReturnType<C[F]>>["wait"]>>> {
    const functionName = `${func as string}(${args.map((arg) => `'${arg}'`).join(",")})`;
    try {
      const gasLimit = await contract.estimateGas[func].apply(null, args);
      console.log(chalk.gray(`executing transaction: ${functionName} with nonce ${nonce}`));
      console.log(maxFeePerGas);
      console.log(maxPriorityFeePerGas);
      console.log(gasLimit.toString());
      const txPromise = contract[func]
        .apply(null, [...args, { gasLimit, nonce: nonce++, maxPriorityFeePerGas, maxFeePerGas }])
        .then((tx: any) => (confirmations === 0 ? tx : tx.wait(confirmations)));
      promises.push(txPromise);
      return txPromise;
    } catch (error: any) {
      if (debug) console.error(error);
      if (retryCount === 0 && error?.message.includes("transaction already imported")) {
        // If the deployment failed because the transaction was already imported,
        // retry with a higher priority fee
        setInternalFeePerGas(priorityFeeMultiplier * 1.1);
        return fastTxExecute(contract, func, args, confirmations, retryCount++);
      } else throw new MUDError(`Gas estimation error for ${functionName}: ${error?.reason}`);
    }
  }

  async function fastTx(
    address: Address,
    abi: Abi,
    func: string,
    args: any,
    confirmations = 1,
    retryCount = 0
  ): Promise<void> {
    const functionDisplay = `JOHNS ${func as string}(${args.map((arg: any) => `'${arg}'`).join(",")})`;
    console.log(functionDisplay);
    console.log(address);
    try {
      // // https://github.com/wagmi-dev/viem/discussions/239
      // const gasLimit = await contract.estimateGas[func].apply(null, args);
      // const gl = await publicClient.estimateGas.apply(null, args);
      console.log(chalk.gray(`executing transaction: ${functionDisplay} with nonce ${nonce}`));
      const result = await publicClient.simulateContract({
        address,
        abi,
        functionName: func,
        account,
        maxPriorityFeePerGas: BigInt(maxPriorityFeePerGas),
        maxFeePerGas,
        nonce: nonce++,
        args: [...args],
      });
      // console.log(result);
      console.log(`???????????? 1 hello ${functionDisplay}`);
      const hash = await client.writeContract(result.request);
      console.log("???????????? 2");
      promises.push(publicClient.waitForTransactionReceipt({ hash, confirmations }));

      // if (confirmations === 0) promises.push(client.writeContract(result.request));
      // else {
      //   console.log("???????????? 1");
      //   const hash = await client.writeContract(result.request);
      //   console.log("???????????? 2");
      //   promises.push(publicClient.waitForTransactionReceipt({ hash, confirmations }));
      // }
    } catch (error: any) {
      console.log(`!!!!!!! EEEK ${functionDisplay} ${nonce}`);
      console.log(error);
      if (debug) console.error(error);
      if (retryCount === 0 && error?.message.includes("transaction already imported")) {
        // If the deployment failed because the transaction was already imported,
        // retry with a higher priority fee
        setInternalFeePerGas(priorityFeeMultiplier * 1.1);
        return fastTx(address, abi, func, args, confirmations, retryCount++);
      } else throw new MUDError(`Gas estimation error for ${functionDisplay}: ${error?.reason}`);
    }
  }

  /**
   * Load the contract's abi and bytecode from the file system
   * @param contractName: Name of the contract to load
   */
  async function getContractData(contractName: string): Promise<{ bytecode: string; abi: Fragment[] }> {
    let data: any;
    const contractDataPath = path.join(forgeOutDirectory, contractName + ".sol", contractName + ".json");
    try {
      data = JSON.parse(readFileSync(contractDataPath, "utf8"));
    } catch (error: any) {
      throw new MUDError(`Error reading file at ${contractDataPath}`);
    }

    const bytecode = data?.bytecode?.object;
    if (!bytecode) throw new MUDError(`No bytecode found in ${contractDataPath}`);

    const abi = data?.abi;
    if (!abi) throw new MUDError(`No ABI found in ${contractDataPath}`);

    return { abi, bytecode };
  }

  /**
   * Set the maxFeePerGas and maxPriorityFeePerGas based on the current base fee and the given multiplier.
   * The multiplier is used to allow replacing pending transactions.
   * @param multiplier Multiplier to apply to the base fee
   */
  async function setInternalFeePerGas(multiplier: number) {
    // Compute maxFeePerGas and maxPriorityFeePerGas like ethers, but allow for a multiplier to allow replacing pending transactions
    const gasEstimate = await publicClient.getFeeHistory({
      blockCount: 4, // TODO - These values are taken directly from Viem and could be improved?
      rewardPercentiles: [25, 75],
    });
    const balance = await publicClient.getBalance({
      address: account.address,
    });
    if (!(gasEstimate.baseFeePerGas[0] === 0n) && balance === 0n) {
      throw new MUDError(`Attempting to deploy to a chain with non-zero base fee with an account that has no balance.
If you're deploying to the Lattice testnet, you can fund your account by running 'pnpm mud faucet --address ${account.address}'`);
    }

    // Set the priority fee to 0 for development chains with no base fee, to allow transactions from unfunded wallets
    maxPriorityFeePerGas = gasEstimate.baseFeePerGas[0] === 0n ? 0 : Math.floor(1_500_000_000 * multiplier);
    maxFeePerGas = gasEstimate.baseFeePerGas[0] * 2n + BigInt(maxPriorityFeePerGas);
  }
}

// TODO: use stringToBytes16 from utils as soon as utils are usable inside cli
// (see https://github.com/latticexyz/mud/issues/499)
function toBytes16(input: string) {
  if (input.length > 16) throw new Error("String does not fit into 16 bytes");

  const result = new Uint8Array(16);
  // Set ascii bytes
  for (let i = 0; i < input.length; i++) {
    result[i] = input.charCodeAt(i);
  }
  // Set the remaining bytes to 0
  for (let i = input.length; i < 16; i++) {
    result[i] = 0;
  }
  return result;
}

// TODO: use TableId from utils as soon as utils are usable inside cli
// (see https://github.com/latticexyz/mud/issues/499)
function toResourceSelector(namespace: string, file: string): Uint8Array {
  const namespaceBytes = toBytes16(namespace);
  const fileBytes = toBytes16(file);
  const result = new Uint8Array(32);
  result.set(namespaceBytes);
  result.set(fileBytes, 16);
  return result;
}

interface FunctionSignature {
  functionName: string;
  functionArgs: string;
}

// TODO: move this to utils as soon as utils are usable inside cli
// (see https://github.com/latticexyz/mud/issues/499)
function toFunctionSelector({ functionName, functionArgs }: FunctionSignature): string {
  const functionSignature = functionName + functionArgs;
  if (functionSignature === "") return "0x";
  return sigHash(functionSignature);
}

// TODO: move this to utils as soon as utils are usable inside cli
// (see https://github.com/latticexyz/mud/issues/499)
function sigHash(signature: string) {
  return ethers.utils.hexDataSlice(ethers.utils.keccak256(ethers.utils.toUtf8Bytes(signature)), 0, 4);
}
