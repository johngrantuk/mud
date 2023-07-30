import { ethers } from "ethers";
import { mainnet, localhost, Chain } from "viem/chains";

// TODO: Use viem's getChainId
export async function getChainId(rpc: string) {
  const { result: chainId } = await ethers.utils.fetchJson(
    rpc,
    '{ "id": 42, "jsonrpc": "2.0", "method": "eth_chainId", "params": [ ] }'
  );
  return Number(chainId);
}

export function getChain(chainId: number): Chain {
  // TODO - This is just a temp helper while it is decided which is best method for determining Chain.
  switch (chainId) {
    case 1:
      return mainnet;
    case 1337:
      return localhost;
    case 31337:
      return { ...localhost, id: 31337 };
    default:
      throw Error(`Unsupported Chain for ID: ${chainId}`);
  }
}
