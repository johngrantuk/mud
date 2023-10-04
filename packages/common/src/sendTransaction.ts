import {
  Account,
  CallParameters,
  Chain,
  Client,
  SendTransactionParameters,
  Transport,
  WriteContractReturnType,
} from "viem";
import { call, sendTransaction as viem_sendTransaction } from "viem/actions";
import pRetry from "p-retry";
import { debug as parentDebug } from "./debug";
import { getNonceManager } from "./getNonceManager";
import { parseAccount } from "viem/accounts";

const debug = parentDebug.extend("sendTransaction");

// TODO: migrate away from this approach once we can hook into viem's nonce management: https://github.com/wagmi-dev/viem/discussions/1230

export async function sendTransaction<
  TChain extends Chain | undefined,
  TAccount extends Account | undefined,
  TChainOverride extends Chain | undefined
>(
  client: Client<Transport, TChain, TAccount>,
  request: SendTransactionParameters<TChain, TAccount, TChainOverride>
): Promise<WriteContractReturnType> {
  const account_ = request.account ?? client.account;
  if (!account_) {
    // TODO: replace with viem AccountNotFoundError once its exported
    throw new Error("No account provided");
  }
  const account = parseAccount(account_);

  const nonceManager = await getNonceManager({
    client,
    address: account.address,
  });

  async function prepare(): Promise<SendTransactionParameters<TChain, TAccount, TChainOverride>> {
    if (request.gas) {
      debug("gas provided, skipping simulate", request);
      return request;
    }

    debug("simulating request", request);
    const result = await call(client, { ...request, account } as CallParameters<TChain>);

    // TODO: estimate gas

    console.log("simulated", request, result);

    // return { ...request, data: result.data };
    return request;
  }

  const preparedRequest = await prepare();

  return await pRetry(
    async () => {
      if (!nonceManager.hasNonce()) {
        await nonceManager.resetNonce();
      }

      const nonce = nonceManager.nextNonce();
      debug("calling write function with nonce", nonce, preparedRequest);
      return await viem_sendTransaction(client, { nonce, ...preparedRequest });
    },
    {
      retries: 3,
      onFailedAttempt: async (error) => {
        // On nonce errors, reset the nonce and retry
        if (nonceManager.shouldResetNonce(error)) {
          debug("got nonce error, retrying", error);
          await nonceManager.resetNonce();
          return;
        }
        // TODO: prepare again if there are gas errors?
        throw error;
      },
    }
  );
}
