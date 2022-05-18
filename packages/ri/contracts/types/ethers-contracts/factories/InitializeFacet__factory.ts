/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import { Provider, TransactionRequest } from "@ethersproject/providers";
import type { InitializeFacet, InitializeFacetInterface } from "../InitializeFacet";

const _abi = [
  {
    inputs: [
      {
        components: [
          {
            internalType: "bool",
            name: "resetCallerEntityID",
            type: "bool",
          },
          {
            internalType: "address",
            name: "personaMirror",
            type: "address",
          },
        ],
        internalType: "struct Config",
        name: "config",
        type: "tuple",
      },
    ],
    name: "initializeExternally",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "accessControllerAddr",
        type: "address",
      },
    ],
    name: "registerAccessControllerExternally",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "contentCreatorAddr",
        type: "address",
      },
    ],
    name: "registerContentCreatorExternally",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "embodiedSystemAddr",
        type: "address",
      },
      {
        internalType: "bytes4",
        name: "selector",
        type: "bytes4",
      },
    ],
    name: "registerEmbodiedSystemExternally",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
];

const _bytecode =
  "0x608060405234801561001057600080fd5b506115d3806100206000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c80633b78571814610051578063cef6222314610066578063fdd1d27c14610079578063fecf4d6d1461008c575b600080fd5b61006461005f3660046104aa565b61009f565b005b6100646100743660046104e4565b61011f565b6100646100873660046104e4565b61012b565b61006461009a366004610508565b610134565b8060006100ac8282610566565b50506040516100ba9061049d565b604051809103906000f0801580156100d6573d6000803e3d6000fd5b50600180547fffffffffffffffffffffffff00000000000000000000000000000000000000001673ffffffffffffffffffffffffffffffffffffffff9290921691909117905550565b61012881610142565b50565b61012881610218565b61013e828261027a565b5050565b6000805b60038201548110156101bc578273ffffffffffffffffffffffffffffffffffffffff1682600301828154811061017e5761017e6105ff565b60009182526020909120015473ffffffffffffffffffffffffffffffffffffffff16036101aa57505050565b806101b48161062e565b915050610146565b506003018054600181018255600091825260209091200180547fffffffffffffffffffffffff00000000000000000000000000000000000000001673ffffffffffffffffffffffffffffffffffffffff92909216919091179055565b6040805160048152602481019091526020810180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167f328984700000000000000000000000000000000000000000000000000000000017905261013e9082906103a9565b7fffffffff00000000000000000000000000000000000000000000000000000000811660009081526004602052604081205473ffffffffffffffffffffffffffffffffffffffff161561032e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601b60248201527f53656c6563746f7220616c72656164792072656769737465726564000000000060448201526064015b60405180910390fd5b7fffffffff000000000000000000000000000000000000000000000000000000009091166000908152600490910160205260409020805473ffffffffffffffffffffffffffffffffffffffff9092167fffffffffffffffffffffffff0000000000000000000000000000000000000000909216919091179055565b60606000808473ffffffffffffffffffffffffffffffffffffffff16846040516103d3919061068d565b600060405180830381855af49150503d806000811461040e576040519150601f19603f3d011682016040523d82523d6000602084013e610413565b606091505b509092509050811515600003610495578051156104335780518082602001fd5b6040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601560248201527f44656c656761746543616c6c20726576657274656400000000000000000000006044820152606401610325565b949350505050565b610ed5806106c983390190565b6000604082840312156104bc57600080fd5b50919050565b73ffffffffffffffffffffffffffffffffffffffff8116811461012857600080fd5b6000602082840312156104f657600080fd5b8135610501816104c2565b9392505050565b6000806040838503121561051b57600080fd5b8235610526816104c2565b915060208301357fffffffff000000000000000000000000000000000000000000000000000000008116811461055b57600080fd5b809150509250929050565b813580151580821461057757600080fd5b8254915060ff81169050807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00831617835560208401356105b6816104c2565b7fffffffffffffffffffffff000000000000000000000000000000000000000000929092161760089190911b74ffffffffffffffffffffffffffffffffffffffff001617905550565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203610686577f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b5060010190565b6000825160005b818110156106ae5760208186018101518583015201610694565b818111156106bd576000828501525b50919091019291505056fe60806040526040516100109061005f565b604051809103906000f08015801561002c573d6000803e3d6000fd5b50600080546001600160a01b0319166001600160a01b039290921691909117905534801561005957600080fd5b5061006c565b61043880610a9d83390190565b610a228061007b6000396000f3fe608060405234801561001057600080fd5b506004361061007d5760003560e01c8063d7ecf62b1161005b578063d7ecf62b146100f5578063d803064a146100fd578063e3d1287514610110578063f30347701461013357600080fd5b80634f27da18146100825780639f54f545146100bf578063af104e40146100e0575b600080fd5b61009561009036600461084f565b610146565b60405173ffffffffffffffffffffffffffffffffffffffff90911681526020015b60405180910390f35b6100d26100cd366004610891565b6101ff565b6040519081526020016100b6565b6100f36100ee3660046108b3565b6102b6565b005b6100d2610433565b6100f361010b36600461093a565b6104ca565b61012361011e36600461084f565b6105ad565b60405190151581526020016100b6565b6100f361014136600461093a565b610647565b60008181526001602052604081205473ffffffffffffffffffffffffffffffffffffffff166101d6576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820181905260248201527f436f6d706f6e656e74206861736e2774206265656e207265676973746572656460448201526064015b60405180910390fd5b5060009081526001602052604090205473ffffffffffffffffffffffffffffffffffffffff1690565b73ffffffffffffffffffffffffffffffffffffffff8116600090815260026020526040812054810361028d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820181905260248201527f436f6d706f6e656e74206861736e2774206265656e207265676973746572656460448201526064016101cd565b5073ffffffffffffffffffffffffffffffffffffffff1660009081526002602052604090205490565b73ffffffffffffffffffffffffffffffffffffffff8416600090815260026020526040812054859103610345576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820181905260248201527f436f6d706f6e656e74206861736e2774206265656e207265676973746572656460448201526064016101cd565b6000546040517f1003e2d20000000000000000000000000000000000000000000000000000000081526004810186905273ffffffffffffffffffffffffffffffffffffffff90911690631003e2d290602401600060405180830381600087803b1580156103b157600080fd5b505af11580156103c5573d6000803e3d6000fd5b50505073ffffffffffffffffffffffffffffffffffffffff8616600081815260026020526040908190205490518793507f6ac31c38682e0128240cf68316d7ae751020d8f74c614e2a30278afcec8a6073906104249088908890610964565b60405180910390a45050505050565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663949d225d6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156104a1573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906104c591906109b1565b905090565b73ffffffffffffffffffffffffffffffffffffffff8216600090815260026020526040812054839103610559576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820181905260248201527f436f6d706f6e656e74206861736e2774206265656e207265676973746572656460448201526064016101cd565b73ffffffffffffffffffffffffffffffffffffffff83166000818152600260205260408082205490518593927f6dd56823030ae6d8ae09cbfb8972c4e9494e67b209c4ab6300c21d73e269b35091a4505050565b600080546040517fcccf7a8e0000000000000000000000000000000000000000000000000000000081526004810184905273ffffffffffffffffffffffffffffffffffffffff9091169063cccf7a8e90602401602060405180830381865afa15801561061d573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061064191906109ca565b92915050565b806000036106b1576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152600a60248201527f496e76616c69642049440000000000000000000000000000000000000000000060448201526064016101cd565b73ffffffffffffffffffffffffffffffffffffffff821661072e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601960248201527f496e76616c696420636f6d706f6e656e7420616464726573730000000000000060448201526064016101cd565b60008181526001602052604090205473ffffffffffffffffffffffffffffffffffffffff16156107ba576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601560248201527f494420616c72656164792072656769737465726564000000000000000000000060448201526064016101cd565b600081815260016020908152604080832080547fffffffffffffffffffffffff00000000000000000000000000000000000000001673ffffffffffffffffffffffffffffffffffffffff871690811790915580845260028352928190208490555191825282917fe065b93b78fd9ec871610269cc875e4f300f3cf0ed219355a75c09ffdc72c185910160405180910390a25050565b60006020828403121561086157600080fd5b5035919050565b803573ffffffffffffffffffffffffffffffffffffffff8116811461088c57600080fd5b919050565b6000602082840312156108a357600080fd5b6108ac82610868565b9392505050565b600080600080606085870312156108c957600080fd5b6108d285610868565b935060208501359250604085013567ffffffffffffffff808211156108f657600080fd5b818701915087601f83011261090a57600080fd5b81358181111561091957600080fd5b88602082850101111561092b57600080fd5b95989497505060200194505050565b6000806040838503121561094d57600080fd5b61095683610868565b946020939093013593505050565b60208152816020820152818360408301376000818301604090810191909152601f9092017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0160101919050565b6000602082840312156109c357600080fd5b5051919050565b6000602082840312156109dc57600080fd5b815180151581146108ac57600080fdfea2646970667358221220dea05dd35e2a5de52b3778ee4f4e909b6fccb04c19c673b812c7fa3b22ce85e964736f6c634300080d0033608060405234801561001057600080fd5b50610418806100206000396000f3fe608060405234801561001057600080fd5b50600436106100675760003560e01c80634cc82215116100505780634cc822151461009f578063949d225d146100b2578063cccf7a8e146100c357600080fd5b80631003e2d21461006c578063410d59cc14610081575b600080fd5b61007f61007a3660046102e9565b6100e6565b005b610089610138565b6040516100969190610302565b60405180910390f35b61007f6100ad3660046102e9565b610190565b600054604051908152602001610096565b6100d66100d13660046102e9565b610286565b6040519015158152602001610096565b6100ef81610286565b156100f75750565b600080548282526001602081905260408320829055810182559080527f290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5630155565b6060600080548060200260200160405190810160405280929190818152602001828054801561018657602002820191906000526020600020905b815481526020019060010190808311610172575b5050505050905090565b61019981610286565b6101a05750565b600080546101b090600190610346565b815481106101c0576101c0610384565b906000526020600020015460006001600084815260200190815260200160002054815481106101f1576101f1610384565b6000918252602080832090910192909255828152600191829052604081205481549092919081908490811061022857610228610384565b90600052602060002001548152602001908152602001600020819055506001600082815260200190815260200160002060009055600080548061026d5761026d6103b3565b6001900381819060005260206000200160009055905550565b60008054810361029857506000919050565b60008281526001602052604081205490036102d45781600080815481106102c1576102c1610384565b9060005260206000200154149050919050565b50600090815260016020526040902054151590565b6000602082840312156102fb57600080fd5b5035919050565b6020808252825182820181905260009190848201906040850190845b8181101561033a5783518352928401929184019160010161031e565b50909695505050505050565b60008282101561037f577f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b500390565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603160045260246000fdfea2646970667358221220306162261924bfa673cd43a39edda8526afef2615cf36bb707b4d6df0e25306264736f6c634300080d0033a26469706673582212207685fac43a170be257db8a677cf3c280f1b85fa216676c257bc4342a152e7f8664736f6c634300080d0033";

type InitializeFacetConstructorParams = [signer?: Signer] | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (xs: InitializeFacetConstructorParams): xs is ConstructorParameters<typeof ContractFactory> =>
  xs.length > 1;

export class InitializeFacet__factory extends ContractFactory {
  constructor(...args: InitializeFacetConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
    this.contractName = "InitializeFacet";
  }

  deploy(overrides?: Overrides & { from?: string | Promise<string> }): Promise<InitializeFacet> {
    return super.deploy(overrides || {}) as Promise<InitializeFacet>;
  }
  getDeployTransaction(overrides?: Overrides & { from?: string | Promise<string> }): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  attach(address: string): InitializeFacet {
    return super.attach(address) as InitializeFacet;
  }
  connect(signer: Signer): InitializeFacet__factory {
    return super.connect(signer) as InitializeFacet__factory;
  }
  static readonly contractName: "InitializeFacet";
  public readonly contractName: "InitializeFacet";
  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): InitializeFacetInterface {
    return new utils.Interface(_abi) as InitializeFacetInterface;
  }
  static connect(address: string, signerOrProvider: Signer | Provider): InitializeFacet {
    return new Contract(address, _abi, signerOrProvider) as InitializeFacet;
  }
}