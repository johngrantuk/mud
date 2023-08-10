import { TableId } from "@latticexyz/common/deprecated";
import { RecsV1TableOptions } from "./types";

export function renderRecsV1Tables(options: RecsV1TableOptions) {
  const { tables } = options;

  return `/* Autogenerated file. Do not edit manually. */

import { defineComponent, Type as RecsType, type World } from "@latticexyz/recs";

export function defineContractComponents(world: World) {
  return {
    ${tables.map((table) => `${table.tableName}: ${renderDefineComponent(table)},`).join("")}
  }
}
`;
}

function renderDefineComponent(table: RecsV1TableOptions["tables"][number]) {
  const { namespace, name } = table.staticResourceData;
  const tableId = new TableId(namespace, name);
  return `
    defineComponent(world, {
      ${table.fields.map(({ name, recsTypeString }) => `${name}: ${recsTypeString}`).join(",")}
    }, {
      id: ${JSON.stringify(tableId.toHex())},
      metadata: {
        componentName: ${JSON.stringify(name)},
        tableName: ${JSON.stringify([namespace, name].join(":"))},
        keySchema: ${JSON.stringify(table.keySchema)},
        valueSchema: ${JSON.stringify(table.valueSchema)},
      },
    } as const)
  `;
}
