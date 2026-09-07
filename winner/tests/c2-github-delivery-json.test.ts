import assert from "node:assert/strict";
import { test } from "node:test";
import { parseGithubDeliveryList, parseGithubDeliveryObject, selectOriginalDelivery, selectRedelivery, unsafeNumberRoundtripChangesId } from "../c2/github-delivery-json.js";

const GUID = "c1278f3a-aaa0-11f1-9f5f-1f10261aa34b";
const INSTALLATION_ID = 158227303;
const REPOSITORY_ID = 1350596128;

function deliveryJson(idToken: string, options: { guid?: string; redelivery?: boolean; repositoryId?: number; installationId?: number; event?: string } = {}): string {
  return JSON.stringify({
    id: 0,
    guid: options.guid ?? GUID,
    event: options.event ?? "push",
    installation_id: options.installationId ?? INSTALLATION_ID,
    repository_id: options.repositoryId ?? REPOSITORY_ID,
    redelivery: options.redelivery ?? false,
    status: "OK",
    status_code: 202,
  }).replace('"id":0', `"id":${idToken}`);
}

test("delivery IDs survive raw JSON parsing as exact decimal strings", () => {
  const ids = ["9007199254740991", "9007199254740992", "9007199254740993", "3841363528254497001", "9999999999999999999"];
  for (const id of ids) {
    const [row] = parseGithubDeliveryList(`[${deliveryJson(id)}]`);
    assert.equal(row.id, id);
    assert.equal(typeof row.id, "string");
  }
  assert.equal(parseGithubDeliveryList(`[${deliveryJson("9007199254740993")}]`)[0].id, "9007199254740993");
  assert.notEqual(String(Number("9007199254740993")), "9007199254740993");
  assert.equal(parseGithubDeliveryList(`[${deliveryJson("3841363528254497001")}]`)[0].id, "3841363528254497001");
});

test("unsafe-number diagnostic is separate from canonical ID storage", () => {
  assert.equal(unsafeNumberRoundtripChangesId("9007199254740991"), false);
  assert.equal(unsafeNumberRoundtripChangesId("9007199254740993"), true);
  assert.equal(unsafeNumberRoundtripChangesId("3841363528254497001"), true);
});

test("malformed delivery IDs fail closed", () => {
  for (const token of ["1.5", "-1", "1e3", '"123abc"', '"123"']) {
    assert.throws(() => parseGithubDeliveryList(`[${deliveryJson(token)}]`), /delivery id|decimal|integer/);
  }
  assert.throws(() => parseGithubDeliveryList(`[${deliveryJson("123").replace('"id":123,', "")}]`), /delivery id/);
  assert.throws(() => parseGithubDeliveryList(`[${deliveryJson("123")},null]`), /malformed object/);
  assert.throws(() => parseGithubDeliveryObject(deliveryJson("123").replace('"event":"push",', "")), /delivery event/);
  const duplicateGuidRows = parseGithubDeliveryList(`[${deliveryJson("123")},${deliveryJson("124")}]`);
  assert.throws(() => selectOriginalDelivery(duplicateGuidRows, { guid: GUID, event: "push", installation_id: INSTALLATION_ID, repository_id: REPOSITORY_ID }), /expected exactly one/);
});

test("original and redelivery selection preserves exact string IDs", () => {
  const originalId = "3841363528254497001";
  const redeliveryId = "9999999999999999999";
  const rows = parseGithubDeliveryList(`[${deliveryJson(originalId)},${deliveryJson(redeliveryId, { redelivery: true })}]`);
  const query = { guid: GUID, event: "push", installation_id: INSTALLATION_ID, repository_id: REPOSITORY_ID };
  assert.equal(selectOriginalDelivery(rows, query).id, originalId);
  assert.equal(selectRedelivery(rows, query, originalId).id, redeliveryId);
});

test("heterogeneous GitHub history rows do not prevent exact candidate selection", () => {
  const valid = deliveryJson("3841363528254496768");
  const unrelated = deliveryJson("3841363528254497002").replace('"installation_id":158227303', '"installation_id":null').replace('"repository_id":1350596128', '"repository_id":null');
  const rows = parseGithubDeliveryList(`[${valid},${unrelated}]`);
  const selected = selectOriginalDelivery(rows, { guid: GUID, event: "push", installation_id: INSTALLATION_ID, repository_id: REPOSITORY_ID });
  assert.equal(selected.id, "3841363528254496768");
});

test("selection fails closed for duplicate original identities and does not use input order", () => {
  const first = deliveryJson("9007199254740992");
  const second = deliveryJson("9007199254740993");
  const query = { guid: GUID, event: "push", installation_id: INSTALLATION_ID, repository_id: REPOSITORY_ID };
  const rows = parseGithubDeliveryList(`[${first},${second}]`);
  assert.throws(() => selectOriginalDelivery(rows, query), /exactly one/);
  assert.throws(() => selectOriginalDelivery([...rows].reverse(), query), /exactly one/);
});
