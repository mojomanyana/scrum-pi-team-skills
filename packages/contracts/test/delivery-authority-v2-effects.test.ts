import {describe,expect,it} from "vitest";
import {evaluateDeliveryEffectV2,evaluateDeliveryRecoveryV2,type DeliveryIdentityV2} from "../src/index.js";
import {identity,v2} from "./delivery-authority-v2.test.js";
const trusted={authorityDigest:v2.authorityDigest,meteringDigest:v2.meteringDigest,controllerStateDigest:v2.controllerStateDigest,identity};
const controller={...identity,role:"controller",access:"controller",actorId:"controller",executionId:"controller-exec",workspaceId:"controller-work"} satisfies DeliveryIdentityV2;
describe("v2 effects, recovery, reconciliation, and cancellation",()=>{
 it("authorizes pure intent once and detects replay conflicts",()=>{
  const request={kind:"prepare-branch-worktree",identity,idempotencyKey:"effect-1",requestDigest:"a".repeat(64),preconditionDigest:"b".repeat(64),postconditionDigest:"c".repeat(64),remainingBudget:1};
  expect(evaluateDeliveryEffectV2(v2,request,trusted,[])).toMatchObject({allowed:true,code:"accepted"});
  expect(evaluateDeliveryEffectV2(v2,request,trusted,[{idempotencyKey:"effect-1",requestDigest:request.requestDigest,outcome:"accepted"}])).toMatchObject({allowed:true,code:"idempotent-replay"});
  expect(evaluateDeliveryEffectV2(v2,{...request,requestDigest:"f".repeat(64)},trusted,[{idempotencyKey:"effect-1",requestDigest:request.requestDigest,outcome:"accepted"}])).toMatchObject({allowed:false,code:"idempotency-conflict"});
 });
 it("fails closed on cancellation, no budget, wrong role, and unknown effects",()=>{
  const request={kind:"launch-verifier",identity,idempotencyKey:"effect-2",requestDigest:"a".repeat(64),preconditionDigest:"b".repeat(64),postconditionDigest:"c".repeat(64),remainingBudget:0};
  expect(evaluateDeliveryEffectV2(v2,request,trusted,[]).allowed).toBe(false);
  expect(evaluateDeliveryEffectV2({...v2,cancelled:true},{...request,remainingBudget:1},trusted,[]).code).toBe("cancelled");
  expect(evaluateDeliveryEffectV2(v2,{...request,kind:"unknown",remainingBudget:1},trusted,[]).allowed).toBe(false);
 });
 it.each(["redundant-assurance-downgrade","missing-keep-branch-choice","repair-order-correction","completed-repair-missing-receipt","stale-evidence-regeneration","canonical-digest-retransmission","disappeared-product","disappeared-flow","disappeared-principal","disappeared-verifier","already-completed-feature-push","already-created-or-updated-pr","interrupted-ci-polling","interrupted-paca-update","cancellation-cleanup"])("accepts exact allowlisted recovery %s",kind=>{
  expect(evaluateDeliveryRecoveryV2({...v2,state:"blocked"},{kind,suspendedState:"blocked",identity:controller,idempotencyKey:`recovery-${kind}`,boundaryId:`boundary-${kind}`,boundaryConsumed:false,identityRevalidated:true,worktreeClean:true,evidenceIds:["rejected-event"],staleEvidenceIds:[],remainingAttempts:1},trusted)).toMatchObject({allowed:true,code:"accepted"});
 });
 it("rejects replayed boundary, dirty worktree, drift, skipped evidence, and nonallowlisted recovery",()=>{
  const request={kind:"disappeared-verifier",suspendedState:"blocked",identity:controller,idempotencyKey:"recovery",boundaryId:"boundary",boundaryConsumed:false,identityRevalidated:true,worktreeClean:true,evidenceIds:["rejected-event"],staleEvidenceIds:[],remainingAttempts:1};
  for(const changed of [{...request,boundaryConsumed:true},{...request,worktreeClean:false},{...request,identityRevalidated:false},{...request,evidenceIds:[]},{...request,kind:"remote-main-drift"}]) expect(evaluateDeliveryRecoveryV2({...v2,state:"blocked"},changed,trusted).allowed).toBe(false);
 });
});
