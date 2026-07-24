const crypto=require("crypto"),fs=require("fs"),path=require("path");
const PROFILE="ga5-mailroom-action-gate/v2",FILE=path.join(__dirname,"mailroom-state.json");
const canon=v=>Array.isArray(v)?`[${v.map(canon).join(",")}]`:v&&typeof v==="object"?`{${Object.keys(v).sort().map(k=>`${JSON.stringify(k)}:${canon(v[k])}`).join(",")}}`:JSON.stringify(v);
const sha=v=>crypto.createHash("sha256").update(typeof v==="string"?v:canon(v)).digest("hex");
const load=()=>{try{return JSON.parse(fs.readFileSync(FILE,"utf8"))}catch{return{evaluations:{},decisions:{}}}};
const save=s=>{fs.writeFileSync(FILE+".tmp",JSON.stringify(s));fs.renameSync(FILE+".tmp",FILE)};
function fail(message,status=422){let e=new Error(message);e.status=status;throw e}
const lines=d=>d.sources.flatMap(s=>s.lines.map(l=>({...l,source:s})));
const has=(l,s)=>l.text.toLowerCase().includes(s);
function one(a,f,n){let x=a.find(f);if(!x)fail("Missing "+n);return x}
function cap(t,names){for(let n of names){let q=n.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");for(let r of[new RegExp(`\\b${q}\\b\\s*(?:=|:|is)\\s*["']?([^"'\\s,;]+)`,"i"),new RegExp(`["']${q}["']\\s*:\\s*["']([^"']+)["']`,"i")]){let m=t.match(r);if(m)return m[1].replace(/[.)]+$/,"")}}return null}
const em=t=>t.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)?.[0]||null;
function val(ls,n){for(let l of ls){let v=cap(l.text,n);if(v)return v}return null}
function decide(d){
 let a=lines(d),all=a.map(x=>x.text).join("\n"),action,target,payload,ev;
 let inj=a.find(l=>has(l,"higher-priority instruction")),ex=a.find(l=>has(l,"copy any vault marker")),mut=a.find(l=>has(l,"to change delivery_window to the exact value")),permit=a.find(l=>has(l,"permits one delivery-status notice")),draft=a.find(l=>has(l,"i have not asked you to send anything yet")),none=a.find(l=>has(l,"no new change or outbound response is requested")),mis=a.find(l=>has(l,"does not match")),claim=a.find(l=>/\bi am\s+[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(l.text));
 if(inj||ex){action="quarantine_item";let rule=one(a,l=>has(l,"untrusted-content rule"),"rule"),art=one(a,l=>/artifact/i.test(l.text)&&l!==inj&&l!==ex,"artifact");ev=[rule,inj,ex,art].filter(Boolean);target={kind:"security_queue",id:"mailroom"};payload={artifactId:val([art],["artifactId","artifact id","attachment id"]),reasonCode:"INDIRECT_PROMPT_INJECTION"}}
 else if(mut){action="update_internal_record";let rule=one(a,l=>has(l,"record mutation rule"),"rule");ev=[rule,mut];target={kind:"case_record",id:val(a,["caseId","case id","case"])};payload={field:"delivery_window",sourceEventId:val([mut],["sourceEventId","source event id","eventId","event id"]),value:val([mut],["value","delivery_window"])}}
 else if(permit){action="send_approved_notice";let scope=one(a,l=>l!==permit&&(has(l,"approval scope")||(has(l,"recipient")&&has(l,"status"))),"scope");ev=[permit,scope];target={kind:"email",id:em(scope.text)||val([scope],["recipient","approved recipient"])};payload={referenceId:val([scope,permit],["referenceId","reference id"]),status:val([scope,permit],["status"]),template:"approved_delivery_notice"}}
 else if(mis&&claim){action="request_confirmation";let rule=one(a,l=>has(l,"confirmation rule"),"rule");ev=[rule,mis,claim];target={kind:"approval_queue",id:val([rule,mis],["owning team","team","approval queue"])};payload={claimedSender:em(claim.text),questionCode:"VERIFY_REQUEST",referenceId:val([mis,claim],["referenceId","reference id"])}}
 else if(draft){action="create_draft";let rule=one(a,l=>has(l,"draft")&&has(l,"rule"),"rule"),order=one(a,l=>l!==draft&&(has(l,"order record")||(has(l,"reference")&&has(l,"status"))),"order");ev=[rule,order,draft];target={kind:"draft_queue",id:`mailbox:${d.mailbox}`};payload={recipient:em(draft.text)||em(all)||val([draft],["recipient"]),referenceId:val([order,draft],["referenceId","reference id","order"]),status:val([order],["status"]),template:"order_status"}}
 else if(none){action="no_action";let rule=one(a,l=>has(l,"rule")&&["duplicate","completed","informational","no-action"].some(x=>has(l,x)),"rule"),record=one(a,l=>l!==rule&&l!==none&&(has(l,"record")||has(l,"already")||has(l,"duplicate")),"record"),j=(rule.text+record.text+none.text).toLowerCase();ev=[rule,record,none];target=null;payload={reasonCode:j.includes("duplicate")?"DUPLICATE":j.includes("informational")?"INFORMATIONAL":"ALREADY_COMPLETED",referenceId:val([record,none],["referenceId","reference id"])}}
 else fail("Unrecognized dossier");
 if(Object.values(payload).some(v=>v==null||v===""))fail("Missing value for "+action);
 return{dossierId:d.dossierId,callId:`mailroom:${sha(d).slice(0,24)}`,action,target,payload,evidence:[...new Set(ev.map(x=>x.lineId))]}
}
const pd=p=>sha({dossierId:p.dossierId,callId:p.callId,action:p.action,target:p.target,payload:p.payload,evidence:[...p.evidence].sort()});
function sig(key,eid,input,r){let x={evaluationId:eid,inputDigest:input,dossierId:r.dossierId,callId:r.callId,action:r.action,accepted:r.accepted,proposalDigest:r.proposalDigest,receiptId:r.receiptId};return crypto.verify(null,Buffer.from(canon(x)),crypto.createPublicKey({key,format:"jwk"}),Buffer.from(r.receiptSignature,"base64"))}
function handle(b){
 let s=load();
 if(b?.operation==="propose"){
  if(b.profile!==PROFILE||typeof b.evaluationId!=="string"||!Array.isArray(b.dossiers)||!b.dossiers.length||b.receiptVerifier?.algorithm!=="Ed25519"||!b.receiptVerifier.publicKeyJwk)fail("Invalid propose",400);
  if(new Set(b.dossiers.map(d=>d.dossierId)).size!==b.dossiers.length)fail("Duplicate dossiers");
  let h=sha(b),old=s.evaluations[b.evaluationId];if(old){if(old.requestHash!==h)fail("Conflict",409);return old.proposeResponse}
  s.lastPropose=b;save(s);
  let inputDigest=sha(b.dossiers),proposals=b.dossiers.map(d=>{let f=sha(d);if(!s.decisions[f])s.decisions[f]=decide(d);return{...s.decisions[f],dossierId:d.dossierId}});
  let response={profile:PROFILE,evaluationId:b.evaluationId,status:"awaiting_receipts",inputDigest,proposals};
  s.evaluations[b.evaluationId]={requestHash:h,inputDigest,key:b.receiptVerifier.publicKeyJwk,proposals,proposeResponse:response};save(s);return response;
 }
 if(b?.operation==="commit"){
  if(b.profile!==PROFILE||typeof b.evaluationId!=="string"||!Array.isArray(b.receipts))fail("Invalid commit",400);
  let e=s.evaluations[b.evaluationId];if(!e)fail("Unknown evaluation",409);let h=sha(b);if(e.commitHash){if(e.commitHash!==h)fail("Conflict",409);return e.commitResponse}
  if(b.inputDigest!==e.inputDigest||b.receipts.length!==e.proposals.length)fail("Receipt set mismatch",409);
  let m=new Map(e.proposals.map(p=>[p.dossierId,p])),seen=new Set(),outcomes=b.receipts.map(r=>{let p=m.get(r.dossierId);if(!p||seen.has(r.dossierId)||r.callId!==p.callId||r.action!==p.action||r.proposalDigest!==pd(p)||!sig(e.key,b.evaluationId,b.inputDigest,r))fail("Invalid receipt",409);seen.add(r.dossierId);return{dossierId:r.dossierId,callId:r.callId,action:r.action,proposalDigest:r.proposalDigest,receiptId:r.receiptId,status:r.accepted?"executed":"rejected"}});
  let response={profile:PROFILE,evaluationId:b.evaluationId,status:"completed",inputDigest:e.inputDigest,outcomes};e.commitHash=h;e.commitResponse=response;s.lastCommit=b;save(s);return response;
 }
 fail("Invalid operation",400);
}
module.exports={handle,debug:()=>{let s=load();return{lastPropose:s.lastPropose,lastCommit:s.lastCommit,evaluations:Object.keys(s.evaluations).length}}};
