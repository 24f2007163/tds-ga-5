const http = require('http');
const crypto = require('crypto');
const EMAIL = '24f2007163@ds.study.iitm.ac.in';
function send(res, status, body) {
  const h = {'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*','Access-Control-Allow-Methods':'POST, OPTIONS'};
  if (body === undefined) { res.writeHead(status,h); return res.end(); }
  const text=JSON.stringify(body); res.writeHead(status,{...h,'Content-Type':'application/json','Content-Length':Buffer.byteLength(text)}); res.end(text);
}
const result=(id,value)=>({jsonrpc:'2.0',id,result:value});
const error=(id,code,message)=>({jsonrpc:'2.0',id:id??null,error:{code,message}});
http.createServer((req,res)=>{
  if(req.method==='OPTIONS') return send(res,204);
  if(req.method!=='POST') return send(res,405,{error:'POST required'});
  let raw=''; req.on('data',c=>{raw+=c;if(raw.length>1048576)req.destroy();});
  req.on('end',()=>{
    let m; try{m=JSON.parse(raw);}catch{return send(res,400,error(null,-32700,'Parse error'));}
    if(!Object.prototype.hasOwnProperty.call(m,'id')) return send(res,202);
    if(m.method==='initialize') return send(res,200,result(m.id,{protocolVersion:m.params?.protocolVersion||'2025-03-26',capabilities:{tools:{listChanged:false}},serverInfo:{name:'tds-ga5-challenge',version:'1.0.0'}}));
    if(m.method==='ping') return send(res,200,result(m.id,{}));
    if(m.method==='tools/list') return send(res,200,result(m.id,{tools:[{name:'solve_challenge',description:'Solve the challenge from the X-Exam-Challenge HTTP header.',inputSchema:{type:'object',properties:{},additionalProperties:false}}]}));
    if(m.method==='tools/call'){
      if(m.params?.name!=='solve_challenge') return send(res,200,error(m.id,-32602,'Unknown tool'));
      const c=req.headers['x-exam-challenge'];
      if(typeof c!=='string'||!/^[0-9a-f]{32}$/.test(c)) return send(res,200,result(m.id,{content:[{type:'text',text:'invalid challenge'}],isError:true}));
      const text=crypto.createHash('sha256').update(c+':'+EMAIL).digest('hex').slice(0,16);
      return send(res,200,result(m.id,{content:[{type:'text',text}],isError:false}));
    }
    return send(res,200,error(m.id,-32601,'Method not found'));
  });
}).listen(Number(process.env.PORT||10000),'0.0.0.0');
