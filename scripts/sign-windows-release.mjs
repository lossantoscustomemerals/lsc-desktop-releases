import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {readFile,writeFile,appendFile} from 'node:fs/promises';
import {fileURLToPath,pathToFileURL} from 'node:url';
import path from 'node:path';

const REPOSITORY='lossantoscustomemerals/lsc-desktop-releases';
const MAX_BINARY=300*1024*1024;
const MAX_MANIFEST=64000;
const API='https://api.github.com/repos/'+REPOSITORY;
const USER_AGENT='Los-Santos-Custom-Official-Release-Signer';
export function versionParts(value){if(typeof value!=='string'||!/^(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})$/.test(value))throw new Error('Versione non valida.');return value.split('.').map(Number);}
export function isNewer(next,current){const a=versionParts(next),b=versionParts(current);for(let i=0;i<3;i++)if(a[i]!==b[i])return a[i]>b[i];return false;}
export function artifactName(version,mode){versionParts(version);if(!['installed','portable'].includes(mode))throw new Error('Modalità non valida.');return `Los-Santos-Custom-${mode==='portable'?'Portable':'Setup'}-${version}.exe`;}
export function artifactUrl(version,mode){return `https://github.com/${REPOSITORY}/releases/download/v${version}/${artifactName(version,mode)}`;}
export function validateConfig(config){
 if(config?.repository!==REPOSITORY||config.feeds?.installed!=='latest-v2.json'||config.feeds?.portable!=='portable-latest-v2.json'||config.legacyVersion!=='2.0.1')throw new Error('Configurazione canale non valida.');
 for(const name of ['publicKey','legacyPublicKey'])if(typeof config[name]!=='string'||createPublicKey(config[name]).asymmetricKeyType!=='ed25519')throw new Error('Chiave pubblica non valida.');
 if(config.publicKey===config.legacyPublicKey)throw new Error('La nuova chiave deve essere distinta dalla precedente.');
 return config;
}
export function canonicalPayload(payload,mode){
 const version=payload?.version;versionParts(version);
 const artifact=payload.artifact;
 if(typeof payload.notes!=='string'||payload.notes.length>6000||typeof payload.publishedAt!=='string'||!Number.isFinite(Date.parse(payload.publishedAt))||!artifact||artifact.filename!==artifactName(version,mode)||artifact.url!==artifactUrl(version,mode)||!/^[a-f0-9]{64}$/.test(artifact.sha256)||!Number.isSafeInteger(artifact.size)||artifact.size<1||artifact.size>MAX_BINARY)throw new Error('Manifest non valido.');
 return {version,notes:payload.notes,publishedAt:payload.publishedAt,artifact:{filename:artifact.filename,url:artifact.url,sha256:artifact.sha256,size:artifact.size}};
}
export function verifyManifest(bytes,publicKey,mode,expectedVersion){
 if(bytes.length>MAX_MANIFEST)throw new Error('Manifest troppo grande.');
 const envelope=JSON.parse(bytes.toString('utf8'));
 if(envelope?.schema!==1||typeof envelope.signature!=='string')throw new Error('Formato firma non valido.');
 const payload=canonicalPayload(envelope.payload,mode),signature=Buffer.from(envelope.signature,'base64');
 if(payload.version!==expectedVersion||signature.length!==64||!verify(null,Buffer.from(JSON.stringify(payload)),publicKey,signature))throw new Error('Firma manifest non valida.');
 return payload;
}
export function createManifest(payload,key,mode,publicKey){
 const canonical=canonicalPayload(payload,mode);
 const bytes=Buffer.from(JSON.stringify({schema:1,payload:canonical,signature:sign(null,Buffer.from(JSON.stringify(canonical)),key).toString('base64')},null,2)+'\n');
 verifyManifest(bytes,publicKey,mode,payload.version);return bytes;
}
export function loadSigningKey(encoded,expectedPublicKey){
 if(typeof encoded!=='string'||!encoded.length||encoded.length>10000||!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)||encoded.length%4!==0)throw new Error('Segreto di firma non configurato correttamente.');
 let key;try{key=createPrivateKey({key:Buffer.from(encoded,'base64'),format:'der',type:'pkcs8'});}catch{throw new Error('Segreto di firma non valido.');}
 if(key.asymmetricKeyType!=='ed25519'||createPublicKey(key).export({format:'pem',type:'spki'})!==expectedPublicKey)throw new Error('La chiave privata non corrisponde al canale configurato.');
 return key;
}
export function expectedArtifact(hash,size,version,mode){
 if(typeof hash!=='string'||!/^[a-f0-9]{64}$/.test(hash)||typeof size!=='string'||!/^\d{1,10}$/.test(size))throw new Error('Impronta o dimensione attesa non valida.');
 const value=Number(size);if(!Number.isSafeInteger(value)||value<1||value>MAX_BINARY)throw new Error('Dimensione attesa non valida.');
 return {mode,name:artifactName(version,mode),sha256:hash,size:value};
}
export async function consumeResponse(response,expectedSize,expectedHash,maxBytes,collect=false){
 if(!response.ok||!response.body)throw new Error('Download asset non riuscito.');
 const advertised=response.headers.get('content-length');if(advertised&&Number(advertised)!==expectedSize&&expectedSize!==null)throw new Error('Dimensione HTTP non corrispondente.');
 const hash=createHash('sha256'),chunks=[];let size=0;
 for await(const chunk of response.body){size+=chunk.length;if(size>maxBytes||expectedSize!==null&&size>expectedSize)throw new Error('Asset troppo grande.');hash.update(chunk);if(collect)chunks.push(Buffer.from(chunk));}
 const sha256=hash.digest('hex');if(expectedSize!==null&&size!==expectedSize||expectedHash!==null&&sha256!==expectedHash)throw new Error('Integrità asset non valida.');
 return {size,sha256,bytes:collect?Buffer.concat(chunks):undefined};
}
function trustedPublicUrl(raw){try{const url=new URL(raw);if(url.protocol!=='https:'||url.username||url.password||url.port||url.hash)return false;return url.hostname==='github.com'&&url.pathname.startsWith(`/${REPOSITORY}/releases/`)&&!url.pathname.includes('%')||url.hostname==='release-assets.githubusercontent.com'&&url.pathname.startsWith('/github-production-release-asset/');}catch{return false;}}
export async function main(env=process.env,args=process.argv.slice(2),options={}){
 if(args.some(arg=>!['--dry-run','--publish','--check-key'].includes(arg))||args.includes('--dry-run')&&args.includes('--publish'))throw new Error('Usare --dry-run, --publish oppure --check-key.');
 const publish=args.includes('--publish')||!args.includes('--dry-run')&&env.PUBLISH_RELEASE==='true';
 if(env.PUBLISH_RELEASE!==undefined&&!['true','false'].includes(env.PUBLISH_RELEASE))throw new Error('Parametro publish non valido.');
 const configPath=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../windows-update-config.json');
 const config=validateConfig(options.configuration||JSON.parse(await readFile(configPath,'utf8')));
 const key=loadSigningKey(env.LSC_UPDATE_SIGNING_KEY_PKCS8,config.publicKey);
 if(env.GITHUB_REPOSITORY&&env.GITHUB_REPOSITORY!==REPOSITORY)throw new Error('Workflow eseguito nel repository errato.');
 const fetcher=options.fetcher||globalThis.fetch,log=options.log||console.log;
 if(args.includes('--check-key')||env.CHECK_KEY_ONLY==='true'){
  const result={keyVerified:true,publicKeySHA256:createHash('sha256').update(config.publicKey).digest('hex'),published:false};
  if(env.GITHUB_STEP_SUMMARY)await appendFile(env.GITHUB_STEP_SUMMARY,`## Firma Windows verificata\n\nLa chiave protetta corrisponde alla pubblica configurata. Nessun rilascio letto o modificato.\n\nImpronta pubblica SHA256: ${result.publicKeySHA256}\n`);
  log(JSON.stringify(result));return result;
 }
 const version=env.RELEASE_VERSION;versionParts(version);if(!isNewer(version,config.legacyVersion))throw new Error('Versione non successiva al canale precedente.');
 const expected=[expectedArtifact(env.SETUP_SHA256,env.SETUP_SIZE,version,'installed'),expectedArtifact(env.PORTABLE_SHA256,env.PORTABLE_SIZE,version,'portable')];
 const token=env.GITHUB_TOKEN;if(typeof token!=='string'||!token)throw new Error('Token GitHub non disponibile.');
 const headers={Authorization:'Bearer '+token,Accept:'application/vnd.github+json','User-Agent':USER_AGENT,'X-GitHub-Api-Version':'2022-11-28'};
 async function api(endpoint,method='GET',body){const response=await fetcher(API+endpoint,{method,redirect:'error',headers:{...headers,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(30000)});if(!response.ok)throw new Error(`GitHub ${method} HTTP ${response.status}.`);return response.status===204?null:response.json();}
 async function publicDownload(raw,signal){let url=raw;for(let redirects=0;redirects<5;redirects++){if(!trustedPublicUrl(url))throw new Error('Origine download non consentita.');const response=await fetcher(url,{redirect:'manual',credentials:'omit',headers:{Accept:'application/octet-stream','User-Agent':USER_AGENT,'Cache-Control':'no-cache'},signal});if([301,302,303,307,308].includes(response.status)){const next=response.headers.get('location');if(!next)throw new Error('Redirect non valido.');url=new URL(next,url).href;continue;}return response;}throw new Error('Troppi redirect.');}
 async function downloadAsset(asset,maxBytes,collect=false){
  if(!Number.isSafeInteger(asset.id)||asset.id<1)throw new Error('Identificativo asset non valido.');
  const signal=AbortSignal.timeout(10*60*1000);
  let response=await fetcher(API+'/releases/assets/'+asset.id,{redirect:'manual',headers:{...headers,Accept:'application/octet-stream'},signal});
  if([301,302,303,307,308].includes(response.status)){const location=response.headers.get('location');if(!location)throw new Error('Redirect asset non valido.');response=await publicDownload(location,signal);}
  const hash=typeof asset.digest==='string'?asset.digest.replace(/^sha256:/,''):null;
  return consumeResponse(response,asset.size,hash,maxBytes,collect);
 }
 const repo=await api('');if(repo.private||repo.full_name!==REPOSITORY)throw new Error('Repository pubblico ufficiale non confermato.');
 const current=await api('/releases/latest');
 if(!/^v\d+\.\d+\.\d+$/.test(current.tag_name)||!isNewer(version,current.tag_name.slice(1)))throw new Error('La versione non supera il rilascio stabile corrente.');
 const release=await api('/releases/tags/v'+version);
 if(!release.draft||release.prerelease||release.tag_name!=='v'+version)throw new Error('Serve una bozza stabile con la versione indicata.');
 if(typeof release.body!=='string'||!release.body.trim()||release.body.length>6000)throw new Error('Le note della bozza devono contenere da 1 a 6000 caratteri.');
 for(const artifact of expected){
  const matches=release.assets.filter(asset=>asset.name===artifact.name);
  if(matches.length!==1||matches[0].state!=='uploaded'||matches[0].size!==artifact.size||matches[0].digest&&matches[0].digest!=='sha256:'+artifact.sha256)throw new Error('Metadati pacchetto non corrispondenti.');
  const verified=await downloadAsset(matches[0],MAX_BINARY);
  if(verified.sha256!==artifact.sha256||verified.size!==artifact.size)throw new Error('Pacchetto scaricato diverso da quello atteso.');
  artifact.assetId=matches[0].id;
 }
 const publishedAt=new Date().toISOString(),files=[];
 for(const artifact of expected){
  const payload={version,notes:release.body.trim(),publishedAt,artifact:{filename:artifact.name,url:artifactUrl(version,artifact.mode),sha256:artifact.sha256,size:artifact.size}};
  files.push({name:config.feeds[artifact.mode],bytes:createManifest(payload,key,artifact.mode,config.publicKey)});
  const legacyName=artifact.mode==='portable'?'portable-latest.json':'latest.json';
  const response=await publicDownload(`https://github.com/${REPOSITORY}/releases/download/v${config.legacyVersion}/${legacyName}`,AbortSignal.timeout(30000));
  const legacy=await consumeResponse(response,null,null,MAX_MANIFEST,true);
  verifyManifest(legacy.bytes,config.legacyPublicKey,artifact.mode,config.legacyVersion);
  files.push({name:legacyName,bytes:legacy.bytes});
 }
 const receipt={repository:REPOSITORY,version,releaseId:release.id,publishRequested:publish,published:false,binaries:expected,manifests:files.map(file=>({name:file.name,size:file.bytes.length,sha256:createHash('sha256').update(file.bytes).digest('hex')}))};
 if(publish){
  const fresh=await api('/releases/'+release.id);if(!fresh.draft||fresh.prerelease||fresh.tag_name!==release.tag_name)throw new Error('La bozza è cambiata durante la verifica.');
  for(const artifact of expected){const remote=fresh.assets.find(item=>item.id===artifact.assetId&&item.name===artifact.name);if(!remote||remote.state!=='uploaded'||remote.size!==artifact.size||remote.digest&&remote.digest!=='sha256:'+artifact.sha256)throw new Error('Pacchetto cambiato durante la verifica.');}
  for(const file of files){
   const existing=fresh.assets.filter(asset=>asset.name===file.name);
   if(existing.length>1)throw new Error('Manifest duplicato nella bozza.');
   if(existing.length)await api('/releases/assets/'+existing[0].id,'DELETE');
   const response=await fetcher(`https://uploads.github.com/repos/${REPOSITORY}/releases/${release.id}/assets?name=${encodeURIComponent(file.name)}`,{method:'POST',redirect:'error',headers:{...headers,'Content-Type':'application/json'},body:file.bytes,signal:AbortSignal.timeout(30000)});
   if(!response.ok)throw new Error('Caricamento manifest HTTP '+response.status+'.');
   const asset=await response.json();
   if(asset.state!=='uploaded'||asset.name!==file.name||asset.size!==file.bytes.length||asset.digest&&asset.digest!=='sha256:'+createHash('sha256').update(file.bytes).digest('hex'))throw new Error('Metadati manifest caricato non corrispondenti.');
   const verified=await downloadAsset(asset,MAX_MANIFEST,true);if(!verified.bytes.equals(file.bytes))throw new Error('Manifest riletto da GitHub diverso.');
  }
  const final=await api('/releases/'+release.id);
  if(!final.draft||final.prerelease)throw new Error('La bozza non è più pubblicabile.');
  for(const file of [...expected.map(value=>({name:value.name,size:value.size,sha256:value.sha256})),...receipt.manifests]){
   const assets=final.assets.filter(asset=>asset.name===file.name);
   if(assets.length!==1||assets[0].state!=='uploaded'||assets[0].size!==file.size||assets[0].digest&&assets[0].digest!=='sha256:'+file.sha256)throw new Error('Non sono presenti tutti i sei asset verificati.');
  }
  const stable=await api('/releases/latest');
  if(!/^v\d+\.\d+\.\d+$/.test(stable.tag_name)||!isNewer(version,stable.tag_name.slice(1)))throw new Error('Un rilascio stabile più recente impedisce la pubblicazione.');
  const published=await api('/releases/'+release.id,'PATCH',{draft:false,make_latest:'true'});
  receipt.published=true;receipt.url=published.html_url;receipt.publicVerification=false;
  await writeFile(options.receiptFile||'windows-release-receipt.json',JSON.stringify(receipt,null,2)+'\n');
  let publicError;
  for(let attempt=0;attempt<8;attempt++){
   try{
    for(const file of files){
     const response=await publicDownload(`https://github.com/${REPOSITORY}/releases/latest/download/${file.name}?check=${Date.now()}`,AbortSignal.timeout(30000));
     const downloaded=await consumeResponse(response,file.bytes.length,createHash('sha256').update(file.bytes).digest('hex'),MAX_MANIFEST,true);
     if(!downloaded.bytes.equals(file.bytes))throw new Error('Feed pubblico non corrispondente.');
    }
    receipt.publicVerification={checkedAt:new Date().toISOString(),manifests:files.length};break;
   }catch(error){publicError=error;if(attempt<7)await new Promise(resolve=>setTimeout(resolve,3000));}
  }
  if(!receipt.publicVerification)throw new Error('Release pubblicata; verifica dei feed pubblici ancora da completare: '+publicError.message);
 }
 await writeFile(options.receiptFile||'windows-release-receipt.json',JSON.stringify(receipt,null,2)+'\n');
 if(env.GITHUB_STEP_SUMMARY)await appendFile(env.GITHUB_STEP_SUMMARY,`## Aggiornamento Windows ${version}\n\n${publish?'Release firmata e pubblicata.':'Verifica completata; nessuna release o asset modificato.'}\n\nDue pacchetti verificati per SHA256 e dimensione; due manifest v2 firmati; due manifest legacy verificati e conservati identici.\n`);
 log(JSON.stringify({version,published:receipt.published,dryRun:!publish,verifiedBinaries:expected.length,verifiedManifests:files.length,publicVerification:receipt.publicVerification||false}));
 return receipt;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href)main().catch(error=>{console.error(error.message);process.exitCode=1;});
