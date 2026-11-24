import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,randomUUID} from 'node:crypto';
import {unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {artifactName,artifactUrl,canonicalPayload,createManifest,verifyManifest,loadSigningKey,expectedArtifact,consumeResponse,validateConfig,main} from './sign-windows-release.mjs';
const pair=generateKeyPairSync('ed25519'),other=generateKeyPairSync('ed25519');
const publicKey=pair.publicKey.export({format:'pem',type:'spki'}),legacyPublicKey=other.publicKey.export({format:'pem',type:'spki'});
const payload={version:'2.1.0',notes:'Aggiornamento app esistente',publishedAt:'2026-11-24T15:00:00.000Z',artifact:{filename:artifactName('2.1.0','installed'),url:artifactUrl('2.1.0','installed'),sha256:'a'.repeat(64),size:3}};
test('il manifest usa il payload canonico compatibile e la firma corretta',()=>{const bytes=createManifest({...payload,ignored:true},pair.privateKey,'installed',publicKey);assert.deepEqual(verifyManifest(bytes,publicKey,'installed','2.1.0'),canonicalPayload(payload,'installed'));assert.throws(()=>verifyManifest(bytes,legacyPublicKey,'installed','2.1.0'),/Firma/);assert.throws(()=>verifyManifest(bytes,publicKey,'portable','2.1.0'),/Manifest/);});
test('una firma valida non autorizza URL esterni, versione o hash alterati',()=>{assert.throws(()=>createManifest({...payload,artifact:{...payload.artifact,url:'https://example.com/file.exe'}},pair.privateKey,'installed',publicKey),/Manifest/);const bytes=createManifest(payload,pair.privateKey,'installed',publicKey);assert.throws(()=>verifyManifest(bytes,publicKey,'installed','2.1.1'),/Firma/);const changed=JSON.parse(bytes);changed.payload.artifact.sha256='b'.repeat(64);assert.throws(()=>verifyManifest(Buffer.from(JSON.stringify(changed)),publicKey,'installed','2.1.0'),/Firma/);});
test('la chiave privata DER deve corrispondere alla pubblica configurata',()=>{const encoded=pair.privateKey.export({format:'der',type:'pkcs8'}).toString('base64');assert.equal(loadSigningKey(encoded,publicKey).asymmetricKeyType,'ed25519');assert.throws(()=>loadSigningKey(encoded,legacyPublicKey),/corrisponde/);assert.throws(()=>loadSigningKey('not a key',publicKey),/Segreto/);});
test('configurazione vincolata al repository e ai due canali',()=>{const config={repository:'lossantoscustomemerals/lsc-desktop-releases',publicKey,legacyPublicKey,legacyVersion:'2.0.1',feeds:{installed:'latest-v2.json',portable:'portable-latest-v2.json'}};assert.equal(validateConfig(config),config);assert.throws(()=>validateConfig({...config,repository:'other/repo'}),/Configurazione/);assert.throws(()=>validateConfig({...config,publicKey:legacyPublicKey}),/distinta/);});
test('le dimensioni attese e gli hash sono obbligatori e limitati',()=>{assert.equal(expectedArtifact('a'.repeat(64),'3','2.1.0','installed').size,3);for(const size of ['0','-3','1.1','9999999999'])assert.throws(()=>expectedArtifact('a'.repeat(64),size,'2.1.0','installed'));assert.throws(()=>expectedArtifact('invalid','3','2.1.0','installed'));});
test('il download verifica i byte effettivi e conserva byte legacy identici',async()=>{const bytes=Buffer.from('abc'),sha='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';assert.deepEqual((await consumeResponse(new Response(bytes),3,sha,100,true)).bytes,bytes);await assert.rejects(consumeResponse(new Response(bytes),3,'a'.repeat(64),100),/Integrità/);await assert.rejects(consumeResponse(new Response(bytes),2,null,100),/grande/);await assert.rejects(consumeResponse(new Response(bytes),null,null,2),/grande/);});
test('check-key controlla il segreto senza token, input release o chiamate HTTP',async()=>{const configuration={repository:'lossantoscustomemerals/lsc-desktop-releases',publicKey,legacyPublicKey,legacyVersion:'2.0.1',feeds:{installed:'latest-v2.json',portable:'portable-latest-v2.json'}};const result=await main({CHECK_KEY_ONLY:'true',LSC_UPDATE_SIGNING_KEY_PKCS8:pair.privateKey.export({format:'der',type:'pkcs8'}).toString('base64')},[],{configuration,fetcher:()=>{throw new Error('HTTP vietato nel controllo chiave');},log:()=>{}});assert.equal(result.keyVerified,true);assert.equal(result.published,false);assert.match(result.publicKeySHA256,/^[a-f0-9]{64}$/);});

function mockRelease({corruptBinary=false}={}){
 const repository='lossantoscustomemerals/lsc-desktop-releases',api='https://api.github.com/repos/'+repository;
 const configuration={repository,publicKey,legacyPublicKey,legacyVersion:'2.0.1',feeds:{installed:'latest-v2.json',portable:'portable-latest-v2.json'}};
 const binary={installed:Buffer.from('setup-binary'),portable:Buffer.from('portable-binary')},blobs=new Map(),legacy=new Map(),mutations=[];
 let nextId=100,release={id:77,tag_name:'v2.1.0',draft:true,prerelease:false,body:'Interfaccia aggiornata nella stessa app.',assets:[]};
 const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
 for(const mode of ['installed','portable']){
  const bytes=binary[mode],asset={id:nextId++,name:artifactName('2.1.0',mode),size:bytes.length,state:'uploaded',digest:'sha256:'+hash(bytes)};
  release.assets.push(asset);blobs.set(asset.id,corruptBinary&&mode==='portable'?Buffer.from('corrupted!!!!!'):bytes);
  const legacyPayload={version:'2.0.1',notes:'Versione precedente',publishedAt:'2026-11-06T16:00:00.000Z',artifact:{filename:artifactName('2.0.1',mode),url:artifactUrl('2.0.1',mode),sha256:'c'.repeat(64),size:9}};
  const original=createManifest(legacyPayload,other.privateKey,mode,legacyPublicKey).toString('utf8').replace(/\n/g,'\r\n');
  legacy.set(mode==='portable'?'portable-latest.json':'latest.json',Buffer.from(original));
 }
 const env={GITHUB_TOKEN:'test-token-not-a-secret',GITHUB_REPOSITORY:repository,LSC_UPDATE_SIGNING_KEY_PKCS8:pair.privateKey.export({format:'der',type:'pkcs8'}).toString('base64'),RELEASE_VERSION:'2.1.0',SETUP_SHA256:hash(binary.installed),SETUP_SIZE:String(binary.installed.length),PORTABLE_SHA256:hash(binary.portable),PORTABLE_SIZE:String(binary.portable.length),PUBLISH_RELEASE:'false'};
 const json=value=>new Response(JSON.stringify(value),{headers:{'content-type':'application/json'}});
 const fetcher=async(raw,options={})=>{
  const url=new URL(raw),method=options.method||'GET';
  if(url.origin==='https://github.com'){
   assert.equal(options.headers.Authorization,undefined,'Il download pubblico non deve ricevere il token');
   const name=url.pathname.split('/').at(-1);if(url.pathname.includes('/latest/download/')){const asset=release.assets.find(value=>value.name===name);if(!asset||release.draft)throw new Error('Feed pubblico assente');return new Response(blobs.get(asset.id));}if(!legacy.has(name))throw new Error('Download pubblico inatteso');return new Response(legacy.get(name));
  }
  if(url.origin==='https://uploads.github.com'){
   assert.equal(method,'POST');const name=url.searchParams.get('name'),bytes=Buffer.from(options.body),asset={id:nextId++,name,size:bytes.length,state:'uploaded',digest:'sha256:'+hash(bytes)};
   release.assets.push(asset);blobs.set(asset.id,bytes);mutations.push({method,name});return json(asset);
  }
  if(raw===api)return json({full_name:repository,private:false});
  if(raw===api+'/releases/latest')return json({id:1,tag_name:'v2.0.1',draft:false,prerelease:false});
  if(raw===api+'/releases/tags/v2.1.0')return json(release);
  if(raw===api+'/releases/77'){
   if(method==='PATCH'){assert.equal(JSON.parse(options.body).make_latest,'true');release={...release,draft:false};mutations.push({method,name:'publish'});return json({...release,html_url:`https://github.com/${repository}/releases/tag/v2.1.0`});}
   return json(release);
  }
  const id=Number(url.pathname.split('/').at(-1));
  if(raw.startsWith(api+'/releases/assets/')&&blobs.has(id))return new Response(blobs.get(id));
  throw new Error('Endpoint di test inatteso: '+url.pathname);
 };
 return {configuration,env,fetcher,mutations,legacy,blobs,getRelease:()=>release};
}
test('dry-run scarica e verifica entrambi i binari senza mutare la bozza',async()=>{
 const mock=mockRelease(),receiptFile=path.join(tmpdir(),'lsc-signing-dry-run-'+randomUUID()+'.json');
 try{const result=await main(mock.env,['--dry-run'],{...mock,receiptFile,log:()=>{}});assert.equal(result.published,false);assert.equal(result.manifests.length,4);assert.equal(mock.mutations.length,0);assert.equal(mock.getRelease().assets.length,2);}finally{await unlink(receiptFile).catch(()=>{});}
});
test('pubblicazione richiede sei asset verificati e conserva i legacy byte per byte',async()=>{
 const mock=mockRelease(),receiptFile=path.join(tmpdir(),'lsc-signing-publish-'+randomUUID()+'.json');
 try{const result=await main(mock.env,['--publish'],{...mock,receiptFile,log:()=>{}});assert.equal(result.published,true);assert.equal(result.publicVerification.manifests,4);assert.equal(mock.getRelease().assets.length,6);assert.equal(mock.mutations.at(-1).name,'publish');for(const name of ['latest.json','portable-latest.json']){const asset=mock.getRelease().assets.find(a=>a.name===name);assert.deepEqual(mock.blobs.get(asset.id),mock.legacy.get(name));}for(const [mode,name]of [['installed','latest-v2.json'],['portable','portable-latest-v2.json']]){const asset=mock.getRelease().assets.find(a=>a.name===name);assert.equal(verifyManifest(mock.blobs.get(asset.id),publicKey,mode,'2.1.0').version,'2.1.0');}}finally{await unlink(receiptFile).catch(()=>{});}
});
test('un binario alterato impedisce qualsiasi caricamento o pubblicazione',async()=>{
 const mock=mockRelease({corruptBinary:true});await assert.rejects(main(mock.env,['--publish'],{...mock,log:()=>{}}),/grande|Integrità|corrispondente/);assert.equal(mock.mutations.length,0);
});
