use crate::EnrolledAuthority;
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::{Path, PathBuf}};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase")]
pub struct StorageMount { pub mountpoint:String, pub source:String, pub filesystem_uuid:Option<String>, pub label:Option<String>, pub filesystem:String, pub readonly:bool, pub total_bytes:u64, pub free_bytes:u64, pub root:bool }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase")]
pub struct EnrollmentState { pub enrolled:Option<EnrolledAuthority>, pub consumed_nonces:Vec<String>, pub consumed_jtis:Vec<String> }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase")]
pub struct StorageGrant { pub grant_id:String, pub capability:String, pub canonical_mountpoint:String, pub canonical_path:String, pub filesystem_uuid:String, pub binding_epoch:u64, pub state:String, pub degraded_reason:Option<String> }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase")]
pub struct StorageGrantPreflight { pub intent_id:String, pub deployment_id:String, pub capability:String, pub canonical_mountpoint:String, pub canonical_path:String, pub filesystem_uuid:String, pub policy_hash:String }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase")]
pub struct StorageTransaction { pub transaction_id:String, pub grant_id:String, pub phase:String, pub previous_dropin:Option<String>, pub target_dropin:String, pub error:Option<String> }

pub struct StorageGrantStore { root:PathBuf }
impl StorageGrantStore {
 pub fn open(root:PathBuf)->Result<Self,String>{fs::create_dir_all(&root).map_err(|e|e.to_string())?;#[cfg(unix)] fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).map_err(|e|e.to_string())?;Ok(Self{root})}
 fn file(&self,n:&str)->PathBuf{self.root.join(n)}
 fn write<T:Serialize>(&self,n:&str,v:&T)->Result<(),String>{let p=self.file(n);let t=p.with_extension("tmp");let bytes=serde_json::to_vec_pretty(v).map_err(|e|e.to_string())?;let mut f=fs::File::create(&t).map_err(|e|e.to_string())?;f.write_all(&bytes).map_err(|e|e.to_string())?;f.sync_all().map_err(|e|e.to_string())?;#[cfg(unix)] fs::set_permissions(&t,fs::Permissions::from_mode(0o600)).map_err(|e|e.to_string())?;fs::rename(t,p).map_err(|e|e.to_string())}
 pub fn enrollment(&self)->Result<EnrollmentState,String>{let p=self.file("enrollment.json");if !p.exists(){return Ok(EnrollmentState{enrolled:None,consumed_nonces:vec![],consumed_jtis:vec![]})}let mut s:EnrollmentState=serde_json::from_slice(&fs::read(p).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;if s.consumed_jtis.is_empty(){s.consumed_jtis=vec![]}Ok(s)}
 pub fn save_enrollment(&self,s:&EnrollmentState)->Result<(),String>{self.write("enrollment.json",s)}
 pub fn grants(&self)->Result<Vec<StorageGrant>,String>{let p=self.file("grants.json");if !p.exists(){return Ok(vec![])}serde_json::from_slice(&fs::read(p).map_err(|e|e.to_string())?).map_err(|e|e.to_string())}
 pub fn save_grants(&self,g:&Vec<StorageGrant>)->Result<(),String>{self.write("grants.json",g)}
 pub fn save_preflight(&self,p:&StorageGrantPreflight)->Result<(),String>{self.write("preflight.json",p)}
 pub fn preflight(&self)->Result<Option<StorageGrantPreflight>,String>{let p=self.file("preflight.json");if !p.exists(){return Ok(None)}Ok(Some(serde_json::from_slice(&fs::read(p).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?))}
 pub fn save_transaction(&self,t:&StorageTransaction)->Result<(),String>{self.write("transaction.json",t)}
 pub fn transaction(&self)->Result<Option<StorageTransaction>,String>{let p=self.file("transaction.json");if !p.exists(){return Ok(None)}Ok(Some(serde_json::from_slice(&fs::read(p).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?))}
}
#[cfg(unix)] use std::os::unix::fs::PermissionsExt;
pub fn canonical_path(mount:&Path,sub:&str)->Result<PathBuf,String>{if sub.split('/').any(|p|p==".."){return Err("STORAGE_GRANT_PATH_TRAVERSAL".into())}let m=fs::canonicalize(mount).map_err(|_|"STORAGE_GRANT_MOUNT_ABSENT")?;let p=if Path::new(sub).is_absolute(){PathBuf::from(sub)}else{m.join(sub)};let parent=p.parent().ok_or("STORAGE_GRANT_PATH_INVALID")?;let resolved=fs::canonicalize(parent).map_err(|_|"STORAGE_GRANT_PARENT_UNAVAILABLE")?.join(p.file_name().ok_or("STORAGE_GRANT_PATH_INVALID")?);if !resolved.starts_with(&m){return Err("STORAGE_GRANT_PATH_ESCAPE".into())}Ok(resolved)}
pub fn policy_hash(capability:&str,mount:&str,path:&str,uuid:&str)->String{let mut h=Sha256::new();for p in [capability,mount,path,uuid]{h.update(p.as_bytes());h.update([0]);}format!("{:x}",h.finalize())}
pub fn render_dropin(grants:&[StorageGrant])->String{let mut out=String::from("# Managed by Actium Node Supervisor; exact grants only\n[Service]\n");for g in grants.iter().filter(|g|g.state=="approved"){out.push_str("ReadWritePaths=");out.push_str(&g.canonical_path);out.push('\n')}out}
pub fn write_dropin(root:&Path,service:&str,grants:&[StorageGrant])->Result<(),String>{if service.is_empty()||service.contains('/')||service.contains('\\'){return Err("STORAGE_DROPIN_SERVICE_INVALID".into())}let dir=root.join("etc/systemd/system").join(format!("{service}.service.d"));fs::create_dir_all(&dir).map_err(|e|e.to_string())?;let path=dir.join("50-storage-grants.conf");let t=path.with_extension("tmp");fs::write(&t,render_dropin(grants)).map_err(|e|e.to_string())?;fs::rename(t,path).map_err(|e|e.to_string())}
#[cfg(test)] mod tests{use super::*;#[test]fn transaction_and_path_guards(){let r=std::env::temp_dir().join(format!("actium-sg-{}",uuid::Uuid::new_v4()));let m=r.join("mount");fs::create_dir_all(m.join("telemetry")).unwrap();let s=StorageGrantStore::open(r.join("state")).unwrap();let g=StorageGrant{grant_id:"g".into(),capability:"telemetry".into(),canonical_mountpoint:m.to_string_lossy().into(),canonical_path:m.join("telemetry").to_string_lossy().into(),filesystem_uuid:"u".into(),binding_epoch:1,state:"approved".into(),degraded_reason:None};s.save_grants(&vec![g.clone()]).unwrap();s.save_transaction(&StorageTransaction{transaction_id:"t".into(),grant_id:"g".into(),phase:"pending".into(),previous_dropin:None,target_dropin:render_dropin(&[g]),error:None}).unwrap();assert!(canonical_path(&m,"../x").is_err());write_dropin(&r,"actium-node-supervisor",&s.grants().unwrap()).unwrap();assert!(fs::read_to_string(r.join("etc/systemd/system/actium-node-supervisor.service.d/50-storage-grants.conf")).unwrap().contains("ReadWritePaths="));let _=fs::remove_dir_all(r);}}
