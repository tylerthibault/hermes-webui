/* Profile-scoped Matrix channel settings. Secrets are write-only. */
let _channelsLoadPromise=null;
let _channelsFormProfile=null;
let _channelsGeneration=0;
function invalidateChannelsForProfileSwitch(){
  _channelsGeneration++;
  _channelsLoadPromise=null;
  _channelsFormProfile=null;
  ['matrixHomeserver','matrixUserId','matrixAccessToken','matrixPassword','matrixRegistrationSecret','matrixAllowedUsers','matrixAllowedRooms'].forEach(id=>{const e=$(id);if(e)e.value='';});
  ['matrixSaveBtn','matrixRestartBtn','matrixCreateAccountBtn','matrixClearBtn'].forEach(id=>{const e=$(id);if(e)e.disabled=false;});
  _setMatrixMessage('Loading channel settings for the selected profile...');
}
function _channelsRequestIsCurrent(generation,profile){return generation===_channelsGeneration&&profile===(S.activeProfile||'default');}
function _matrixLines(id){const e=$(id);return e?String(e.value||'').split(/\r?\n/).map(v=>v.trim()).filter(Boolean):[];}
function _setMatrixMessage(message,error){const e=$('matrixChannelMessage');if(e){e.textContent=message||'';e.style.color=error?'var(--error,#e05)':'var(--muted)';}}
function syncMatrixAuthFields(){const password=$('matrixAuthMethod')?.value==='password';if($('matrixAccessTokenField'))$('matrixAccessTokenField').style.display=password?'none':'';if($('matrixPasswordField'))$('matrixPasswordField').style.display=password?'':'none';}
function _renderMatrixChannel(data){
  if(!data)return;
  if(data.profile!==(S.activeProfile||'default'))return;
  _channelsFormProfile=data.profile;
  if($('matrixProfileName'))$('matrixProfileName').textContent=data.profile||'default';
  if($('matrixHomeserver'))$('matrixHomeserver').value=data.homeserver||data.provisioning_homeserver||'';
  if($('matrixUserId'))$('matrixUserId').value=data.user_id||'';
  if($('matrixAuthMethod'))$('matrixAuthMethod').value=data.auth_method||'access_token';
  const matrixAccessToken=$('matrixAccessToken'),matrixPassword=$('matrixPassword');
  if(matrixAccessToken){matrixAccessToken.value = '';matrixAccessToken.placeholder=data.has_access_token?'Saved token (leave blank to keep)':'Enter access token';}
  if(matrixPassword){matrixPassword.value = '';matrixPassword.placeholder=data.has_password?'Saved password (leave blank to keep)':'Enter password';}
  if($('matrixAllowedUsers'))$('matrixAllowedUsers').value=(data.allowed_users||[]).join('\n');
  if($('matrixAllowedRooms'))$('matrixAllowedRooms').value=(data.allowed_rooms||[]).join('\n');
  if($('matrixRequireMention'))$('matrixRequireMention').checked=data.require_mention!==false;
  if($('matrixSessionScope'))$('matrixSessionScope').value=data.session_scope||'room';
  if($('matrixAutoThread'))$('matrixAutoThread').checked=!!data.auto_thread;
  if($('matrixE2eeMode'))$('matrixE2eeMode').value=data.e2ee_mode||'required';
  const status=$('matrixChannelStatus');if(status){const running=data.gateway_status==='running';status.textContent=running?'Running':(data.configured?'Configured · stopped':'Not configured');status.className='detail-badge '+(running?'ok':'warn');}
  if($('matrixRestartBtn'))$('matrixRestartBtn').disabled=!data.configured;
  if($('matrixClearBtn'))$('matrixClearBtn').disabled=!data.configured;
  const createBtn=$('matrixCreateAccountBtn'),provisioningHint=$('matrixProvisioningHint'),registrationSecret=$('matrixRegistrationSecret'),canProvision=!!data.provisioning_available&&!data.configured;
  if(createBtn){createBtn.hidden=!canProvision;createBtn.disabled=!canProvision;}
  if(provisioningHint){provisioningHint.hidden=!!data.configured;provisioningHint.textContent=data.configured?'':(canProvision?'Creates a non-admin Matrix account named after this Hermes profile. The registration secret is used once and never saved.':'Account creation is disabled until the operator configures a provisioning homeserver.');}
  if(registrationSecret){registrationSecret.value='';const secretField=registrationSecret.closest('.settings-field');if(secretField)secretField.hidden=!canProvision;}
  syncMatrixAuthFields();
}
async function loadChannelsPanel(){
  if(_channelsLoadPromise)return _channelsLoadPromise;
  const generation=_channelsGeneration;
  const requestedProfile=S.activeProfile||'default';
  _channelsLoadPromise=(async()=>{try{const data=await api('/api/channels/matrix');if(!_channelsRequestIsCurrent(generation,requestedProfile)||data.profile!==requestedProfile)return null;_renderMatrixChannel(data);_setMatrixMessage('');return data;}catch(e){if(_channelsRequestIsCurrent(generation,requestedProfile))_setMatrixMessage('Could not load Matrix settings: '+(e?.message||'request failed'),true);return null;}finally{if(_channelsRequestIsCurrent(generation,requestedProfile))_channelsLoadPromise=null;}})();
  return _channelsLoadPromise;
}
function _matrixPayload(){return {
  homeserver:($('matrixHomeserver')?.value||'').trim(),user_id:($('matrixUserId')?.value||'').trim(),auth_method:$('matrixAuthMethod')?.value||'access_token',
  access_token:$('matrixAccessToken')?.value||'',password:$('matrixPassword')?.value||'',allowed_users:_matrixLines('matrixAllowedUsers'),allowed_rooms:_matrixLines('matrixAllowedRooms'),
  require_mention:!!$('matrixRequireMention')?.checked,session_scope:$('matrixSessionScope')?.value||'room',auto_thread:!!$('matrixAutoThread')?.checked,e2ee_mode:$('matrixE2eeMode')?.value||'required'};}
async function saveMatrixChannel(event,quiet){
  if(!_channelsFormProfile||_channelsFormProfile!==(S.activeProfile||'default')){invalidateChannelsForProfileSwitch();await loadChannelsPanel();throw new Error('Profile changed; Matrix settings were reloaded.');}
  const generation=_channelsGeneration,profile=S.activeProfile||'default';
  event?.preventDefault();const btn=$('matrixSaveBtn');if(btn)btn.disabled=true;_setMatrixMessage('Saving Matrix settings...');
  try{const data=await api('/api/channels/matrix',{method:'POST',body:JSON.stringify(_matrixPayload())});if(!_channelsRequestIsCurrent(generation,profile))return null;_renderMatrixChannel(data);_setMatrixMessage('Saved for '+(data.profile||'active profile')+'. Restart the gateway to apply changes.');if(!quiet)showToast('Matrix channel saved');return data;}
  catch(e){if(_channelsRequestIsCurrent(generation,profile)){_setMatrixMessage('Save failed: '+(e?.message||'request failed'),true);if(!quiet)showToast('Matrix save failed');}throw e;}finally{if(_channelsRequestIsCurrent(generation,profile)&&btn)btn.disabled=false;}
}
async function restartMatrixGateway(){
  if(!_channelsFormProfile||_channelsFormProfile!==(S.activeProfile||'default')){invalidateChannelsForProfileSwitch();await loadChannelsPanel();throw new Error('Profile changed; Matrix settings were reloaded.');}
  const generation=_channelsGeneration,profile=S.activeProfile||'default';
  const btn=$('matrixRestartBtn');if(btn)btn.disabled=true;_setMatrixMessage("Restarting this profile's gateway...");
  try{const r=await api('/api/channels/matrix/restart',{method:'POST',body:'{}'});if(!_channelsRequestIsCurrent(generation,profile))return null;_setMatrixMessage(r?.message||'Gateway restart requested.');showToast('Gateway restart requested');return r;}
  catch(e){if(_channelsRequestIsCurrent(generation,profile))_setMatrixMessage('Gateway restart failed: '+(e?.message||'request failed'),true);throw e;}finally{if(_channelsRequestIsCurrent(generation,profile)&&btn)btn.disabled=false;}
}
async function saveAndRestartMatrixGateway(){try{const saved=await saveMatrixChannel(null,true);if(saved)await restartMatrixGateway();}catch(_e){}}
async function createMatrixAccount(){
  if(!_channelsFormProfile||_channelsFormProfile!==(S.activeProfile||'default')){invalidateChannelsForProfileSwitch();await loadChannelsPanel();return;}
  const payload=_matrixPayload(),registrationSecret=$('matrixRegistrationSecret');
  if(!registrationSecret?.value){_setMatrixMessage('Enter Synapse’s one-time registration secret.',true);registrationSecret?.focus();return;}
  if((payload.password||'').length<12){_setMatrixMessage('Enter a new Matrix password with at least 12 characters.',true);$('matrixPassword')?.focus();return;}
  if(!payload.allowed_users.length){_setMatrixMessage('Add at least one allowed Matrix user before creating the account.',true);$('matrixAllowedUsers')?.focus();return;}
  const generation=_channelsGeneration,profile=S.activeProfile||'default';
  if(!window.confirm('Create a non-admin Matrix account for Hermes profile "'+profile+'"? This creates a durable account on Synapse.'))return;
  payload.registration_secret=registrationSecret.value;registrationSecret.value='';
  const btn=$('matrixCreateAccountBtn');if(btn)btn.disabled=true;let created=false;_setMatrixMessage('Creating and saving the Matrix account...');
  try{const data=await api('/api/channels/matrix/provision',{method:'POST',body:JSON.stringify(payload)});if(!_channelsRequestIsCurrent(generation,profile))return null;created=true;_renderMatrixChannel(data);_setMatrixMessage('Created '+data.user_id+' and saved it to profile '+data.profile+'. Restart the gateway to connect.');showToast('Matrix account created');return data;}
  catch(e){if(_channelsRequestIsCurrent(generation,profile)){_setMatrixMessage('Account creation failed: '+(e?.message||'request failed'),true);showToast('Matrix account creation failed');}throw e;}
  finally{if(_channelsRequestIsCurrent(generation,profile)&&btn)btn.disabled=created;}
}
async function clearMatrixChannel(){
  if(!_channelsFormProfile||_channelsFormProfile!==(S.activeProfile||'default')){invalidateChannelsForProfileSwitch();await loadChannelsPanel();return;}
  if(!window.confirm('Disconnect Matrix from the active Hermes profile? Other profiles are not affected.'))return;
  const generation=_channelsGeneration,profile=S.activeProfile||'default';
  const btn=$('matrixClearBtn');if(btn)btn.disabled=true;
  try{const data=await api('/api/channels/matrix/clear',{method:'POST',body:'{}'});if(!_channelsRequestIsCurrent(generation,profile))return null;_renderMatrixChannel(data);_setMatrixMessage('Matrix disconnected from '+(data.profile||'active profile')+'.');showToast('Matrix channel disconnected');}
  catch(e){if(_channelsRequestIsCurrent(generation,profile))_setMatrixMessage('Disconnect failed: '+(e?.message||'request failed'),true);}finally{if(_channelsRequestIsCurrent(generation,profile)&&btn)btn.disabled=false;}
}
