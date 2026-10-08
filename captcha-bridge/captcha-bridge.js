(function () {
  'use strict';
  if (window.__csqttCaptchaBridgeInstalled) return;
  window.__csqttCaptchaBridgeInstalled = true;
  function panelOrigin() { try { if (document.referrer) return new URL(document.referrer).origin; } catch (_) {} return ''; }
  let sent = false;
  function sendToken(token) { if (!token || sent) return; const origin=panelOrigin(); if(!origin)return; sent=true; fetch(origin+'/api/captcha/result',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sessionToken:new URL(location.href).searchParams.get('session_token')||'',result:String(token)}),credentials:'omit'}).catch(function(){sent=false;}); }
  function inspect(data) { try { if(data&&data.response&&data.response.success_token) sendToken(data.response.success_token); } catch(_){} }
  const originalFetch=window.fetch; if(originalFetch){ window.fetch=function(){ return originalFetch.apply(this,arguments).then(function(response){ try { const url=typeof arguments[0]==='string'?arguments[0]:(arguments[0]&&arguments[0].url)||''; if(String(url).includes('captchaNotRobot.check')) response.clone().json().then(inspect).catch(function(){}); }catch(_){} return response; }); }; }
  const originalOpen=XMLHttpRequest.prototype.open; const originalSend=XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open=function(method,url){this.__csqttCaptchaUrl=String(url||'');return originalOpen.apply(this,arguments);};
  XMLHttpRequest.prototype.send=function(){ if(this.__csqttCaptchaUrl&&this.__csqttCaptchaUrl.includes('captchaNotRobot.check')) this.addEventListener('load',function(){try{inspect(JSON.parse(this.responseText));}catch(_){} }); return originalSend.apply(this,arguments); };
})();