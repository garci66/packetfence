/* -*- Mode: javascript; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

$(function() {
  'use strict';

  var varsEl = document.getElementById('variables');
  var vars = JSON.parse(variables.textContent || variables.innerHTML);

  window.waitTime = vars.waitTime + vars.initial_delay;
  window.retry_delay = vars.retry_delay;
  window.txt_web_notification = vars.txt_web_notification;
  window.timerbarAction = function() {
    if(vars["auto_redirect"] != 0) {
      $('.timerbar').addClass('hide');
      $('#detectionNotice').addClass('hide');
      $('#detectionError').removeClass('hide');
    }
    else {
      networkAccessCallback(vars.destination_url);
    }
  }; 

  if (vars.network_logoff_popup != 0) {
    window.network_logoff_popup = "http://"+vars.hostname+"/networklogoff";
  }

  // Initialize progress bar (requires timerbar.js)
  initTimerbar();

  setTimeout(function() {
    // Start network detection after an initial delay
    detectNetworkAccess(vars.retry_delay, vars.destination_url, vars.external_ip, vars.image_path);
  }, vars.initial_delay * 1000);

  // require access to web notifications now so it's ready when the access is activated
  initWebNotifications();
});
