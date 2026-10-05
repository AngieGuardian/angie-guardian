// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import "testing"

func TestDiagnosticsAdmissionAndDownloadStates(t *testing.T) {
	vm := jsRuntime(t, "diagnosticsView", "makeDiagnosticsController")
	_, err := vm.RunString(`
	  var requests = [], views = [], downloads = 0, pendingPost, current = {enabled:true, capturing:false, retry_after_seconds:0};
	  var controller = makeDiagnosticsController(function(path, opts) {
	    requests.push(opts && opts.method || "GET");
	    if (opts && opts.method === "POST") return new Promise(function(resolve) { pendingPost = resolve; });
	    return Promise.resolve({json:function() { return Promise.resolve(current); }});
	  }, function() { downloads++; return Promise.resolve(); }, function(view) { views.push(view); },
	  function() { return {signal:{}, abort:function(){}}; });
	  controller.refresh();
	`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vm.RunString(`controller.capture(); controller.capture();`)
	if err != nil {
		t.Fatal(err)
	}
	var during struct {
		Posts    int
		Disabled bool
		Message  string
	}
	call(t, vm, `({Posts:requests.filter(function(x){return x === "POST";}).length, Disabled:views[views.length-1].disabled, Message:views[views.length-1].message})`, &during)
	if during.Posts != 1 || !during.Disabled || during.Message != "Capturing profiles…" {
		t.Fatalf("capture admission = %+v", during)
	}
	_, err = vm.RunString(`current = {enabled:true, capturing:false, retry_after_seconds:60}; pendingPost({});`)
	if err != nil {
		t.Fatal(err)
	}
	var after struct {
		Downloads int
		Disabled  bool
		Message   string
	}
	call(t, vm, `({Downloads:downloads, Disabled:views[views.length-1].disabled, Message:views[views.length-1].message})`, &after)
	if after.Downloads != 1 || !after.Disabled || after.Message != "Download initiated. Inspect both profiles with go tool pprof. Capture available in 60s." {
		t.Fatalf("download/cooldown = %+v", after)
	}
	_, err = vm.RunString(`controller.capture();`)
	if err != nil {
		t.Fatal(err)
	}
	var posts int
	call(t, vm, `requests.filter(function(x){return x === "POST";}).length`, &posts)
	if posts != 1 {
		t.Fatalf("cooldown sent another POST: %d", posts)
	}
}

func TestDiagnosticsLogoutDiscardsLateCaptureAndStatus(t *testing.T) {
	vm := jsRuntime(t, "diagnosticsView", "makeDiagnosticsController")
	_, err := vm.RunString(`
	  var waits = [], downloads = 0, aborted = 0, views = [];
	  var controller = makeDiagnosticsController(function(path, opts) {
	    return new Promise(function(resolve) { waits.push(resolve); });
	  }, function() { downloads++; return Promise.resolve(); }, function(view) { views.push(view); },
	  function() { return {signal:{}, abort:function(){aborted++;}}; });
	  controller.refresh();
	  controller.capture();
	  controller.reset();
	  waits.shift()({json:function(){return Promise.resolve({enabled:true, capturing:false, retry_after_seconds:0});}});
	  waits.shift()({json:function(){return Promise.resolve({enabled:true, capturing:false, retry_after_seconds:0});}});
	`)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Downloads int
		Aborted   int
		Pending   int
		Disabled  bool
	}
	call(t, vm, `({Downloads:downloads, Aborted:aborted, Pending:waits.length, Disabled:views[views.length-1].disabled})`, &got)
	if got.Downloads != 0 || got.Aborted != 1 || got.Pending != 0 || !got.Disabled {
		t.Fatalf("logout state = %+v", got)
	}
}

func TestDiagnosticsErrorAndDisabledFeedback(t *testing.T) {
	vm := jsRuntime(t, "diagnosticsView", "makeDiagnosticsController")
	_, err := vm.RunString(`
	  var views = [], posts = 0, enabled = false;
	  var controller = makeDiagnosticsController(function(path, opts) {
	    if (opts && opts.method === "POST") {
	      posts++; var e = new Error("cooldown"); e.status = 429; e.retryAfter = 12; return Promise.reject(e);
	    }
	    return Promise.resolve({json:function(){return Promise.resolve({enabled:enabled,capturing:false,retry_after_seconds:0});}});
	  }, function(){throw new Error("must not download");}, function(view){views.push(view);},
	  function(){return {signal:{},abort:function(){}};});
	  controller.capture();
	`)
	if err != nil {
		t.Fatal(err)
	}
	var disabled struct {
		Posts    int
		Disabled bool
		Message  string
	}
	call(t, vm, `({Posts:posts,Disabled:views[views.length-1].disabled,Message:views[views.length-1].message})`, &disabled)
	if disabled.Posts != 0 || !disabled.Disabled || disabled.Message != "Disabled. Set admin.diagnostics_enabled: true and restart Guardian." {
		t.Fatalf("disabled = %+v", disabled)
	}
	_, err = vm.RunString(`enabled = true; controller.capture();`)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Posts   int
		Message string
	}
	call(t, vm, `({Posts:posts,Message:views[views.length-1].message})`, &got)
	if got.Posts != 1 || got.Message != "Capture failed: cooldown" {
		t.Fatalf("error feedback = %+v", got)
	}
}

func TestDiagnosticsBinaryDownloadAndURLCleanup(t *testing.T) {
	vm := jsRuntime(t, "downloadDiagnostics")
	_, err := vm.RunString(`
	  var created = 0, revoked = 0, clicked = 0, removed = 0, filename = "", error = "";
	  var URL = {createObjectURL:function(){created++;return "blob:test";},revokeObjectURL:function(){revoked++;}};
	  var document = {body:{appendChild:function(){}},createElement:function(){return {
	    click:function(){clicked++;filename=this.download;},remove:function(){removed++;}};}};
	  var setTimeout = function(f){f();};
	  var response = {headers:{get:function(k){return k === "Content-Type" ? "application/x-tar" : 'attachment; filename="guardian-goroutines-test.tar"';}},
	    blob:function(){return Promise.resolve({size:1234});}};
	  downloadDiagnostics(response,function(){return true;});
	`)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Created, Revoked, Clicked, Removed int
		Filename                           string
	}
	call(t, vm, `({Created:created,Revoked:revoked,Clicked:clicked,Removed:removed,Filename:filename})`, &got)
	if got.Created != 1 || got.Revoked != 1 || got.Clicked != 1 || got.Removed != 1 || got.Filename != "guardian-goroutines-test.tar" {
		t.Fatalf("download = %+v", got)
	}
	_, err = vm.RunString(`downloadDiagnostics(response,function(){return false;});`)
	if err != nil {
		t.Fatal(err)
	}
	call(t, vm, `clicked`, &got.Clicked)
	if got.Clicked != 1 {
		t.Fatal("late download after logout")
	}
	_, err = vm.RunString(`response.blob = function(){return Promise.resolve({size:33554433});}; downloadDiagnostics(response,function(){return true;}).catch(function(e){error=e.message;});`)
	if err != nil {
		t.Fatal(err)
	}
	var message string
	call(t, vm, `error`, &message)
	if message != "profile archive exceeds the download limit" {
		t.Fatalf("oversize error = %q", message)
	}
}

func TestDiagnosticsCooldownRefreshesWithoutDashboardPolling(t *testing.T) {
	vm := jsRuntime(t, "diagnosticsView", "makeDiagnosticsController")
	_, err := vm.RunString(`
	  var timers = [], canceled = [], views = [], requests = 0, retry = 60;
	  var controller = makeDiagnosticsController(function(){requests++; return Promise.resolve({json:function(){
	    return Promise.resolve({enabled:true,capturing:false,retry_after_seconds:retry});}});},
	    function(){}, function(view){views.push(view);}, function(){return {signal:{},abort:function(){}};},
	    function(f,ms){timers.push({run:f,ms:ms});return timers.length;}, function(id){canceled.push(id);});
	  controller.refresh();
	`)
	if err != nil {
		t.Fatal(err)
	}
	var before struct {
		Disabled bool
		Delay    int
	}
	call(t, vm, `({Disabled:views[views.length-1].disabled,Delay:timers[0].ms})`, &before)
	if !before.Disabled || before.Delay != 60000 {
		t.Fatalf("cooldown timer = %+v", before)
	}
	_, err = vm.RunString(`retry = 0; timers[0].run();`)
	if err != nil {
		t.Fatal(err)
	}
	var after struct {
		Disabled bool
		Requests int
	}
	call(t, vm, `({Disabled:views[views.length-1].disabled,Requests:requests})`, &after)
	if after.Disabled || after.Requests != 2 {
		t.Fatalf("independent cooldown expiry = %+v", after)
	}
	_, err = vm.RunString(`retry = 60; controller.refresh(); controller.reset(); timers[timers.length-1].run();`)
	if err != nil {
		t.Fatal(err)
	}
	call(t, vm, `requests`, &after.Requests)
	if after.Requests != 3 {
		t.Fatalf("logout timer fetched again: %d", after.Requests)
	}
}

func TestDiagnosticsAvailabilityRecoversWithoutDashboardPolling(t *testing.T) {
	vm := jsRuntime(t, "diagnosticsView", "makeDiagnosticsController")
	_, err := vm.RunString(`
	  var timers = [], views = [], failed = true;
	  var controller = makeDiagnosticsController(function(){
	    if (failed) return Promise.reject(new Error("offline"));
	    return Promise.resolve({json:function(){return Promise.resolve({enabled:true,capturing:false,retry_after_seconds:0});}});
	  }, function(){}, function(view){views.push(view);}, function(){return {signal:{},abort:function(){}};},
	  function(f,ms){timers.push({run:f,ms:ms});return timers.length;},function(){});
	  controller.refresh();
	`)
	if err != nil {
		t.Fatal(err)
	}
	var before struct {
		Message string
		Delay   int
	}
	call(t, vm, `({Message:views[views.length-1].message,Delay:timers[0].ms})`, &before)
	if before.Message != "Diagnostics unavailable: offline" || before.Delay != 5000 {
		t.Fatalf("status failure = %+v", before)
	}
	_, err = vm.RunString(`failed = false; timers[0].run();`)
	if err != nil {
		t.Fatal(err)
	}
	var after struct {
		Message  string
		Disabled bool
	}
	call(t, vm, `({Message:views[views.length-1].message,Disabled:views[views.length-1].disabled})`, &after)
	if after.Disabled || after.Message != "Ready. Profiles are captured only when requested." {
		t.Fatalf("recovered state = %+v", after)
	}
}
