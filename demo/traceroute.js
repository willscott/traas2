var el = document.getElementById('traceroute');

fetch('../start').then(function(resp) {
  return resp.text();
}).then(function(body) {
  var data;
  try {
    data = JSON.parse(body);
  } catch (e) {
    el.style.Color = '#ff0000';
    el.innerHTML = "Could not parse response:" + e + "\n" + body;
    return
  }

  if (!data.Route) {
    el.style.Color = '#ff0000';
    el.innerHTML = "Unexpected response:" + body;
    return
  }
  el.innerHTML = "";
  var next = document.createElement("div");
  var ih ="<h4>Route to " + data.To + "</h4><ul>";
  for (var i = 0; i < data.Route.length; i++) {
    ih += "<li><b>" + data.Route[i].TTL +"</b> - " + data.Route[i].IP + "</li>";
  }
  ih += "</ul>";
  next.innerHTML = ih;
  el.parentNode.appendChild(next);
}).catch(function(err) {
  el.style.Color = '#ff0000';
  el.innerHTML = err;
});
