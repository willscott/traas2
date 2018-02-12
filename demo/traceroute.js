var el = document.getElementById('traceroute');

fetch('../start').then(function(resp) {
  return resp.text();
}).then(function(body) {
  el.innerHTML = body;
}).catch(function(err) {
  el.style.Color = '#ff0000';
  el.innerHTML = err;
});
