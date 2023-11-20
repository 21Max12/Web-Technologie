var socket = io.connect('http://' + document.domain + ':' + location.port);
socket.on('connect', function() {
    // Bei Verbindungsaufbau
});
socket.on('spielupdate', function(data) {
    // Verarbeitung von Spielupdates
});